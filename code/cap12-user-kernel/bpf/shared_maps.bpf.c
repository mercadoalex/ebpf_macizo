//go:build ignore

// shared_maps.bpf.c — Capítulo 12: Maps compartidos (comunicación bidireccional)
//
// Demuestra comunicación BIDIRECCIONAL entre kernel y user space usando maps:
//
// 1. config_map (array): User space → Kernel
//    User space escribe configuración (rate limit, filtros).
//    El programa BPF lee la config en cada invocación.
//
// 2. stats_map (per-CPU array): Kernel → User space
//    El programa BPF actualiza contadores per-CPU.
//    User space lee y agrega las estadísticas.
//
// 3. blocklist (hash): User space → Kernel (dinámico)
//    User space agrega/remueve PIDs a bloquear.
//    El programa BPF consulta el hash para decidir si actuar.
//
// Este patrón es clave para tools de observabilidad configurables:
// puedes cambiar el comportamiento del programa BPF sin recargarlo.
//
// Attach point: tracepoint/raw_syscalls/sys_enter
// Maps: config_map, stats_map, blocklist

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// ─── Configuración (user space → kernel) ─────────────────────────
// Índices del array de configuración.
#define CFG_ENABLED     0  // 0=deshabilitado, 1=habilitado
#define CFG_SAMPLE_RATE 1  // Tomar 1 de cada N eventos (sampling)
#define CFG_MAX_ENTRIES 3

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CFG_MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} config_map SEC(".maps");

// ─── Estadísticas (kernel → user space) ──────────────────────────
// Per-CPU array para contadores sin lock contention.
#define STATS_TOTAL     0  // Total de syscalls observadas
#define STATS_SAMPLED   1  // Syscalls que pasaron el sampling
#define STATS_FILTERED  2  // Syscalls de PIDs bloqueados
#define STATS_MAX       3

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

// ─── Blocklist de PIDs (user space → kernel, dinámico) ───────────
// Hash map para lookup rápido de PIDs a filtrar.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);     // PID
    __type(value, __u8);    // Valor dummy (presencia = bloqueado)
} blocklist SEC(".maps");

// Variable interna para implementar sampling (no exportada a user space).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} counter SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int configurable_monitor(void *ctx) {
    // ─── Paso 1: Leer configuración desde user space ─────────
    __u32 key_enabled = CFG_ENABLED;
    __u64 *enabled = bpf_map_lookup_elem(&config_map, &key_enabled);
    if (!enabled || *enabled == 0) {
        return 0; // Programa deshabilitado desde user space.
    }

    // ─── Paso 2: Incrementar counter total ───────────────────
    __u32 key_total = STATS_TOTAL;
    __u64 *total = bpf_map_lookup_elem(&stats_map, &key_total);
    if (total) {
        __sync_fetch_and_add(total, 1);
    }

    // ─── Paso 3: Verificar si el PID está bloqueado ──────────
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *blocked = bpf_map_lookup_elem(&blocklist, &pid);
    if (blocked) {
        // PID está en la blocklist — incrementar filtered y salir.
        __u32 key_filtered = STATS_FILTERED;
        __u64 *filtered = bpf_map_lookup_elem(&stats_map, &key_filtered);
        if (filtered) {
            __sync_fetch_and_add(filtered, 1);
        }
        return 0;
    }

    // ─── Paso 4: Aplicar sampling ───────────────────────────
    __u32 key_rate = CFG_SAMPLE_RATE;
    __u64 *sample_rate = bpf_map_lookup_elem(&config_map, &key_rate);
    __u64 rate = (sample_rate && *sample_rate > 0) ? *sample_rate : 1;

    __u32 counter_key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&counter, &counter_key);
    if (!cnt) {
        return 0;
    }
    __u64 current = __sync_fetch_and_add(cnt, 1);

    if (current % rate != 0) {
        return 0; // No es turno de samplear.
    }

    // ─── Paso 5: Evento pasa todos los filtros ──────────────
    __u32 key_sampled = STATS_SAMPLED;
    __u64 *sampled = bpf_map_lookup_elem(&stats_map, &key_sampled);
    if (sampled) {
        __sync_fetch_and_add(sampled, 1);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
