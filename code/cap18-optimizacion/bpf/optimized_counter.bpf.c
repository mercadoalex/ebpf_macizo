//go:build ignore

// optimized_counter.bpf.c — Capítulo 18: Técnicas de optimización para eBPF
//
// Este archivo demuestra tres técnicas de optimización fundamentales para
// programas eBPF, comparando la versión "naive" con la versión optimizada:
//
// Técnica 1: Per-CPU maps (evitar contención entre cores)
//   - naive: BPF_MAP_TYPE_HASH con atomic increment
//   - optimizado: BPF_MAP_TYPE_PERCPU_HASH, cada core escribe su copia
//
// Técnica 2: Batching de actualizaciones (reducir llamadas a helpers)
//   - naive: un bpf_map_update_elem por cada campo
//   - optimizado: acumular en struct local y hacer un solo update
//
// Técnica 3: __always_inline + branch hints (guiar al compilador)
//   - naive: funciones normales + sin hints
//   - optimizado: todo inlined + likely/unlikely en branches calientes
//
// Para medir la diferencia, se usan ambas versiones con BPF_PROG_TEST_RUN
// y se comparan las latencias. La versión optimizada típicamente muestra
// 2-5x mejor rendimiento en microbenchmarks.
//
// Attach point: tracepoint/raw_syscalls/sys_enter (para contar syscalls)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// =============================================================================
// Branch hints
// =============================================================================

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

// =============================================================================
// Estructuras
// =============================================================================

// Estadísticas por PID (versión optimizada — struct empaquetado)
struct pid_stats {
    __u64 syscall_count;   // Total de syscalls
    __u64 last_ts;         // Último timestamp
    __u64 total_latency;   // Latencia acumulada (ns)
    __u32 pid;             // PID del proceso
    __u32 _pad;            // Alineamiento
};

// =============================================================================
// VERSION NAIVE — Para comparación de rendimiento
// =============================================================================

// Map naive: hash map regular (contención entre cores)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} naive_counter SEC(".maps");

// Map naive para timestamps (acceso no optimizado)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} naive_timestamps SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int naive_syscall_count(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 ts = bpf_ktime_get_ns();

    // Naive: dos lookups + dos updates separados (más llamadas a helpers)
    __u64 *count = bpf_map_lookup_elem(&naive_counter, &pid);
    if (count) {
        *count += 1;  // No es atómico en hash map regular con múltiples cores
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&naive_counter, &pid, &initial, BPF_ANY);
    }

    // Segundo update — otro lookup + update
    bpf_map_update_elem(&naive_timestamps, &pid, &ts, BPF_ANY);

    return 0;
}

// =============================================================================
// VERSION OPTIMIZADA — Usa per-CPU maps + batching + inlining
// =============================================================================

// Per-CPU map: cada core tiene su propia copia → zero contention
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct pid_stats);
} optimized_stats SEC(".maps");

// Función auxiliar completamente inlined — sin overhead de call
static __always_inline void update_pid_stats(
    __u32 pid,
    __u64 current_ts
) {
    struct pid_stats *stats = bpf_map_lookup_elem(&optimized_stats, &pid);

    if (likely(stats != NULL)) {
        // Hot path: PID ya existe — actualizar in-place
        // Un solo write a la struct (batching implícito)
        stats->syscall_count += 1;

        // Calcular latencia desde último syscall
        if (likely(stats->last_ts > 0)) {
            __u64 delta = current_ts - stats->last_ts;
            stats->total_latency += delta;
        }

        stats->last_ts = current_ts;
    } else {
        // Cold path: primera vez que vemos este PID
        // Una sola llamada a bpf_map_update_elem con toda la info
        struct pid_stats new_stats = {
            .syscall_count = 1,
            .last_ts = current_ts,
            .total_latency = 0,
            .pid = pid,
        };
        bpf_map_update_elem(&optimized_stats, &pid, &new_stats, BPF_ANY);
    }
}

SEC("tracepoint/raw_syscalls/sys_enter")
int optimized_syscall_count(void *ctx) {
    // Obtener PID y timestamp en una sola pasada
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 ts = bpf_ktime_get_ns();

    // Un solo path con una sola función inlined
    // - Per-CPU: sin contención
    // - Batching: un solo map operation vs dos
    // - Inlined: sin overhead de function call
    update_pid_stats(pid, ts);

    return 0;
}

// =============================================================================
// VERSION XDP PARA BPF_PROG_TEST_RUN (benchmarking directo)
// =============================================================================

// Versión naive del counter XDP (para benchmark A/B con prog_test_run)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} naive_xdp_stats SEC(".maps");

SEC("xdp")
int naive_xdp_counter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + 14 > data_end)  // Ethernet header
        return XDP_DROP;

    // Naive: lookup + increment sin inline, sin per-cpu
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&naive_xdp_stats, &key);
    if (val)
        *val += 1;

    key = 1;
    __u32 pkt_len = data_end - data;
    __u64 *bytes = bpf_map_lookup_elem(&naive_xdp_stats, &key);
    if (bytes)
        *bytes += pkt_len;

    return XDP_PASS;
}

// Versión optimizada del counter XDP
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} optimized_xdp_stats SEC(".maps");

static __always_inline void opt_increment(__u32 key, __u64 val) {
    __u64 *counter = bpf_map_lookup_elem(&optimized_xdp_stats, &key);
    if (likely(counter != NULL))
        *counter += val;
}

SEC("xdp")
int optimized_xdp_counter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (unlikely(data + 14 > data_end))
        return XDP_DROP;

    __u32 pkt_len = data_end - data;

    // Optimizado: per-CPU + inlined + batched (dos calls inlined)
    opt_increment(0, 1);
    opt_increment(1, pkt_len);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
