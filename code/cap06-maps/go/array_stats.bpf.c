//go:build ignore

// array_stats.bpf.c — Array Map: Estadísticas globales (Capítulo 6)
//
// Demuestra el uso de BPF_MAP_TYPE_ARRAY para contadores globales.
// Un array map es ideal cuando las claves son índices numéricos
// consecutivos (0, 1, 2, ...) y el tamaño es fijo.
//
// Aquí usamos un array de 3 posiciones para contar:
//   - Índice 0: Total de syscalls observadas
//   - Índice 1: Syscalls de procesos con PID < 1000 (servicios del sistema)
//   - Índice 2: Syscalls de procesos con PID >= 1000 (usuario)
//
// Ventaja del array sobre hash: acceso O(1) garantizado, sin hashing.
// Desventaja: las claves deben ser índices 0..N-1, no valores arbitrarios.
//
// Attach point: tracepoint/raw_syscalls/sys_enter
// Map: stats (array, key=u32, value=u64, max_entries=3)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Índices con nombres legibles.
#define STAT_TOTAL    0
#define STAT_SYSTEM   1
#define STAT_USER     2

// Array map de 3 entradas — tamaño fijo, acceso por índice.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int track_stats(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Incrementar contador total (índice 0).
    __u32 key_total = STAT_TOTAL;
    __u64 *val = bpf_map_lookup_elem(&stats, &key_total);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }

    // Clasificar: ¿proceso del sistema o de usuario?
    __u32 key_class;
    if (pid < 1000) {
        key_class = STAT_SYSTEM;
    } else {
        key_class = STAT_USER;
    }

    val = bpf_map_lookup_elem(&stats, &key_class);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
