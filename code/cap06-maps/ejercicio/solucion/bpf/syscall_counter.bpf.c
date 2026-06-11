//go:build ignore

// syscall_counter.bpf.c — Solución: Contador de Syscalls por Proceso (Capítulo 6)
//
// Programa eBPF completo que cuenta cuántas syscalls ejecuta cada proceso
// y almacena los conteos en un hash map accesible desde user space.
//
// Attach point: tracepoint/raw_syscalls/sys_enter
// Map: syscall_count (hash, key=__u32 PID, value=__u64 count)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Hash map para almacenar conteo de syscalls por PID.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} syscall_count SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int count_syscalls(void *ctx) {
    // Obtener PID del proceso actual (32 bits altos del valor retornado).
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Buscar si ya existe un contador para este PID.
    __u64 *count = bpf_map_lookup_elem(&syscall_count, &pid);

    if (count) {
        // PID ya existe → incrementar atómicamente.
        __sync_fetch_and_add(count, 1);
    } else {
        // Primera syscall de este PID → insertar con valor 1.
        __u64 init_val = 1;
        bpf_map_update_elem(&syscall_count, &pid, &init_val, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
