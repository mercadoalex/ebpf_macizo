//go:build ignore

// hash_counter.bpf.c — Hash Map: Contador de syscalls por PID (Capítulo 6)
//
// Demuestra el uso de BPF_MAP_TYPE_HASH para contar eventos por clave.
// Cada vez que un proceso ejecuta cualquier syscall, incrementamos un
// contador asociado a su PID en un hash map.
//
// El hash map es como un diccionario/tabla hash:
//   - Clave: PID del proceso (__u32)
//   - Valor: Número de syscalls ejecutadas (__u64)
//
// User space puede leer este map en cualquier momento para ver
// qué procesos están más activos.
//
// Attach point: tracepoint/raw_syscalls/sys_enter
// Map: syscall_count (hash, key=u32, value=u64, max_entries=10240)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Definición del hash map.
// SEC(".maps") le dice al loader que esta estructura define un map BPF.
// max_entries limita cuántos PIDs distintos podemos trackear simultáneamente.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} syscall_count SEC(".maps");

// Se dispara en CADA syscall de CUALQUIER proceso.
// raw_syscalls/sys_enter es el tracepoint más genérico — captura todo.
SEC("tracepoint/raw_syscalls/sys_enter")
int count_syscalls(void *ctx) {
    // Obtener PID del proceso que hizo la syscall.
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Buscar si ya existe un contador para este PID.
    __u64 *count = bpf_map_lookup_elem(&syscall_count, &pid);

    if (count) {
        // El PID ya existe en el map → incrementar.
        // __sync_fetch_and_add es atómico — necesario porque múltiples
        // CPUs pueden ejecutar este programa simultáneamente.
        __sync_fetch_and_add(count, 1);
    } else {
        // Primera syscall de este PID → insertar con valor 1.
        // BPF_ANY: crear si no existe, actualizar si existe.
        __u64 init_val = 1;
        bpf_map_update_elem(&syscall_count, &pid, &init_val, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
