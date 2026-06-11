//go:build ignore

// syscall_counter.bpf.c — Ejercicio: Contador de Syscalls por Proceso (Capítulo 6)
//
// INSTRUCCIONES:
// Completa los 3 TODOs para que este programa cuente cuántas syscalls
// ejecuta cada proceso, almacenando el conteo en un hash map.
//
// Attach point: tracepoint/raw_syscalls/sys_enter
// Map: syscall_count (hash, key=__u32 PID, value=__u64 count)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Hash map para almacenar conteo de syscalls por PID.
// - Key: PID del proceso (__u32)
// - Value: Número de syscalls ejecutadas (__u64)
// - max_entries: máximo de PIDs distintos que podemos trackear
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} syscall_count SEC(".maps");

// Este programa se dispara en CADA syscall de CUALQUIER proceso.
SEC("tracepoint/raw_syscalls/sys_enter")
int count_syscalls(void *ctx) {
    // TODO 1: Obtener el PID del proceso actual.
    //
    // Usa bpf_get_current_pid_tgid() que retorna un __u64.
    // Los 32 bits altos contienen el PID (TGID en terminología del kernel).
    // Haz shift right >> 32 para extraer el PID en un __u32.
    //
    // __u32 pid = ???;

    // TODO 2: Buscar si este PID ya tiene un contador en el map.
    //
    // Usa bpf_map_lookup_elem(&syscall_count, &pid) para buscar.
    // Retorna un puntero __u64* al valor, o NULL si no existe.
    //
    // __u64 *count = ???;

    // TODO 3: Incrementar el contador existente, o insertar uno nuevo.
    //
    // Si count != NULL (el PID ya existe en el map):
    //   Usa __sync_fetch_and_add(count, 1) para incrementar atómicamente.
    //
    // Si count == NULL (primera syscall de este PID):
    //   Declara __u64 init_val = 1;
    //   Usa bpf_map_update_elem(&syscall_count, &pid, &init_val, BPF_ANY)
    //   para insertar la primera entrada.
    //

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
