//go:build ignore

// 01_null_deref.bpf.c — Programa ROTO: Falla el verifier
//
// ERROR: Dereferencia de puntero sin null check
//
// Cuando haces bpf_map_lookup_elem(), el retorno puede ser NULL
// (si la key no existe en el map). El verifier EXIGE que verifiques
// el puntero antes de usarlo. Si no lo haces → rechazado.
//
// Error del verifier:
//   "R0 invalid mem access 'map_value_or_null'"
//   "dereference of modified ctx ptr"
//
// Attach point: tracepoint/syscalls/sys_enter_execve

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Map para contar execve() por PID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} exec_count SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int count_execve(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // ❌ ERROR: bpf_map_lookup_elem puede retornar NULL.
    // Estamos usando el valor directamente sin verificar si es NULL.
    // El verifier ve que count puede ser NULL y no nos deja
    // dereferenciarlo.
    __u64 *count = bpf_map_lookup_elem(&exec_count, &pid);

    // ❌ Esto explota: si pid no está en el map, count == NULL
    // y estamos escribiendo en dirección NULL.
    *count += 1;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
