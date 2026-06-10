//go:build ignore

// 01_null_deref.bpf.c — Versión CORREGIDA
//
// FIX: Verificar que el puntero de bpf_map_lookup_elem no es NULL
// antes de dereferenciarlo.
//
// Patrón correcto:
//   ptr = bpf_map_lookup_elem(&map, &key);
//   if (!ptr)        ← Null check OBLIGATORIO
//       return 0;
//   *ptr += 1;      ← Ahora es seguro
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
    __u64 initial = 0;

    // Intentar buscar el contador existente para este PID
    __u64 *count = bpf_map_lookup_elem(&exec_count, &pid);

    // ✅ FIX: Verificar si el puntero es NULL.
    // Si la key no existe, insertamos un valor inicial.
    if (!count) {
        // La key no existe todavía — la creamos con valor 0
        bpf_map_update_elem(&exec_count, &pid, &initial, BPF_ANY);
        // Volver a buscar para obtener un puntero válido
        count = bpf_map_lookup_elem(&exec_count, &pid);
        if (!count)
            return 0;  // Si aún falla, salir limpio
    }

    // ✅ Ahora count apunta a memoria válida del map — seguro
    *count += 1;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
