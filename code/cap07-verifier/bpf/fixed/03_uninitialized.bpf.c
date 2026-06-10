//go:build ignore

// 03_uninitialized.bpf.c — Versión CORREGIDA
//
// FIX: Inicializar TODOS los campos de la struct antes de pasarla
// a una helper function.
//
// Patrón correcto:
//   struct event evt = {};    ← Inicializa todo a cero
//   evt.pid = ...;
//   evt.uid = ...;
//   bpf_perf_event_output(ctx, &map, flags, &evt, sizeof(evt));
//
// Alternativa:
//   __builtin_memset(&evt, 0, sizeof(evt));  ← También funciona
//
// Attach point: tracepoint/syscalls/sys_enter_execve

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Estructura para enviar datos a user space via perf event
struct event {
    __u32 pid;
    __u32 uid;
    char comm[16];
};

// Map de tipo perf event array para enviar eventos
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx) {
    // ✅ FIX: Inicializar la struct entera a cero.
    // El "= {}" (zero initialization) garantiza que TODOS los bytes
    // del struct son cero antes de rellenarlos. Ninguna basura del
    // stack se filtra a user space.
    struct event evt = {};

    // Rellenamos los campos que queremos
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // ✅ Ahora es seguro: toda la struct está inicializada
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &evt, sizeof(evt));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
