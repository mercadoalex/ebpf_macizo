//go:build ignore

// 03_uninitialized.bpf.c — Programa ROTO: Falla el verifier
//
// ERROR: Struct pasada a helper function sin inicialización completa
//
// Cuando pasas una struct por referencia a una helper function,
// el verifier exige que TODOS los bytes estén inicializados.
// Si dejas campos sin inicializar, podría haber basura del stack
// que se filtre como información del kernel → rechazado.
//
// Error del verifier:
//   "invalid indirect read from stack R2 off -24+8 size 24"
//   "uninitialized stack memory"
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
    struct event evt;

    // ❌ ERROR: Solo inicializamos ALGUNOS campos de la struct.
    // El campo uid queda sin inicializar.
    // Cuando pasamos &evt a bpf_perf_event_output(), el verifier
    // detecta que hay bytes no inicializados en el stack.
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    // evt.uid = ???  ← NO SE INICIALIZA
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // ❌ El verifier rechaza esto porque evt.uid tiene basura
    // del stack, y esa basura podría contener datos sensibles
    // del kernel que estaríamos enviando a user space.
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &evt, sizeof(evt));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
