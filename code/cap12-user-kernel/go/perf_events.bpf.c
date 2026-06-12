//go:build ignore

// perf_events.bpf.c — Capítulo 12: Perf Events (forma clásica)
//
// Demuestra el uso de BPF_MAP_TYPE_PERF_EVENT_ARRAY para enviar eventos
// del kernel a user space. Esta es la forma "clásica" de comunicación
// antes de que existiera el ring buffer.
//
// Perf events es per-CPU: cada CPU tiene su propio buffer, lo que evita
// contención pero requiere que user space lea de múltiples buffers.
//
// Cada vez que se crea un proceso (fork/clone via sched_process_fork),
// enviamos un evento con PID del padre, PID del hijo, y nombre.
//
// Attach point: tracepoint/sched/sched_process_fork
// Map: perf_events (perf_event_array)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Estructura del evento — debe coincidir con la definición en Go.
struct fork_event {
    __u32 parent_pid;
    __u32 child_pid;
    __u64 timestamp_ns;
    char comm[16];
};

// Perf event array — el kernel escribe aquí, user space lee.
// A diferencia de un hash/array map, esto es un canal de streaming.
// max_entries = número de CPUs (el kernel lo ajusta automáticamente).
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} perf_events SEC(".maps");

// Argumentos del tracepoint sched_process_fork.
// Esta estructura refleja el formato del tracepoint en el kernel.
struct sched_process_fork_args {
    // Los primeros campos son comunes a todos los tracepoints.
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    // Campos específicos de sched_process_fork.
    char parent_comm[16];
    pid_t parent_pid;
    char child_comm[16];
    pid_t child_pid;
};

SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct sched_process_fork_args *ctx) {
    struct fork_event evt = {};

    // Llenar el evento con datos del tracepoint.
    evt.parent_pid = ctx->parent_pid;
    evt.child_pid = ctx->child_pid;
    evt.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // Enviar evento via perf buffer.
    // Flags=BPF_F_CURRENT_CPU indica enviar al buffer de la CPU actual.
    bpf_perf_event_output(ctx, &perf_events, BPF_F_CURRENT_CPU,
                          &evt, sizeof(evt));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
