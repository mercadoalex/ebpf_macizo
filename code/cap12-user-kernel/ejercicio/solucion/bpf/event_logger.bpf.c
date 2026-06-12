//go:build ignore

// event_logger.bpf.c — Ejercicio Capítulo 12: Event Logger con Ring Buffer (Solución)
//
// Este programa BPF captura dos tipos de eventos de procesos:
//   1. EXEC — cuando un proceso ejecuta un nuevo binario (execve)
//   2. EXIT — cuando un proceso termina (sched_process_exit)
//
// Los eventos se envían a user space via ring buffer como structs
// tipados. El consumer en Go los deserializa y muestra.
//
// Attach points:
//   - tracepoint/syscalls/sys_enter_execve (eventos EXEC)
//   - tracepoint/sched/sched_process_exit  (eventos EXIT)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Tipos de evento.
#define EVENT_EXEC 1
#define EVENT_EXIT 2

// Estructura del evento — debe coincidir EXACTAMENTE con la struct en Go.
struct process_event {
    __u32 event_type;    // EVENT_EXEC o EVENT_EXIT
    __u32 pid;           // PID del proceso
    __u32 ppid;          // PID del padre (relevante en EXEC)
    __u32 exit_code;     // Código de salida (relevante en EXIT)
    __u64 timestamp_ns;  // Timestamp del evento
    char comm[16];       // Nombre del proceso
};

// Ring buffer — 256KB.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// ─── Tracepoint: execve (proceso nuevo) ─────────────────────────

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(void *ctx) {
    struct process_event *evt;

    evt = bpf_ringbuf_reserve(&events, sizeof(struct process_event), 0);
    if (!evt) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    evt->event_type = EVENT_EXEC;
    evt->pid = pid_tgid >> 32;
    evt->ppid = bpf_get_current_pid_tgid() & 0xFFFFFFFF; // tgid (thread group)
    evt->exit_code = 0;
    evt->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// ─── Tracepoint: process exit (proceso termina) ─────────────────

// Argumentos del tracepoint sched/sched_process_exit.
struct sched_process_exit_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    char comm[16];
    pid_t pid;
    int prio;
};

SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct sched_process_exit_args *ctx) {
    struct process_event *evt;

    evt = bpf_ringbuf_reserve(&events, sizeof(struct process_event), 0);
    if (!evt) {
        return 0;
    }

    evt->event_type = EVENT_EXIT;
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->ppid = 0;
    evt->exit_code = ctx->prio; // Usamos prio como proxy del exit code aquí
    evt->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
