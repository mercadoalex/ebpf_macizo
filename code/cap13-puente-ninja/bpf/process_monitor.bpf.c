//go:build ignore

// process_monitor.bpf.c — Capítulo 13: Process Lifecycle Monitor (Referencia)
//
// Ejercicio integrador del Nivel Intermedio. Combina:
//   - Hash maps (Cap 6) para almacenar metadata de procesos
//   - Helper functions (Cap 8) para timestamps, comm, PIDs
//   - Tracepoints (Cap 9) para detectar fork y exit
//   - Ring buffer (Cap 12) para enviar eventos a user space
//
// Este programa trackea el ciclo de vida de procesos en tiempo real:
//   - sched_process_fork → registra proceso nuevo, emite evento FORK
//   - sched_process_exit → calcula duración de vida, limpia map, emite evento EXIT
//
// Attach points:
//   - tracepoint/sched/sched_process_fork
//   - tracepoint/sched/sched_process_exit

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define EVENT_FORK 1
#define EVENT_EXIT 2

// Información que guardamos sobre cada proceso en el hash map.
// El map funciona como un "registro de nacimiento": cuando un proceso
// hace fork, guardamos cuándo nació y cómo se llama.
struct process_info {
    __u64 start_time;
    char comm[TASK_COMM_LEN];
};

// Evento que enviamos a user space via ring buffer.
// Contiene todo lo que el consumer necesita para mostrar el evento.
struct event {
    __u8 type;           // EVENT_FORK=1, EVENT_EXIT=2
    __u8 _pad[3];        // Padding explícito para alineación
    __u32 pid;           // PID del proceso
    __u32 ppid;          // PID del padre
    __u32 _pad2;         // Padding para alinear timestamp a 8 bytes
    __u64 timestamp;     // Timestamp del evento (ns)
    __u64 duration_ns;   // Duración de vida (solo EXIT, 0 si desconocido)
    char comm[TASK_COMM_LEN]; // Nombre del proceso
};

// ─── Maps ────────────────────────────────────────────────────────────────────

// Hash map: PID → process_info.
// Se usa como tabla de "procesos nacidos bajo nuestra vigilancia".
// max_entries=10240 es generoso para un sistema normal.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct process_info);
} process_info_map SEC(".maps");

// Ring buffer: canal de comunicación kernel → user space.
// Los eventos se serializan aquí y el consumer en Go los lee.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// ─── Tracepoint: sched_process_fork ─────────────────────────────────────────

struct sched_process_fork_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    char parent_comm[16];
    pid_t parent_pid;
    char child_comm[16];
    pid_t child_pid;
};

SEC("tp/sched/sched_process_fork")
int handle_fork(struct sched_process_fork_args *ctx)
{
    __u32 child_pid = ctx->child_pid;
    __u32 parent_pid = ctx->parent_pid;
    __u64 ts = bpf_ktime_get_ns();

    // Registrar el proceso nuevo en el hash map.
    struct process_info info = {};
    info.start_time = ts;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    bpf_map_update_elem(&process_info_map, &child_pid, &info, BPF_ANY);

    // Emitir evento FORK via ring buffer.
    struct event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!evt) {
        return 0;
    }

    evt->type = EVENT_FORK;
    evt->pid = child_pid;
    evt->ppid = parent_pid;
    evt->timestamp = ts;
    evt->duration_ns = 0;
    __builtin_memcpy(evt->comm, info.comm, TASK_COMM_LEN);

    bpf_ringbuf_submit(evt, 0);

    return 0;
}

// ─── Tracepoint: sched_process_exit ─────────────────────────────────────────

struct sched_process_exit_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    char comm[16];
    pid_t pid;
    int prio;
};

SEC("tp/sched/sched_process_exit")
int handle_exit(struct sched_process_exit_args *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 ts = bpf_ktime_get_ns();

    // Buscar en el map: ¿nació bajo nuestra vigilancia?
    __u64 duration = 0;
    struct process_info *info = bpf_map_lookup_elem(&process_info_map, &pid);
    if (info) {
        duration = ts - info->start_time;
        bpf_map_delete_elem(&process_info_map, &pid);
    }

    // Emitir evento EXIT.
    struct event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!evt) {
        return 0;
    }

    evt->type = EVENT_EXIT;
    evt->pid = pid;
    evt->ppid = 0;
    evt->timestamp = ts;
    evt->duration_ns = duration;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
