//go:build ignore

// process_monitor.bpf.c — Solución Ejercicio Integrador Cap 13: Process Lifecycle Monitor
//
// Este programa BPF trackea el ciclo de vida de procesos:
//   - sched_process_fork → registra proceso nuevo, emite evento FORK
//   - sched_process_exit → calcula duración, limpia map, emite evento EXIT
//
// Combina: hash maps (Cap 6), helpers (Cap 8), tracepoints (Cap 9),
// y ring buffer (Cap 12). Todo lo del Nivel Intermedio en un solo programa.
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
struct process_info {
    __u64 start_time;
    char comm[TASK_COMM_LEN];
};

// Evento que enviamos a user space via ring buffer.
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

// Hash map para almacenar metadata de procesos activos.
// Cuando un proceso hace fork, guardamos su PID → (start_time, comm).
// Cuando un proceso hace exit, hacemos lookup + delete.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct process_info);
} process_info_map SEC(".maps");

// Ring buffer para enviar eventos estructurados a user space.
// 256KB es suficiente para la mayoría de workloads.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// ─── Argumentos del tracepoint sched/sched_process_fork ─────────────────────

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
    // 1. Obtener PIDs del contexto del tracepoint.
    __u32 child_pid = ctx->child_pid;
    __u32 parent_pid = ctx->parent_pid;

    // 2. Timestamp de creación.
    __u64 ts = bpf_ktime_get_ns();

    // 3. Crear registro de proceso y guardarlo en el hash map.
    struct process_info info = {};
    info.start_time = ts;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    bpf_map_update_elem(&process_info_map, &child_pid, &info, BPF_ANY);

    // 4. Reservar espacio en el ring buffer para el evento.
    struct event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!evt) {
        // Buffer lleno — descartamos el evento silenciosamente.
        return 0;
    }

    // 5. Llenar el evento FORK.
    evt->type = EVENT_FORK;
    evt->pid = child_pid;
    evt->ppid = parent_pid;
    evt->timestamp = ts;
    evt->duration_ns = 0;  // No aplica para fork.
    __builtin_memcpy(evt->comm, info.comm, TASK_COMM_LEN);

    // 6. Enviar el evento a user space.
    bpf_ringbuf_submit(evt, 0);

    return 0;
}

// ─── Argumentos del tracepoint sched/sched_process_exit ─────────────────────

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
    // 1. Obtener el PID del proceso que está terminando.
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 2. Obtener timestamp actual.
    __u64 ts = bpf_ktime_get_ns();

    // 3. Buscar en el hash map — ¿registramos este proceso?
    __u64 duration = 0;
    struct process_info *info = bpf_map_lookup_elem(&process_info_map, &pid);
    if (info) {
        // El proceso fue registrado por nuestro handle_fork.
        // Calcular cuánto tiempo vivió.
        duration = ts - info->start_time;

        // Limpiar la entrada del map — evita memory leaks.
        bpf_map_delete_elem(&process_info_map, &pid);
    }
    // Si info == NULL: el proceso se creó antes de que cargáramos el programa.
    // Emitimos el evento con duration = 0 (desconocido).

    // 4. Reservar espacio en el ring buffer.
    struct event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!evt) {
        return 0;
    }

    // 5. Llenar el evento EXIT.
    evt->type = EVENT_EXIT;
    evt->pid = pid;
    evt->ppid = 0;  // No relevante en exit.
    evt->timestamp = ts;
    evt->duration_ns = duration;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    // 6. Enviar.
    bpf_ringbuf_submit(evt, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
