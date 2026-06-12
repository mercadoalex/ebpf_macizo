//go:build ignore

// process_monitor.bpf.c — Ejercicio Integrador Capítulo 13: Process Lifecycle Monitor
//
// Este programa BPF trackea el ciclo de vida de procesos:
//   - sched_process_fork → registra proceso nuevo, emite evento FORK
//   - sched_process_exit → calcula duración, limpia map, emite evento EXIT
//
// Combina: hash maps (Cap 6), helpers (Cap 8), tracepoints (Cap 9),
// y ring buffer (Cap 12). Todo lo del Nivel Intermedio en un solo programa.
//
// TU TRABAJO: Implementar los TODOs en las funciones handle_fork y handle_exit.
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
// NOTA: Hay padding después de 'type' para alinear 'pid' a 4 bytes.
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

// ─────────────────────────────────────────────────────────────────────────────
// TODO 1: Definir el hash map "process_info_map"
//
// Necesitas un BPF_MAP_TYPE_HASH que almacene:
//   - key:   __u32 (pid del proceso)
//   - value: struct process_info (start_time + comm)
//   - max_entries: 10240
//
// Pista: Usa la sintaxis BTF-style:
//   struct {
//       __uint(type, BPF_MAP_TYPE_HASH);
//       __uint(max_entries, 10240);
//       __type(key, __u32);
//       __type(value, struct process_info);
//   } process_info_map SEC(".maps");
// ─────────────────────────────────────────────────────────────────────────────

// >>> TU CÓDIGO AQUÍ (hash map) <<<

// ─────────────────────────────────────────────────────────────────────────────
// TODO 2: Definir el ring buffer "events"
//
// Ring buffer de 256KB para enviar eventos a user space.
//
// Pista: Usa la sintaxis BTF-style:
//   struct {
//       __uint(type, BPF_MAP_TYPE_RINGBUF);
//       __uint(max_entries, 256 * 1024);
//   } events SEC(".maps");
// ─────────────────────────────────────────────────────────────────────────────

// >>> TU CÓDIGO AQUÍ (ring buffer) <<<

// ─── Argumentos del tracepoint sched/sched_process_fork ─────────────────────
// Formato: /sys/kernel/debug/tracing/events/sched/sched_process_fork/format
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
    // ─────────────────────────────────────────────────────────────────────────
    // TODO 3: Implementar el handler de fork.
    //
    // Pasos:
    //   1. Obtener el PID del proceso hijo: ctx->child_pid
    //   2. Obtener el PID del padre: ctx->parent_pid
    //   3. Obtener el timestamp actual: bpf_ktime_get_ns()
    //   4. Crear un struct process_info con start_time y comm
    //      - Usa bpf_get_current_comm() para obtener el comm
    //   5. Guardar en el hash map: bpf_map_update_elem(&process_info_map, &child_pid, &info, BPF_ANY)
    //   6. Reservar espacio en el ring buffer: bpf_ringbuf_reserve(&events, sizeof(struct event), 0)
    //      - Si retorna NULL, retornar 0 (buffer lleno, descartamos)
    //   7. Llenar el struct event:
    //      - type = EVENT_FORK
    //      - pid = child_pid
    //      - ppid = parent_pid
    //      - timestamp = el timestamp que obtuviste
    //      - duration_ns = 0 (no aplica para fork)
    //      - comm = copiar con __builtin_memcpy o bpf_probe_read_kernel
    //   8. Enviar: bpf_ringbuf_submit(evt, 0)
    // ─────────────────────────────────────────────────────────────────────────

    // >>> TU CÓDIGO AQUÍ <<<

    return 0;
}

// ─── Argumentos del tracepoint sched/sched_process_exit ─────────────────────
// Formato: /sys/kernel/debug/tracing/events/sched/sched_process_exit/format
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
    // ─────────────────────────────────────────────────────────────────────────
    // TODO 4: Implementar el handler de exit.
    //
    // Pasos:
    //   1. Obtener el PID: bpf_get_current_pid_tgid() >> 32
    //   2. Buscar en el hash map: bpf_map_lookup_elem(&process_info_map, &pid)
    //   3. Si existe en el map:
    //      a. Calcular duración: bpf_ktime_get_ns() - info->start_time
    //      b. Eliminar del map: bpf_map_delete_elem(&process_info_map, &pid)
    //   4. Si NO existe: el proceso se creó antes de cargar el programa
    //      - Usa duration = 0 para indicar "desconocido"
    //   5. Reservar espacio en el ring buffer
    //      - Si retorna NULL, retornar 0
    //   6. Llenar el struct event:
    //      - type = EVENT_EXIT
    //      - pid = pid del proceso
    //      - ppid = 0 (no relevante en exit)
    //      - timestamp = ahora
    //      - duration_ns = la duración calculada (o 0 si no estaba en map)
    //      - comm = bpf_get_current_comm()
    //   7. Enviar: bpf_ringbuf_submit(evt, 0)
    // ─────────────────────────────────────────────────────────────────────────

    // >>> TU CÓDIGO AQUÍ <<<

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
