//go:build ignore

// portable_tracer.bpf.c — Ejercicio Ninja: Observabilidad portable (Capítulo 15)
//
// Programa BPF que funciona SIN MODIFICACIÓN en kernels 5.10, 5.15 y 6.1.
// Demuestra todas las técnicas CO-RE del capítulo:
//
//   - BPF_CORE_READ para acceso portable a campos
//   - bpf_core_field_exists para manejar el rename state → __state
//   - Cadenas de dereference para acceder a PID namespace
//   - vmlinux.h en vez de kernel headers
//
// Funcionalidad:
//   1. Traza execve: reporta PID, PPID, UID, comm, PID namespace
//   2. Traza exit: reporta PID, exit code, tiempo de vida del proceso
//   3. Emite eventos via ring buffer a user space
//
// Attach points:
//   - kprobe/do_execveat_common (execve)
//   - kprobe/do_exit (exit)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// ============================================================================
// Tipos de eventos
// ============================================================================

#define EVENT_EXEC 1
#define EVENT_EXIT 2

// Evento de execve: proceso nuevo ejecutándose.
struct exec_event {
    __u8  type;         // EVENT_EXEC
    __u8  pad[3];
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 pid_ns_inum;  // PID namespace inode number
    char  comm[16];
};

// Evento de exit: proceso terminando.
struct exit_event {
    __u8  type;         // EVENT_EXIT
    __u8  pad[3];
    __u32 pid;
    __s32 exit_code;
    __u64 lifetime_ns;  // Tiempo de vida en nanosegundos
    char  comm[16];
};

// ============================================================================
// Maps
// ============================================================================

// Ring buffer para enviar eventos a user space.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Hash map para trackear start_time de procesos (para calcular lifetime).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} exec_times SEC(".maps");

// ============================================================================
// Helpers internos
// ============================================================================

// Obtener el estado del proceso de forma portable.
// El campo 'state' se renombró a '__state' en kernel 5.14+.
// Usamos bpf_core_field_exists para detectar cuál existe.
static __always_inline long get_task_state(struct task_struct *task) {
    // Primero intentar __state (kernel >= 5.14)
    if (bpf_core_field_exists(task->__state)) {
        return BPF_CORE_READ(task, __state);
    }
    // Fallback a state (kernel < 5.14)
    return BPF_CORE_READ(task, state);
}

// Obtener el PID namespace inode number.
// Cadena: task->nsproxy->pid_ns_for_children->ns.inum
// CO-RE genera 3 relocations para esta cadena.
static __always_inline __u32 get_pid_ns_inum(struct task_struct *task) {
    return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
}

// ============================================================================
// Programas BPF
// ============================================================================

// Traza execve — se dispara cuando un proceso ejecuta un nuevo programa.
SEC("kprobe/do_execveat_common")
int trace_exec(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // Leer campos con CO-RE (portable entre kernels).
    __u32 pid = BPF_CORE_READ(task, tgid);
    __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    __u32 uid = BPF_CORE_READ(task, real_cred, uid);

    // Acceder al PID namespace — cadena de 3 niveles.
    __u32 pid_ns = get_pid_ns_inum(task);

    // Guardar timestamp de inicio para calcular lifetime después.
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&exec_times, &pid, &now, BPF_ANY);

    // Reservar y emitir evento via ring buffer.
    struct exec_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->type = EVENT_EXEC;
    evt->pid = pid;
    evt->ppid = ppid;
    evt->uid = uid;
    evt->pid_ns_inum = pid_ns;
    BPF_CORE_READ_STR_INTO(&evt->comm, task, comm);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

// Traza exit — se dispara cuando un proceso termina.
SEC("kprobe/do_exit")
int trace_exit(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    __u32 pid = BPF_CORE_READ(task, tgid);

    // Calcular tiempo de vida: ahora - timestamp del exec.
    __u64 *start = bpf_map_lookup_elem(&exec_times, &pid);
    __u64 lifetime_ns = 0;
    if (start) {
        __u64 now = bpf_ktime_get_ns();
        lifetime_ns = now - *start;
        // Limpiar la entrada del map.
        bpf_map_delete_elem(&exec_times, &pid);
    }

    // Leer exit code del primer argumento de do_exit (en di register).
    // En kprobe, los argumentos están en pt_regs.
    long exit_code;
    bpf_probe_read_kernel(&exit_code, sizeof(exit_code), &ctx->di);

    // Emitir evento de exit.
    struct exit_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->type = EVENT_EXIT;
    evt->pid = pid;
    evt->exit_code = (__s32)exit_code;
    evt->lifetime_ns = lifetime_ns;
    BPF_CORE_READ_STR_INTO(&evt->comm, task, comm);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
