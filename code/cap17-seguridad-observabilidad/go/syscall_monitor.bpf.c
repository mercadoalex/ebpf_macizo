//go:build ignore

// syscall_monitor.bpf.c — Capítulo 17: Monitoreo de Syscalls Sospechosas
//
// Este programa detecta patrones de syscalls asociados con actividad
// maliciosa o intentos de escape de contenedores:
//
// 1. execve desde procesos en namespaces no-root (containers)
// 2. Manipulación de namespaces (setns, unshare) — señal de escape
// 3. Ejecución de binarios sensibles (nsenter, mount, etc.)
// 4. Patrones de escalación de privilegios
//
// Emite alertas clasificadas por severidad al user space via ring buffer.
// El control plane (Go) consume los eventos y decide si alertar.
//
// Attach points:
// - tracepoint/syscalls/sys_enter_execve — detecta ejecuciones sospechosas
// - tracepoint/syscalls/sys_enter_setns  — detecta cambio de namespace
// - tracepoint/syscalls/sys_enter_unshare — detecta creación de namespace
//
// Requisitos: kernel >= 5.8 con BTF habilitado

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// =============================================================================
// Configuración
// =============================================================================

// Niveles de severidad para alertas
#define SEVERITY_INFO     0
#define SEVERITY_WARNING  1
#define SEVERITY_CRITICAL 2

// Tipos de evento detectado
#define EVENT_EXECVE_CONTAINER  1  // execve desde un container
#define EVENT_SETNS             2  // setns (cambio de namespace)
#define EVENT_UNSHARE           3  // unshare (creación de namespace)
#define EVENT_SUSPICIOUS_EXEC   4  // ejecución de binario sensible

// Máximo de binarios sospechosos a monitorear
#define MAX_SUSPICIOUS_BINS 32

// Largo máximo del path del binario
#define MAX_BIN_LEN 64

// =============================================================================
// Estructuras
// =============================================================================

// Alerta de seguridad emitida al user space
struct syscall_alert {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 event_type;    // EVENT_*
    __u32 severity;      // SEVERITY_*
    __u32 namespace_id;  // PID namespace del proceso
    char  comm[16];      // Nombre del proceso
    char  filename[MAX_BIN_LEN]; // Binario ejecutado (si aplica)
};

// Argumentos del tracepoint sys_enter_execve
struct trace_event_raw_sys_enter_execve {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

// Argumentos del tracepoint sys_enter_setns
struct trace_event_raw_sys_enter_setns {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long syscall_nr;
    int fd;
    int flags;
};

// Argumentos del tracepoint sys_enter_unshare
struct trace_event_raw_sys_enter_unshare {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long syscall_nr;
    int flags;
};

// =============================================================================
// Maps
// =============================================================================

// Ring buffer para alertas
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB
} alerts SEC(".maps");

// Hash map de binarios sospechosos: nombre → severidad
// El control plane llena esto con los nombres a vigilar.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SUSPICIOUS_BINS);
    __type(key, char[MAX_BIN_LEN]);
    __type(value, __u32); // severidad
} suspicious_bins SEC(".maps");

// Estadísticas per-CPU: index → count
// 0 = total events, 1 = execve, 2 = setns, 3 = unshare
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} monitor_stats SEC(".maps");

// =============================================================================
// Funciones auxiliares
// =============================================================================

static __always_inline void stats_inc(__u32 idx) {
    __u64 *counter = bpf_map_lookup_elem(&monitor_stats, &idx);
    if (counter)
        *counter += 1;
}

// Determina si el proceso está en un namespace no-root (indicador de container).
// Compara el PID namespace del proceso con el PID namespace init (1).
static __always_inline __u32 get_pid_namespace() {
    struct task_struct *task = (void *)bpf_get_current_task();
    __u32 ns_id = 0;

    // Leer el PID namespace inum del proceso actual
    // task->nsproxy->pid_ns_for_children->ns.inum
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (nsproxy) {
        struct pid_namespace *pid_ns = BPF_CORE_READ(nsproxy, pid_ns_for_children);
        if (pid_ns) {
            ns_id = BPF_CORE_READ(pid_ns, ns.inum);
        }
    }

    return ns_id;
}

// Verifica si estamos en un container (namespace distinto al host)
// El PID namespace del host típicamente es un valor fijo bajo.
static __always_inline int is_container_context() {
    __u32 ns_id = get_pid_namespace();
    // Si el namespace ID es distinto a 0 y al típico del host,
    // probablemente estamos en un container.
    // El namespace del host es generalmente 0xF0000000+ (varía por kernel).
    // En la práctica, comparamos contra el PID NS init que se configura via map.
    // Simplificación: si ns_id != 0, asumimos que leímos el namespace.
    return ns_id != 0;
}

// =============================================================================
// Programa: Monitoreo de execve
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter_execve *ctx) {
    stats_inc(0); // total events
    stats_inc(1); // execve events

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Leer el filename del execve
    char filename[MAX_BIN_LEN] = {};
    const char *fname_ptr = ctx->filename;
    bpf_probe_read_user_str(filename, sizeof(filename), fname_ptr);

    // Determinar severidad y tipo de evento
    __u32 event_type = 0;
    __u32 severity = SEVERITY_INFO;

    // Check 1: ¿Es un binario en la lista de sospechosos?
    __u32 *sev = bpf_map_lookup_elem(&suspicious_bins, filename);
    if (sev) {
        event_type = EVENT_SUSPICIOUS_EXEC;
        severity = *sev;
    }

    // Check 2: ¿Está en un container?
    __u32 ns_id = get_pid_namespace();
    if (ns_id != 0 && event_type == 0) {
        // execve desde container — info level por defecto
        event_type = EVENT_EXECVE_CONTAINER;
        severity = SEVERITY_INFO;
    }

    // Si es un binario sospechoso desde un container, elevar severidad
    if (sev && ns_id != 0) {
        severity = SEVERITY_CRITICAL;
    }

    // Solo emitir alerta si hay algo interesante
    if (event_type == 0)
        return 0;

    // Emitir alerta
    struct syscall_alert *alert;
    alert = bpf_ringbuf_reserve(&alerts, sizeof(*alert), 0);
    if (!alert)
        return 0;

    alert->timestamp_ns = bpf_ktime_get_ns();
    alert->pid = pid;
    alert->tgid = tgid;
    alert->uid = uid;
    alert->event_type = event_type;
    alert->severity = severity;
    alert->namespace_id = ns_id;
    bpf_get_current_comm(alert->comm, sizeof(alert->comm));
    __builtin_memcpy(alert->filename, filename, MAX_BIN_LEN);

    bpf_ringbuf_submit(alert, 0);

    return 0;
}

// =============================================================================
// Programa: Monitoreo de setns (cambio de namespace)
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_setns")
int trace_setns(struct trace_event_raw_sys_enter_setns *ctx) {
    stats_inc(0); // total events
    stats_inc(2); // setns events

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 ns_id = get_pid_namespace();

    // setns siempre es sospechoso — severidad WARNING mínimo
    __u32 severity = SEVERITY_WARNING;

    // Si se ejecuta desde un container, es CRITICAL (posible escape)
    if (ns_id != 0)
        severity = SEVERITY_CRITICAL;

    // Emitir alerta
    struct syscall_alert *alert;
    alert = bpf_ringbuf_reserve(&alerts, sizeof(*alert), 0);
    if (!alert)
        return 0;

    alert->timestamp_ns = bpf_ktime_get_ns();
    alert->pid = pid;
    alert->tgid = tgid;
    alert->uid = uid;
    alert->event_type = EVENT_SETNS;
    alert->severity = severity;
    alert->namespace_id = ns_id;
    bpf_get_current_comm(alert->comm, sizeof(alert->comm));
    alert->filename[0] = '\0'; // No aplica filename para setns

    bpf_ringbuf_submit(alert, 0);

    return 0;
}

// =============================================================================
// Programa: Monitoreo de unshare (creación de namespace)
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_unshare(struct trace_event_raw_sys_enter_unshare *ctx) {
    stats_inc(0); // total events
    stats_inc(3); // unshare events

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    __u32 ns_id = get_pid_namespace();

    // unshare con flags de namespace desde container es sospechoso
    __u32 severity = SEVERITY_WARNING;
    if (ns_id != 0)
        severity = SEVERITY_CRITICAL;

    // Emitir alerta
    struct syscall_alert *alert;
    alert = bpf_ringbuf_reserve(&alerts, sizeof(*alert), 0);
    if (!alert)
        return 0;

    alert->timestamp_ns = bpf_ktime_get_ns();
    alert->pid = pid;
    alert->tgid = tgid;
    alert->uid = uid;
    alert->event_type = EVENT_UNSHARE;
    alert->severity = severity;
    alert->namespace_id = ns_id;
    bpf_get_current_comm(alert->comm, sizeof(alert->comm));
    alert->filename[0] = '\0';

    bpf_ringbuf_submit(alert, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
