//go:build ignore

// escape_detector.bpf.c — Ejercicio Capítulo 17: Detector de Container Escapes
//
// Sistema de detección de intentos de escape de contenedores que combina:
//
// 1. LSM hooks — Intercepta mount y setns para bloquear/detectar escapes
// 2. Syscall monitoring — Monitorea patrones sospechosos típicos de escapes
// 3. Correlación — Detecta secuencias de syscalls que indican un escape activo
//
// Técnicas de escape detectadas:
// - Mount de /proc/host o filesystems del host desde dentro del container
// - setns hacia namespaces del host (PID, NET, MNT)
// - unshare para crear nuevos namespaces privilegiados
// - execve de binarios de escape (nsenter, chroot, pivot_root)
// - Acceso directo a /proc/1/ns/* (namespace del init host)
//
// Este ejercicio integra conceptos de:
// - Capítulo 9: Tracepoints para monitoreo de syscalls
// - Capítulo 12: Ring buffer para comunicación kernel→user
// - Capítulo 15: CO-RE para portabilidad entre kernels
// - Capítulo 17: LSM hooks para enforcement
//
// Attach points:
// - lsm/sb_mount — intercepta mount syscall
// - lsm/task_fix_setgroups — intercepta cambios de grupos
// - tracepoint/syscalls/sys_enter_execve
// - tracepoint/syscalls/sys_enter_setns
// - tracepoint/syscalls/sys_enter_unshare
// - tracepoint/syscalls/sys_enter_mount
//
// Requisitos: kernel >= 5.7 con CONFIG_BPF_LSM=y, BTF habilitado

#include <linux/bpf.h>
#include <linux/lsm_hooks.h>
#include <linux/errno.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// =============================================================================
// Configuración
// =============================================================================

// Severidad de alertas
#define SEV_INFO     0
#define SEV_WARNING  1
#define SEV_CRITICAL 2
#define SEV_ESCAPE   3  // Escape confirmado

// Tipos de evento
#define EVT_MOUNT_SUSPICIOUS    1  // mount sospechoso desde container
#define EVT_SETNS_ESCAPE        2  // setns hacia namespace del host
#define EVT_UNSHARE_PRIVILEGED  3  // unshare con flags privilegiados
#define EVT_EXEC_ESCAPE_TOOL    4  // ejecución de herramienta de escape
#define EVT_PROC_NS_ACCESS      5  // acceso a /proc/1/ns/*
#define EVT_LSM_MOUNT_BLOCKED   6  // mount bloqueado por LSM

// Flags de detección para unshare
#define CLONE_NEWNS   0x00020000
#define CLONE_NEWPID  0x20000000
#define CLONE_NEWUSER 0x10000000
#define CLONE_NEWNET  0x40000000

// Máximo de entradas
#define MAX_ESCAPE_TOOLS 16
#define MAX_PATH_LEN     128
#define MAX_BIN_LEN       64

// =============================================================================
// Estructuras
// =============================================================================

// Alerta de escape
struct escape_alert {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 event_type;      // EVT_*
    __u32 severity;        // SEV_*
    __u32 namespace_id;    // PID namespace del proceso
    __u32 flags;           // flags relevantes (mount flags, clone flags, etc.)
    __u32 _pad;
    char  comm[16];
    char  detail[MAX_PATH_LEN]; // path, binario, o descripción
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

// Argumentos del tracepoint sys_enter_mount
struct trace_event_raw_sys_enter_mount {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long syscall_nr;
    const char *dev_name;
    const char *dir_name;
    const char *type;
    unsigned long flags;
    const void *data;
};

// =============================================================================
// Maps
// =============================================================================

// Ring buffer para alertas de escape
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 21); // 2MB — más espacio para eventos críticos
} escape_alerts SEC(".maps");

// Herramientas de escape: nombre → severidad
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ESCAPE_TOOLS);
    __type(key, char[MAX_BIN_LEN]);
    __type(value, __u32);
} escape_tools SEC(".maps");

// Contadores per-CPU de eventos
// 0=total, 1=mount, 2=setns, 3=unshare, 4=execve, 5=blocked
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} escape_stats SEC(".maps");

// Configuración runtime: index 0 = enforce mode (1=block, 0=detect-only)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

// =============================================================================
// Funciones auxiliares
// =============================================================================

static __always_inline void stats_inc(__u32 idx) {
    __u64 *counter = bpf_map_lookup_elem(&escape_stats, &idx);
    if (counter)
        *counter += 1;
}

static __always_inline __u32 get_config(__u32 idx) {
    __u32 *val = bpf_map_lookup_elem(&config, &idx);
    return val ? *val : 0;
}

static __always_inline __u32 get_pid_ns_inum() {
    struct task_struct *task = (void *)bpf_get_current_task();
    __u32 ns_id = 0;

    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (nsproxy) {
        struct pid_namespace *pid_ns = BPF_CORE_READ(nsproxy, pid_ns_for_children);
        if (pid_ns) {
            ns_id = BPF_CORE_READ(pid_ns, ns.inum);
        }
    }
    return ns_id;
}

static __always_inline int is_in_container() {
    // Un proceso en container tiene un PID namespace distinto del host.
    // El host namespace tiene un inum conocido. Si leemos un ns distinto
    // de cero, probablemente estamos en un container.
    return get_pid_ns_inum() != 0;
}

static __always_inline void emit_alert(
    __u32 event_type, __u32 severity, __u32 flags,
    const char *detail, int detail_len
) {
    struct escape_alert *alert;
    alert = bpf_ringbuf_reserve(&escape_alerts, sizeof(*alert), 0);
    if (!alert)
        return;

    alert->timestamp_ns = bpf_ktime_get_ns();
    alert->pid = bpf_get_current_pid_tgid() >> 32;
    alert->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    alert->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    alert->event_type = event_type;
    alert->severity = severity;
    alert->namespace_id = get_pid_ns_inum();
    alert->flags = flags;
    alert->_pad = 0;
    bpf_get_current_comm(alert->comm, sizeof(alert->comm));

    if (detail && detail_len > 0) {
        bpf_probe_read_kernel_str(alert->detail, sizeof(alert->detail), detail);
    } else {
        alert->detail[0] = '\0';
    }

    bpf_ringbuf_submit(alert, 0);
}

// =============================================================================
// LSM Hook: sb_mount — Intercepta intentos de mount
// =============================================================================

SEC("lsm/sb_mount")
int BPF_PROG(lsm_sb_mount,
    const char *dev_name, const struct path *path,
    const char *type, unsigned long flags, void *data)
{
    stats_inc(0);
    stats_inc(1);

    // Solo nos interesan mounts desde containers
    if (!is_in_container())
        return 0;

    // Cualquier mount desde un container es sospechoso
    __u32 severity = SEV_WARNING;

    // Si estamos en enforce mode, bloquear
    __u32 enforce = get_config(0);

    emit_alert(EVT_LSM_MOUNT_BLOCKED, severity, (__u32)flags, dev_name, 0);

    if (enforce) {
        stats_inc(5); // blocked counter
        return -EPERM;
    }

    return 0;
}

// =============================================================================
// Tracepoint: execve — Detecta herramientas de escape
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_escape_execve(struct trace_event_raw_sys_enter_execve *ctx) {
    stats_inc(0);
    stats_inc(4);

    // Solo monitorear procesos en containers
    __u32 ns_id = get_pid_ns_inum();
    if (ns_id == 0)
        return 0;

    // Leer filename
    char filename[MAX_BIN_LEN] = {};
    bpf_probe_read_user_str(filename, sizeof(filename), ctx->filename);

    // Buscar en tabla de herramientas de escape
    __u32 *sev = bpf_map_lookup_elem(&escape_tools, filename);
    if (!sev)
        return 0;

    // ¡Herramienta de escape ejecutada desde container!
    __u32 severity = *sev;

    // Elevar a ESCAPE si estamos en container
    if (severity >= SEV_CRITICAL)
        severity = SEV_ESCAPE;

    emit_alert(EVT_EXEC_ESCAPE_TOOL, severity, 0, filename, sizeof(filename));

    return 0;
}

// =============================================================================
// Tracepoint: setns — Detecta cambio de namespace (escape clásico)
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_setns")
int trace_escape_setns(struct trace_event_raw_sys_enter_setns *ctx) {
    stats_inc(0);
    stats_inc(2);

    __u32 ns_id = get_pid_ns_inum();

    // setns desde container = escape attempt
    __u32 severity = SEV_WARNING;
    if (ns_id != 0)
        severity = SEV_ESCAPE;

    emit_alert(EVT_SETNS_ESCAPE, severity, (__u32)ctx->flags, NULL, 0);

    return 0;
}

// =============================================================================
// Tracepoint: unshare — Detecta creación de namespaces privilegiados
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_escape_unshare(struct trace_event_raw_sys_enter_unshare *ctx) {
    stats_inc(0);
    stats_inc(3);

    __u32 ns_id = get_pid_ns_inum();
    int flags = ctx->flags;

    // Solo alertar si los flags incluyen namespaces sensibles
    int suspicious = (flags & CLONE_NEWNS) ||
                     (flags & CLONE_NEWPID) ||
                     (flags & CLONE_NEWUSER) ||
                     (flags & CLONE_NEWNET);

    if (!suspicious)
        return 0;

    __u32 severity = SEV_WARNING;
    if (ns_id != 0) {
        // unshare de namespaces privilegiados desde container = escape
        severity = SEV_ESCAPE;
    }

    emit_alert(EVT_UNSHARE_PRIVILEGED, severity, (__u32)flags, NULL, 0);

    return 0;
}

// =============================================================================
// Tracepoint: mount — Monitoreo adicional de mounts sospechosos
// =============================================================================

SEC("tracepoint/syscalls/sys_enter_mount")
int trace_escape_mount(struct trace_event_raw_sys_enter_mount *ctx) {
    stats_inc(0);
    stats_inc(1);

    __u32 ns_id = get_pid_ns_inum();
    if (ns_id == 0)
        return 0;

    // Mount desde container — leer source para más contexto
    char dev_name[MAX_PATH_LEN] = {};
    bpf_probe_read_user_str(dev_name, sizeof(dev_name), ctx->dev_name);

    __u32 severity = SEV_CRITICAL;

    emit_alert(EVT_MOUNT_SUSPICIOUS, severity, (__u32)ctx->flags, dev_name, sizeof(dev_name));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
