//go:build ignore

// portable_tracer.bpf.c — Copia para go generate (Ejercicio Ninja, Capítulo 15)
//
// Original en ../bpf/. bpf2go necesita el .bpf.c en el mismo directorio.
//
// Programa portable entre kernels 5.10/5.15/6.1 que demuestra:
//   - BPF_CORE_READ para acceso portable
//   - bpf_core_field_exists para el rename state → __state
//   - Cadenas de dereference para PID namespace
//   - Ring buffer para eventos a user space

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// ============================================================================
// Tipos de eventos
// ============================================================================

#define EVENT_EXEC 1
#define EVENT_EXIT 2

struct exec_event {
    __u8  type;
    __u8  pad[3];
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 pid_ns_inum;
    char  comm[16];
};

struct exit_event {
    __u8  type;
    __u8  pad[3];
    __u32 pid;
    __s32 exit_code;
    __u64 lifetime_ns;
    char  comm[16];
};

// ============================================================================
// Maps
// ============================================================================

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} exec_times SEC(".maps");

// ============================================================================
// Helpers
// ============================================================================

static __always_inline long get_task_state(struct task_struct *task) {
    if (bpf_core_field_exists(task->__state)) {
        return BPF_CORE_READ(task, __state);
    }
    return BPF_CORE_READ(task, state);
}

static __always_inline __u32 get_pid_ns_inum(struct task_struct *task) {
    return BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
}

// ============================================================================
// Programas BPF
// ============================================================================

SEC("kprobe/do_execveat_common")
int trace_exec(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    __u32 pid = BPF_CORE_READ(task, tgid);
    __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    __u32 uid = BPF_CORE_READ(task, real_cred, uid);
    __u32 pid_ns = get_pid_ns_inum(task);

    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&exec_times, &pid, &now, BPF_ANY);

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

SEC("kprobe/do_exit")
int trace_exit(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    __u32 pid = BPF_CORE_READ(task, tgid);

    __u64 *start = bpf_map_lookup_elem(&exec_times, &pid);
    __u64 lifetime_ns = 0;
    if (start) {
        __u64 now = bpf_ktime_get_ns();
        lifetime_ns = now - *start;
        bpf_map_delete_elem(&exec_times, &pid);
    }

    long exit_code;
    bpf_probe_read_kernel(&exit_code, sizeof(exit_code), &ctx->di);

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
