//go:build ignore

// process_monitor.bpf.c — Capítulo 13: Process Lifecycle Monitor (Referencia)
//
// Copia para go generate / bpf2go.
// El original está en ../bpf/process_monitor.bpf.c

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define EVENT_FORK 1
#define EVENT_EXIT 2

struct process_info {
    __u64 start_time;
    char comm[TASK_COMM_LEN];
};

struct event {
    __u8 type;
    __u8 _pad[3];
    __u32 pid;
    __u32 ppid;
    __u32 _pad2;
    __u64 timestamp;
    __u64 duration_ns;
    char comm[TASK_COMM_LEN];
};

// ─── Maps ────────────────────────────────────────────────────────────────────

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct process_info);
} process_info_map SEC(".maps");

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

    struct process_info info = {};
    info.start_time = ts;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    bpf_map_update_elem(&process_info_map, &child_pid, &info, BPF_ANY);

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

    __u64 duration = 0;
    struct process_info *info = bpf_map_lookup_elem(&process_info_map, &pid);
    if (info) {
        duration = ts - info->start_time;
        bpf_map_delete_elem(&process_info_map, &pid);
    }

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
