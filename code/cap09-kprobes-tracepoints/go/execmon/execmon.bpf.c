// Capítulo 9 — Tracepoint: Monitor de procesos nuevos
// (copia para go generate / bpf2go)

//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Declaraciones forward para leer task_struct
struct task_struct {
    int                   pid;
    int                   tgid;
    struct task_struct    *real_parent;
} __attribute__((preserve_access_index));

struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct sched_process_exec_args {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    int            __data_loc_filename;
    int            pid;
    int            old_pid;
};

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct sched_process_exec_args *ctx) {
    struct exec_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Obtener PPID desde task_struct
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid),
                          &task->real_parent->tgid);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
