// Capítulo 9 — Solución: Mini-opensnoop (copia para bpf2go)

//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_FILENAME_LEN 128

struct open_event {
    __u32 pid;
    __u32 uid;
    __u64 delta_ns;
    int   ret;
    char  comm[16];
    char  filename[MAX_FILENAME_LEN];
};

struct start_data {
    __u64 ts;
    char  filename[MAX_FILENAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct start_data);
} inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/do_sys_openat2")
int trace_open_entry(struct pt_regs *ctx) {
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    struct start_data data = {};
    data.ts = bpf_ktime_get_ns();

    const char *fname = (const char *)PT_REGS_PARM2(ctx);
    bpf_probe_read_user_str(data.filename, sizeof(data.filename), fname);

    bpf_map_update_elem(&inflight, &tid, &data, BPF_ANY);
    return 0;
}

SEC("kretprobe/do_sys_openat2")
int trace_open_exit(struct pt_regs *ctx) {
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    struct start_data *data = bpf_map_lookup_elem(&inflight, &tid);
    if (!data)
        return 0;

    __u64 delta = bpf_ktime_get_ns() - data->ts;
    bpf_map_delete_elem(&inflight, &tid);

    struct open_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->delta_ns = delta;
    e->ret = (int)PT_REGS_RC(ctx);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->filename, data->filename, MAX_FILENAME_LEN);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
