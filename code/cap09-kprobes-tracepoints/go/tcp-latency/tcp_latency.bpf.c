// Capítulo 9 — Kprobe + Kretprobe: Medición de latencia de tcp_connect
// (copia para go generate / bpf2go)

//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
    __u32 pid;
    __u64 delta_ns;
    long  ret;
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/tcp_connect")
int trace_tcp_connect_entry(struct pt_regs *ctx) {
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_connect")
int trace_tcp_connect_exit(struct pt_regs *ctx) {
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    __u64 *start_ts = bpf_map_lookup_elem(&start, &tid);
    if (!start_ts)
        return 0;

    __u64 delta = bpf_ktime_get_ns() - *start_ts;
    bpf_map_delete_elem(&start, &tid);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->delta_ns = delta;
    e->ret = PT_REGS_RC(ctx);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
