// Capítulo 9 — Kprobe openat (copia para go generate / bpf2go)
//
// Este archivo es una copia del programa BPF para que bpf2go lo compile
// directamente junto con el loader en Go.

//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("kprobe/do_sys_openat2")
int trace_openat(struct pt_regs *ctx) {
    // do_sys_openat2(int dfd, const char __user *filename, struct open_how *how)
    const char *filename = (const char *)PT_REGS_PARM2(ctx);

    char buf[64];
    bpf_probe_read_user_str(buf, sizeof(buf), filename);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("pid=%d open: %s", pid, buf);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
