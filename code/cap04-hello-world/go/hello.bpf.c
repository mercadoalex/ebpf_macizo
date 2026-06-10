//go:build ignore

// hello.bpf.c — Hello World eBPF (Capítulo 4)
//
// Este archivo es una copia del programa BPF en bpf/ para uso con bpf2go.
// La directiva //go:generate en main.go referencia este archivo directamente.
//
// Attach point: tracepoint/syscalls/sys_enter_execve
// Output: /sys/kernel/debug/tracing/trace_pipe

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int hello_execve(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    bpf_printk("execve: PID=%d COMM=%s", pid, comm);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
