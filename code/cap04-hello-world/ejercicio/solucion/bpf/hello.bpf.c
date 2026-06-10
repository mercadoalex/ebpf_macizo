//go:build ignore

// hello.bpf.c — Solución: Execve Tracer (Capítulo 4)
//
// Programa eBPF completo que imprime PID y nombre del proceso
// cada vez que se ejecuta execve().
//
// Attach point: tracepoint/syscalls/sys_enter_execve
// Output: /sys/kernel/debug/tracing/trace_pipe

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int hello_execve(void *ctx) {
    // Obtener el PID: bits altos del valor retornado por bpf_get_current_pid_tgid()
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Obtener el nombre del proceso
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // Imprimir al trace_pipe
    bpf_printk("execve: PID=%d COMM=%s", pid, comm);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
