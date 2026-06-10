//go:build ignore

// hello.bpf.c — Hello World eBPF (Capítulo 4)
//
// Tu primer programa eBPF que hace algo visible.
// Se adjunta al tracepoint sys_enter_execve y cada vez que un proceso
// ejecuta un programa nuevo, imprime el PID y el nombre del proceso.
//
// Esto es el "Hello World" de eBPF: observar eventos del kernel
// sin modificar su comportamiento.
//
// Attach point: tracepoint/syscalls/sys_enter_execve
// Output: /sys/kernel/debug/tracing/trace_pipe

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// SEC() define la sección ELF que indica al loader dónde adjuntar este programa.
// "tracepoint/syscalls/sys_enter_execve" se dispara cada vez que se ejecuta execve().
SEC("tracepoint/syscalls/sys_enter_execve")
int hello_execve(void *ctx) {
    // Obtener el PID del proceso que hizo execve.
    // bpf_get_current_pid_tgid() retorna un u64 donde:
    //   - Los 32 bits altos son el TGID (thread group ID = PID del proceso)
    //   - Los 32 bits bajos son el TID (thread ID)
    // Hacemos >> 32 para quedarnos con el PID real.
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Obtener el nombre del proceso (comm).
    // bpf_get_current_comm() llena un buffer con el nombre del ejecutable
    // (máximo 16 caracteres, como lo muestra /proc/self/comm).
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // Imprimir al trace_pipe.
    // bpf_printk() es un wrapper de bpf_trace_printk() que escribe
    // en /sys/kernel/debug/tracing/trace_pipe.
    // ⚠️  Solo para debug — NO usar en producción (tiene overhead).
    bpf_printk("execve: PID=%d COMM=%s", pid, comm);

    return 0;
}

// Todos los programas BPF necesitan declarar su licencia.
// Sin esto, el verifier rechaza el programa y no tendrás acceso
// a muchas helper functions que requieren GPL.
char LICENSE[] SEC("license") = "GPL";
