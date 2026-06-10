//go:build ignore

// hello.bpf.c — Ejercicio: Execve Tracer (Capítulo 4)
//
// INSTRUCCIONES:
// Completa los 3 TODOs para que este programa imprima el PID y nombre
// de cada proceso que ejecuta execve().
//
// Attach point: tracepoint/syscalls/sys_enter_execve
// Output esperado: "execve: PID=<pid> COMM=<nombre>"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int hello_execve(void *ctx) {
    // TODO 1: Obtener el PID del proceso actual.
    //
    // Usa bpf_get_current_pid_tgid() que retorna un __u64.
    // Los 32 bits altos contienen el PID (TGID).
    // Haz shift right >> 32 para extraer el PID en un __u32.
    //
    // __u32 pid = ???;

    // TODO 2: Obtener el nombre del proceso (comm).
    //
    // Declara un buffer: char comm[16];
    // Llama a bpf_get_current_comm(&comm, sizeof(comm));
    // Esta función llena el buffer con el nombre del ejecutable.
    //

    // TODO 3: Imprimir al trace_pipe.
    //
    // Usa bpf_printk() con el formato: "execve: PID=%d COMM=%s"
    // Pasa pid y comm como argumentos.
    //

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
