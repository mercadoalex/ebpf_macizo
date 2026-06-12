//go:build ignore

// hardcoded_offsets.bpf.c — Ejemplo de lo que NO hay que hacer (Capítulo 15)
//
// Este programa demuestra el PROBLEMA de portabilidad: usa offsets
// hardcodeados para acceder a campos de task_struct. Funciona SOLO
// en un kernel específico (5.15 en este caso).
//
// ¡NUNCA hagas esto en producción! Los offsets cambian entre:
//   - Versiones de kernel (5.10 vs 5.15 vs 6.1)
//   - Configuraciones diferentes (CONFIG_*)
//   - Distros (Ubuntu vs RHEL vs Amazon Linux)
//
// Este archivo existe para demostrar por qué CO-RE es necesario.
//
// Attach point: kprobe/do_exit
// Método: bpf_probe_read_kernel con offsets mágicos

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// ¡PELIGRO! Offsets hardcodeados para un kernel 5.15 específico.
// Estos números son BASURA en cualquier otro kernel.
#define TASK_COMM_OFFSET       2560
#define TASK_TGID_OFFSET       2292
#define TASK_REAL_PARENT_OFFSET 2296

struct task_struct;

SEC("kprobe/do_exit")
int trace_exit_hardcoded(struct pt_regs *ctx) {
    struct task_struct *task = (void *)bpf_get_current_task();

    // Leer PID con offset hardcodeado.
    // Funciona en kernel 5.15.x de Ubuntu — explota en todo lo demás.
    __u32 pid;
    bpf_probe_read_kernel(&pid, sizeof(pid),
                          (void *)task + TASK_TGID_OFFSET);

    // Leer puntero a task padre con offset hardcodeado.
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent),
                          (void *)task + TASK_REAL_PARENT_OFFSET);

    // Leer PPID del padre (mismo offset mágico, misma fragilidad).
    __u32 ppid;
    bpf_probe_read_kernel(&ppid, sizeof(ppid),
                          (void *)parent + TASK_TGID_OFFSET);

    // Leer nombre del proceso con offset hardcodeado.
    char comm[16];
    bpf_probe_read_kernel(&comm, sizeof(comm),
                          (void *)task + TASK_COMM_OFFSET);

    bpf_printk("exit [HARDCODED]: pid=%d ppid=%d comm=%s", pid, ppid, comm);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
