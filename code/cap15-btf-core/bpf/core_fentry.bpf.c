//go:build ignore

// core_fentry.bpf.c — Fentry + CO-RE: el código más limpio posible (Capítulo 15)
//
// Combina dos features avanzadas del kernel:
//   - fentry: acceso directo a argumentos de funciones del kernel (sin pt_regs)
//   - CO-RE: offsets portables entre versiones de kernel
//
// Resultado: código que parece casi "normal" (no parece BPF) y funciona
// en cualquier kernel >= 5.5 con BTF.
//
// Attach point: fentry/do_exit
// Requisitos: kernel >= 5.5 con CONFIG_DEBUG_INFO_BTF
// Fallback: si el kernel no soporta fentry, usar core_exit_tracer.bpf.c (kprobe)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// El mismo evento que core_exit_tracer, para que el loader Go sea compatible.
struct exit_event {
    __u32 pid;
    __u32 ppid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// BPF_PROG macro: recibe los argumentos de la función del kernel directamente.
// do_exit(long code) → recibimos 'code' como argumento, sin parsear pt_regs.
SEC("fentry/do_exit")
int BPF_PROG(trace_exit_fentry, long code) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // CO-RE: acceso portable a campos de task_struct.
    // Fentry nos da los argumentos de la función.
    // Juntos son la combinación definitiva.
    __u32 pid = BPF_CORE_READ(task, tgid);
    __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

    struct exit_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->pid = pid;
    evt->ppid = ppid;
    BPF_CORE_READ_STR_INTO(&evt->comm, task, comm);

    bpf_ringbuf_submit(evt, 0);

    // También podemos usar el argumento de la función directamente.
    // 'code' es el exit code que el proceso pasó a exit().
    bpf_printk("fentry/do_exit: pid=%d code=%ld", pid, code);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
