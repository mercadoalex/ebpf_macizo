//go:build ignore

// core_exit_tracer.bpf.c — Process exit tracer con CO-RE (Capítulo 15)
//
// Copia para go generate. El original está en ../bpf/.
// bpf2go necesita el .bpf.c en el mismo directorio que main.go.
//
// Demuestra BPF_CORE_READ para acceso portable a task_struct.
// Reporta PID, PPID y nombre del proceso que termina via ring buffer.
//
// Attach point: kprobe/do_exit
// Output: ring buffer con struct exit_event

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Evento que enviamos a user space.
struct exit_event {
    __u32 pid;
    __u32 ppid;
    char comm[16];
};

// Ring buffer para comunicación kernel → user space.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/do_exit")
int trace_exit_core(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // CO-RE: offsets resueltos en tiempo de carga por cilium/ebpf.
    // El loader lee el BTF del kernel target y parchea las instrucciones.
    __u32 pid = BPF_CORE_READ(task, tgid);
    __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

    struct exit_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->pid = pid;
    evt->ppid = ppid;
    BPF_CORE_READ_STR_INTO(&evt->comm, task, comm);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
