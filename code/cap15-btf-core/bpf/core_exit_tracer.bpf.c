//go:build ignore

// core_exit_tracer.bpf.c — Process exit tracer con CO-RE (Capítulo 15)
//
// Demuestra el uso de BPF_CORE_READ para acceder a campos de task_struct
// de forma portable entre versiones de kernel. No importa si los offsets
// de tgid, real_parent, o comm cambian — CO-RE los resuelve en carga.
//
// Reporta a user space via ring buffer:
//   - PID del proceso que termina
//   - PPID (PID del padre)
//   - Nombre del proceso (comm)
//
// Contraste con hardcoded_offsets.bpf.c: mismo resultado, pero este
// funciona en CUALQUIER kernel con BTF habilitado.
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
    __uint(max_entries, 256 * 1024);  // 256 KB
} events SEC(".maps");

SEC("kprobe/do_exit")
int trace_exit_core(struct pt_regs *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // BPF_CORE_READ: acceso portable a campos.
    // El compilador emite relocations que el loader resuelve contra el
    // BTF del kernel target. No importa si el offset de 'tgid' es 2292
    // en un kernel y 2304 en otro — CO-RE lo maneja.
    __u32 pid = BPF_CORE_READ(task, tgid);

    // Cadena de dereferences: task->real_parent->tgid
    // CO-RE genera DOS relocations aquí:
    //   1. Offset de real_parent en task_struct
    //   2. Offset de tgid en la task_struct apuntada por real_parent
    __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

    // Reservar espacio en el ring buffer.
    struct exit_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->pid = pid;
    evt->ppid = ppid;

    // BPF_CORE_READ_STR_INTO: lee un string con relocation CO-RE.
    BPF_CORE_READ_STR_INTO(&evt->comm, task, comm);

    // Enviar el evento a user space.
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
