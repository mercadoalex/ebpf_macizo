//go:build ignore

// ringbuf_events.bpf.c — Capítulo 12: Ring Buffer (forma moderna y eficiente)
//
// Demuestra el uso de BPF_MAP_TYPE_RINGBUF para enviar eventos
// estructurados del kernel a user space. El ring buffer es la forma
// moderna (kernel 5.8+) de comunicación kernel → user space:
//
// Ventajas sobre perf events:
//   - Un solo buffer compartido entre todas las CPUs
//   - Orden global de eventos garantizado
//   - Mejor uso de memoria (no se desperdicia espacio per-CPU)
//   - API más limpia: reserve → fill → submit
//   - Notificación eficiente (epoll-based)
//
// Cada vez que se abre un archivo (sys_enter_openat), enviamos un
// evento con PID, nombre del proceso, y flags del open.
//
// Attach point: tracepoint/syscalls/sys_enter_openat
// Map: events (ringbuf, 256KB)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Estructura del evento que enviamos a user space.
// El layout debe coincidir exactamente con la estructura en Go.
struct file_event {
    __u32 pid;
    __u32 flags;       // flags de openat (O_RDONLY, O_WRONLY, etc.)
    __u64 timestamp_ns;
    char comm[16];
    char filename[64]; // path del archivo (truncado a 64 bytes)
};

// Ring buffer — 256KB de espacio circular compartido entre todas las CPUs.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Argumentos del tracepoint sys_enter_openat.
struct sys_enter_openat_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int __syscall_nr;
    int dfd;
    const char *filename;
    int flags;
    unsigned short mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct sys_enter_openat_args *ctx) {
    // Filtrar procesos del kernel (PID 0).
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (pid == 0) {
        return 0;
    }

    // Reservar espacio en el ring buffer.
    // Si el buffer está lleno, retorna NULL y descartamos el evento.
    struct file_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(struct file_event), 0);
    if (!evt) {
        return 0;
    }

    // Llenar el evento.
    evt->pid = pid;
    evt->flags = ctx->flags;
    evt->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    // Leer el filename desde user space.
    // bpf_probe_read_user_str lee un string terminado en NULL.
    bpf_probe_read_user_str(&evt->filename, sizeof(evt->filename),
                            ctx->filename);

    // Submit — envía el evento y notifica a los consumers.
    bpf_ringbuf_submit(evt, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
