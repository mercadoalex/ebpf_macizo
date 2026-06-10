//go:build ignore

// ringbuf_events.bpf.c — Ring Buffer: Streaming de eventos (Capítulo 6)
//
// Demuestra el uso de BPF_MAP_TYPE_RINGBUF para enviar eventos
// estructurados del kernel al user space en tiempo real.
//
// A diferencia de hash/array maps (donde user space hace polling),
// el ring buffer es push-based: el programa BPF escribe eventos
// y user space los recibe conforme llegan — ideal para streaming.
//
// Cada vez que se ejecuta un nuevo proceso (execve), enviamos un
// evento con: PID, nombre del proceso, y timestamp.
//
// Attach point: tracepoint/syscalls/sys_enter_execve
// Map: events (ringbuf, max_entries=256*1024 = 256KB)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Estructura del evento que enviamos a user space.
// Debe ser idéntica a la definida en el código Go.
struct event {
    __u32 pid;
    __u64 timestamp_ns;
    char comm[16];
};

// Ring buffer — 256KB de espacio circular.
// Cuando se llena, los eventos más nuevos se descartan (no sobreescriben).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int exec_event(void *ctx) {
    // Reservar espacio en el ring buffer para un evento.
    // bpf_ringbuf_reserve() retorna un puntero al espacio reservado,
    // o NULL si el buffer está lleno.
    struct event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!evt) {
        // Buffer lleno — descartamos este evento.
        // En producción querrías un contador de drops.
        return 0;
    }

    // Llenar el evento con datos del contexto actual.
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    // Enviar el evento — user space lo recibirá inmediatamente.
    // bpf_ringbuf_submit() libera la reserva y notifica a los consumers.
    bpf_ringbuf_submit(evt, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
