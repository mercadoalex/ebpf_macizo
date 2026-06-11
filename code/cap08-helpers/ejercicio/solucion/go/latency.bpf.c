//go:build ignore

// latency.bpf.c — Solución: Medición de latencia de syscalls (Capítulo 8)
//
// Este archivo es una copia del programa BPF en bpf/ para uso con bpf2go.
// La directiva //go:generate en main.go referencia este archivo directamente.
//
// Mide cuánto tarda do_sys_openat2 en completarse usando kprobe/kretprobe
// y bpf_ktime_get_ns(). Los resultados se envían al user space via ring buffer.
//
// Estrategia:
//   1. kprobe en do_sys_openat2: guardar timestamp de entrada en hash map (key = TID)
//   2. kretprobe en do_sys_openat2: recuperar timestamp, calcular delta, enviar a ring buffer

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Evento de latencia que se envía al user space.
struct latency_event {
    __u32 pid;
    __u32 tid;
    __u64 delta_ns;     // Latencia en nanosegundos
    char  comm[16];
};

// Hash map para almacenar timestamps de entrada.
// Key = TID del thread, Value = timestamp en nanosegundos.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} start_time SEC(".maps");

// Ring buffer para enviar eventos de latencia al user space.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// kprobe en do_sys_openat2 — se ejecuta al ENTRAR a la función.
// Guarda el timestamp de entrada indexado por TID.
SEC("kprobe/do_sys_openat2")
int kprobe_openat2(void *ctx) {
    // Obtener el TID (bits bajos de pid_tgid).
    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    // Capturar timestamp de entrada.
    __u64 ts = bpf_ktime_get_ns();

    // Guardar en el hash map. BPF_ANY = crear o actualizar.
    bpf_map_update_elem(&start_time, &tid, &ts, BPF_ANY);

    return 0;
}

// kretprobe en do_sys_openat2 — se ejecuta al SALIR de la función.
// Calcula la latencia y la envía al user space.
SEC("kretprobe/do_sys_openat2")
int kretprobe_openat2(void *ctx) {
    // Obtener TID y PID.
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    __u32 pid = pid_tgid >> 32;

    // Buscar el timestamp de entrada.
    __u64 *start_ts = bpf_map_lookup_elem(&start_time, &tid);
    if (!start_ts) {
        // No vimos la entrada — descartamos.
        return 0;
    }

    // Calcular latencia = ahora - timestamp de entrada.
    __u64 delta_ns = bpf_ktime_get_ns() - *start_ts;

    // Reservar espacio en el ring buffer.
    struct latency_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        // Buffer lleno — descartamos el evento.
        goto cleanup;
    }

    // Llenar el evento.
    e->pid = pid;
    e->tid = tid;
    e->delta_ns = delta_ns;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Enviar al user space.
    bpf_ringbuf_submit(e, 0);

cleanup:
    // Limpiar la entrada del hash map.
    bpf_map_delete_elem(&start_time, &tid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
