//go:build ignore

// latency.bpf.c — Ejercicio: Medición de latencia de syscalls (Capítulo 8)
//
// Objetivo: medir cuánto tarda do_sys_openat2 en completarse usando
// kprobe (entrada) y kretprobe (salida) con bpf_ktime_get_ns().
//
// Estrategia:
//   1. kprobe en do_sys_openat2: guardar timestamp de entrada en hash map (key = TID)
//   2. kretprobe en do_sys_openat2: recuperar timestamp, calcular delta, enviar a ring buffer
//
// El resultado es la latencia en nanosegundos de cada llamada a openat2.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Evento de latencia que se envía al user space.
struct latency_event {
    __u32 pid;
    __u32 tid;
    __u64 delta_ns;     // Latencia en nanosegundos
    char  comm[16];
};

// TODO 1: Definir un hash map llamado "start_time" para almacenar timestamps.
//
// El map debe:
//   - Ser de tipo BPF_MAP_TYPE_HASH
//   - Usar __u32 como key (el TID del thread)
//   - Usar __u64 como value (el timestamp en nanosegundos)
//   - Tener max_entries = 10240 (suficiente para threads concurrentes)
//
// Sintaxis de definición de map BTF:
//   struct {
//       __uint(type, BPF_MAP_TYPE_HASH);
//       __uint(max_entries, ...);
//       __type(key, ...);
//       __type(value, ...);
//   } nombre_del_map SEC(".maps");


// TODO 2: Definir un ring buffer llamado "events" para enviar resultados.
//
// El ring buffer debe tener max_entries = 256 * 1024 (256 KB).
//
// Sintaxis:
//   struct {
//       __uint(type, BPF_MAP_TYPE_RINGBUF);
//       __uint(max_entries, ...);
//   } nombre SEC(".maps");


// kprobe en do_sys_openat2 — se ejecuta al ENTRAR a la función.
// Aquí guardamos el timestamp de entrada.
SEC("kprobe/do_sys_openat2")
int kprobe_openat2(void *ctx) {
    // TODO 3: Obtener el TID del thread actual.
    //
    // Usa bpf_get_current_pid_tgid() y quédate con los 32 bits bajos.
    // Recuerda: bits 63-32 = TGID (PID), bits 31-0 = TID.


    // TODO 4: Obtener el timestamp actual con bpf_ktime_get_ns().


    // TODO 5: Guardar el timestamp en el hash map "start_time" con key = TID.
    //
    // Usa bpf_map_update_elem(&map, &key, &value, BPF_ANY).
    // BPF_ANY significa: crear si no existe, actualizar si existe.


    return 0;
}

// kretprobe en do_sys_openat2 — se ejecuta al SALIR de la función.
// Aquí calculamos la latencia y la enviamos al user space.
SEC("kretprobe/do_sys_openat2")
int kretprobe_openat2(void *ctx) {
    // TODO 6: Obtener el TID actual (igual que en el kprobe).


    // TODO 7: Buscar el timestamp de entrada en el hash map.
    //
    // Usa bpf_map_lookup_elem(&start_time, &tid).
    // Si retorna NULL, significa que no vimos la entrada — descartamos.


    // TODO 8: Calcular el delta (latencia) = timestamp_actual - timestamp_entrada.
    //
    // Obtén el timestamp actual con bpf_ktime_get_ns() y réstale
    // el valor almacenado en el map.


    // TODO 9: Reservar espacio en el ring buffer, llenar el struct latency_event,
    // y enviarlo con bpf_ringbuf_submit().
    //
    // Pasos:
    //   a) bpf_ringbuf_reserve(&events, sizeof(struct latency_event), 0)
    //   b) Si retorna NULL, salir
    //   c) Llenar: pid (>> 32 del pid_tgid), tid, delta_ns, comm
    //   d) bpf_ringbuf_submit(e, 0)


    // TODO 10: Limpiar la entrada del hash map para no acumular basura.
    //
    // Usa bpf_map_delete_elem(&start_time, &tid).


    return 0;
}

char LICENSE[] SEC("license") = "GPL";
