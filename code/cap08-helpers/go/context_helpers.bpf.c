//go:build ignore

// context_helpers.bpf.c — Demo de helper functions de contexto (Capítulo 8)
//
// Este archivo es una copia del programa BPF en bpf/ para uso con bpf2go.
// La directiva //go:generate en main.go referencia este archivo directamente.
//
// Demuestra las helper functions más usadas para obtener información del
// contexto de ejecución:
//
//   - bpf_get_current_pid_tgid()  → PID y TID del proceso actual
//   - bpf_get_current_comm()      → Nombre del ejecutable (max 16 chars)
//   - bpf_ktime_get_ns()          → Timestamp monotónico en nanosegundos
//   - bpf_get_current_uid_gid()   → UID y GID del proceso actual
//
// Los datos se envían al user space via ring buffer como un struct event.
//
// Attach point: tracepoint/syscalls/sys_enter_openat
// Output: ring buffer → consumer en Go

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Estructura del evento que enviamos al user space.
// El ring buffer transporta estos structs completos.
struct event {
    __u32 pid;          // Process ID (TGID)
    __u32 tid;          // Thread ID
    __u32 uid;          // User ID
    __u32 gid;          // Group ID
    __u64 timestamp_ns; // Timestamp en nanosegundos (monotónico)
    char  comm[16];     // Nombre del ejecutable
};

// Ring buffer para enviar eventos al user space.
// max_entries = tamaño en bytes del buffer (256 KB).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Se dispara cada vez que un proceso llama a openat().
// Capturamos información del contexto usando helper functions
// y la enviamos al user space via ring buffer.
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(void *ctx) {
    struct event *e;

    // Reservar espacio en el ring buffer para un evento.
    // Si el buffer está lleno, retorna NULL y descartamos el evento.
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // === HELPER 1: bpf_get_current_pid_tgid() ===
    // Retorna un __u64 donde:
    //   - Bits 63-32: TGID (Thread Group ID = PID del proceso)
    //   - Bits 31-0:  TID  (Thread ID = PID del thread/LWP)
    //
    // En un proceso single-threaded, PID == TID.
    // En un proceso multi-threaded, todos los threads comparten el TGID
    // pero cada uno tiene su propio TID.
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;        // TGID = PID del proceso
    e->tid = (__u32)pid_tgid;       // TID = ID del thread

    // === HELPER 2: bpf_get_current_comm() ===
    // Llena un buffer con el nombre del ejecutable actual.
    // Máximo 16 caracteres (TASK_COMM_LEN del kernel).
    // Si el nombre es más largo, se trunca silenciosamente.
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // === HELPER 3: bpf_ktime_get_ns() ===
    // Retorna el tiempo monotónico del sistema en nanosegundos.
    // "Monotónico" = nunca retrocede, no afectado por NTP o ajustes de reloj.
    // Perfecto para medir latencias y duraciones.
    // El valor es relativo al boot del sistema (no es epoch Unix).
    e->timestamp_ns = bpf_ktime_get_ns();

    // === HELPER 4: bpf_get_current_uid_gid() ===
    // Retorna un __u64 donde:
    //   - Bits 63-32: GID (Group ID)
    //   - Bits 31-0:  UID (User ID)
    //
    // Estos son los IDs *efectivos* (no los reales).
    // Útil para filtrar eventos por usuario o detectar escalación de privilegios.
    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = (__u32)uid_gid;        // UID efectivo
    e->gid = uid_gid >> 32;         // GID efectivo

    // Enviar el evento al user space.
    // bpf_ringbuf_submit() libera la reserva y notifica al consumer.
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
