// Capítulo 9 — Solución: Mini-opensnoop (Programa BPF)
//
// Tracer de operaciones open() usando kprobe + kretprobe en do_sys_openat2.
// Captura: nombre del archivo, latencia de la operación, y resultado (fd o error).
//
// Compilar:
//   make opensnoop.bpf.o

//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_FILENAME_LEN 128

// Evento completo que se envía a user space
struct open_event {
    __u32 pid;
    __u32 uid;
    __u64 delta_ns;
    int   ret;       // fd si éxito, errno negativo si error
    char  comm[16];
    char  filename[MAX_FILENAME_LEN];
};

// Datos temporales guardados en el kprobe de entrada
struct start_data {
    __u64 ts;
    char  filename[MAX_FILENAME_LEN];
};

// Map para correlacionar entry con exit (TID -> datos de entrada)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);               // TID
    __type(value, struct start_data);  // timestamp + filename
} inflight SEC(".maps");

// Ring buffer para enviar eventos a user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/do_sys_openat2")
int trace_open_entry(struct pt_regs *ctx) {
    // Obtener el TID (thread ID) para correlacionar con el kretprobe
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // Guardar timestamp y leer el nombre del archivo
    struct start_data data = {};
    data.ts = bpf_ktime_get_ns();

    // do_sys_openat2(int dfd, const char __user *filename, struct open_how *how)
    // El segundo argumento es el filename en user space
    const char *fname = (const char *)PT_REGS_PARM2(ctx);
    bpf_probe_read_user_str(data.filename, sizeof(data.filename), fname);

    // Guardar en el map para recuperar en el kretprobe
    bpf_map_update_elem(&inflight, &tid, &data, BPF_ANY);

    return 0;
}

SEC("kretprobe/do_sys_openat2")
int trace_open_exit(struct pt_regs *ctx) {
    // Obtener el TID
    __u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // Buscar los datos de entrada
    struct start_data *data = bpf_map_lookup_elem(&inflight, &tid);
    if (!data)
        return 0;

    // Calcular latencia
    __u64 delta = bpf_ktime_get_ns() - data->ts;

    // Borrar entrada del map (cleanup — evita que crezca indefinidamente)
    bpf_map_delete_elem(&inflight, &tid);

    // Reservar espacio en ring buffer
    struct open_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    // Llenar el evento
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->delta_ns = delta;
    e->ret = (int)PT_REGS_RC(ctx);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->filename, data->filename, MAX_FILENAME_LEN);

    // Enviar evento a user space
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
