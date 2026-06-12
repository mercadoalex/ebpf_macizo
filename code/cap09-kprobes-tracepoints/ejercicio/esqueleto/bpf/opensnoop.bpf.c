// Capítulo 9 — Ejercicio: Mini-opensnoop (Esqueleto BPF)
//
// INSTRUCCIONES:
// Completa los TODOs para implementar un tracer de operaciones open().
// El programa combina kprobe (entrada) + kretprobe (salida) para capturar:
//   - Nombre del archivo que se intenta abrir
//   - Cuánto tardó la operación
//   - Si tuvo éxito (fd positivo) o falló (errno negativo)
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
    // TODO 1: Obtener el TID (thread ID)
    // Pista: bpf_get_current_pid_tgid() & 0xFFFFFFFF
    // __u32 tid = ???;

    // TODO 2: Crear un struct start_data en el stack y llenarlo
    // Pista:
    //   struct start_data data = {};
    //   data.ts = bpf_ktime_get_ns();
    //   const char *fname = (const char *)PT_REGS_PARM2(ctx);
    //   bpf_probe_read_user_str(data.filename, sizeof(data.filename), fname);

    // TODO 3: Guardar start_data en el map 'inflight' con TID como clave
    // Pista: bpf_map_update_elem(&inflight, &tid, &data, BPF_ANY);

    return 0;
}

SEC("kretprobe/do_sys_openat2")
int trace_open_exit(struct pt_regs *ctx) {
    // TODO 4: Obtener el TID
    // __u32 tid = ???;

    // TODO 5: Buscar los datos de entrada en 'inflight'
    // Pista:
    //   struct start_data *data = bpf_map_lookup_elem(&inflight, &tid);
    //   if (!data)
    //       return 0;

    // TODO 6: Calcular delta de tiempo
    // Pista: __u64 delta = bpf_ktime_get_ns() - data->ts;

    // TODO 7: Borrar la entrada del map (cleanup)
    // Pista: bpf_map_delete_elem(&inflight, &tid);

    // TODO 8: Reservar espacio en el ring buffer para un struct open_event
    // Pista:
    //   struct open_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    //   if (!e)
    //       return 0;

    // TODO 9: Llenar el evento con todos los campos
    // Pista:
    //   e->pid = bpf_get_current_pid_tgid() >> 32;
    //   e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    //   e->delta_ns = delta;
    //   e->ret = (int)PT_REGS_RC(ctx);
    //   bpf_get_current_comm(&e->comm, sizeof(e->comm));
    //   __builtin_memcpy(e->filename, data->filename, MAX_FILENAME_LEN);

    // TODO 10: Enviar el evento
    // Pista: bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
