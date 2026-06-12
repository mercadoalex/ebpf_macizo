// Capítulo 9 — Ejercicio: Mini-opensnoop (copia para bpf2go)
//
// NOTA: Este es el mismo archivo que bpf/opensnoop.bpf.c
// Debes completar los TODOs aquí también (o copiar tu solución BPF aquí).

//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_FILENAME_LEN 128

struct open_event {
    __u32 pid;
    __u32 uid;
    __u64 delta_ns;
    int   ret;
    char  comm[16];
    char  filename[MAX_FILENAME_LEN];
};

struct start_data {
    __u64 ts;
    char  filename[MAX_FILENAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct start_data);
} inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/do_sys_openat2")
int trace_open_entry(struct pt_regs *ctx) {
    // TODO: Implementar (ver esqueleto/bpf/opensnoop.bpf.c para pistas)
    return 0;
}

SEC("kretprobe/do_sys_openat2")
int trace_open_exit(struct pt_regs *ctx) {
    // TODO: Implementar (ver esqueleto/bpf/opensnoop.bpf.c para pistas)
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
