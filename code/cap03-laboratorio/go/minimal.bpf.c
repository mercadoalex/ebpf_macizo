//go:build ignore

// minimal.bpf.c — Programa BPF mínimo del Capítulo 3
//
// Este archivo es una copia del programa BPF en bpf/ para uso con bpf2go.
// La directiva //go:generate en main.go referencia este archivo directamente.
//
// Attach point: tracepoint/syscalls/sys_enter_execve

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int minimal_prog(void *ctx) {
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
