//go:build ignore

// xdp_pass.bpf.c — Programa XDP mínimo (usado por bpf2go)
//
// Este archivo es una copia del programa BPF para que bpf2go pueda
// compilarlo junto al loader en Go.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
