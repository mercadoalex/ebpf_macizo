//go:build ignore

// xdp_pass.bpf.c — Capítulo 10: El programa XDP más simple
//
// Este programa simplemente deja pasar todos los paquetes.
// Demuestra la estructura mínima de un programa XDP:
// - Sección "xdp"
// - Contexto struct xdp_md *ctx
// - Retorno de una acción (XDP_PASS)
//
// Attach point: XDP hook en interfaz de red

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
