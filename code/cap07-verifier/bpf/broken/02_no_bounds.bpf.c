//go:build ignore

// 02_no_bounds.bpf.c — Programa ROTO: Falla el verifier
//
// ERROR: Acceso a datos del paquete sin bounds check
//
// En programas XDP, tienes acceso al paquete raw via data y data_end.
// El verifier EXIGE que verifiques que tu puntero no se sale del
// paquete antes de leer. Si no haces el bounds check → rechazado.
//
// Error del verifier:
//   "invalid access to packet, off=14 size=20, R2(id=0,off=0,r=0)"
//   "R2 offset is outside of the packet"
//
// Attach point: xdp

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    // data y data_end definen los límites del paquete
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parseamos el header Ethernet
    struct ethhdr *eth = data;

    // ❌ ERROR: Estamos accediendo a eth->h_proto sin verificar
    // que el header Ethernet cabe dentro del paquete.
    // Si el paquete es más pequeño que sizeof(struct ethhdr),
    // estaríamos leyendo fuera de bounds.
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return XDP_PASS;

    // ❌ ERROR: Acceso al header IP sin bounds check.
    // Incluso si el header Ethernet existe, no verificamos
    // que el header IP también cabe en el paquete.
    struct iphdr *ip = (void *)(eth + 1);

    // El verifier no sabe si ip apunta a memoria válida dentro
    // del paquete. Necesitamos demostrar que (ip + 1) <= data_end.
    if (ip->protocol == 6)  // TCP
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
