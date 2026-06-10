//go:build ignore

// 02_no_bounds.bpf.c — Versión CORREGIDA
//
// FIX: Verificar bounds del paquete antes de acceder a headers.
//
// Patrón correcto para XDP:
//   struct hdr *h = data + offset;
//   if ((void *)(h + 1) > data_end)   ← Bounds check OBLIGATORIO
//       return XDP_PASS;
//   // Ahora es seguro acceder a h->campo
//
// Attach point: xdp

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parseamos el header Ethernet
    struct ethhdr *eth = data;

    // ✅ FIX: Verificar que el header Ethernet cabe en el paquete.
    // Si el paquete es demasiado pequeño para contener un header
    // Ethernet completo, dejamos pasar sin tocar nada.
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Ahora es seguro acceder a eth->h_proto
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return XDP_PASS;

    // Parseamos el header IP (empieza justo después del Ethernet)
    struct iphdr *ip = (void *)(eth + 1);

    // ✅ FIX: Verificar que el header IP también cabe en el paquete.
    // Mismo patrón: (puntero_al_final_del_header) > data_end → fuera
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Ahora es seguro acceder a ip->protocol
    if (ip->protocol == 6)  // TCP → drop
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
