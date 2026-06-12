//go:build ignore

// xdp_parser.bpf.c — Capítulo 10: Parseo completo de paquetes en XDP
//
// Programa XDP que demuestra el parseo completo de paquetes de red:
// Ethernet → IP → TCP/UDP. Ilustra el patrón fundamental de parseo
// con bounds checking obligatorio en cada capa.
//
// Conceptos demostrados:
// - Parseo capa por capa (L2 → L3 → L4)
// - Bounds checking antes de cada acceso
// - IP header length variable (ihl * 4)
// - Conversión de byte order (network → host)
// - Helper function inline para parseo reusable
// - Logging con bpf_printk para debugging
//
// Attach point: XDP hook en interfaz de red

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Estructura para almacenar los headers parseados
struct pkt_headers {
    struct ethhdr *eth;
    struct iphdr  *ip;
    union {
        struct tcphdr *tcp;
        struct udphdr *udp;
    };
    __u8 l4_proto;
};

// Función helper inline para parseo reusable.
// __always_inline es OBLIGATORIO — sin esto, el verifier no puede
// rastrear los bounds checks correctamente.
static __always_inline int parse_headers(struct xdp_md *ctx,
                                          struct pkt_headers *hdrs) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // === PASO 1: Ethernet header ===
    hdrs->eth = data;
    if ((void *)(hdrs->eth + 1) > data_end)
        return -1;

    // Solo IPv4
    if (hdrs->eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    // === PASO 2: IP header ===
    hdrs->ip = (void *)(hdrs->eth + 1);
    if ((void *)(hdrs->ip + 1) > data_end)
        return -1;

    // Validar IP header length (mínimo 20 bytes = 5 words)
    __u32 ip_hdr_len = hdrs->ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return -1;

    // === PASO 3: L4 header (TCP o UDP) ===
    void *l4 = (void *)hdrs->ip + ip_hdr_len;
    hdrs->l4_proto = hdrs->ip->protocol;

    if (hdrs->l4_proto == IPPROTO_TCP) {
        hdrs->tcp = l4;
        if ((void *)(hdrs->tcp + 1) > data_end)
            return -1;
    } else if (hdrs->l4_proto == IPPROTO_UDP) {
        hdrs->udp = l4;
        if ((void *)(hdrs->udp + 1) > data_end)
            return -1;
    }

    return 0;
}

SEC("xdp")
int xdp_parse_pkt(struct xdp_md *ctx) {
    struct pkt_headers hdrs = {};

    // Parsear todo el paquete de una vez
    if (parse_headers(ctx, &hdrs) < 0)
        return XDP_PASS;  // No es IPv4 TCP/UDP — dejar pasar

    // A partir de aquí, hdrs.ip y hdrs.tcp/udp están validados
    if (hdrs.l4_proto == IPPROTO_TCP) {
        __u16 src_port = bpf_ntohs(hdrs.tcp->source);
        __u16 dst_port = bpf_ntohs(hdrs.tcp->dest);
        bpf_printk("XDP TCP: %pI4:%d -> port %d",
                   &hdrs.ip->saddr, src_port, dst_port);
    } else if (hdrs.l4_proto == IPPROTO_UDP) {
        __u16 src_port = bpf_ntohs(hdrs.udp->source);
        __u16 dst_port = bpf_ntohs(hdrs.udp->dest);
        bpf_printk("XDP UDP: %pI4:%d -> port %d",
                   &hdrs.ip->saddr, src_port, dst_port);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
