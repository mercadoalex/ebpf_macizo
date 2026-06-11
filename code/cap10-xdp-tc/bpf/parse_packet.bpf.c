//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int parse_packet(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // ═══════════════════════════════════════════
    // PASO 1: Parsear Ethernet header
    // ═══════════════════════════════════════════
    struct ethhdr *eth = data;

    // Bounds check: ¿hay espacio para un header Ethernet completo?
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    // ¿Es IPv4?
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // ═══════════════════════════════════════════
    // PASO 2: Parsear IP header
    // ═══════════════════════════════════════════
    struct iphdr *ip = (void *)(eth + 1);

    // Bounds check: ¿hay espacio para el header IP?
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    // Extraer info útil
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u8  proto  = ip->protocol;

    // El header IP tiene tamaño variable (ihl = IP Header Length en words de 4 bytes)
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_DROP;

    // ═══════════════════════════════════════════
    // PASO 3: Parsear L4 (TCP o UDP)
    // ═══════════════════════════════════════════
    void *l4_hdr = (void *)ip + ip_hdr_len;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_hdr;
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;

        __u16 src_port = bpf_ntohs(tcp->source);
        __u16 dst_port = bpf_ntohs(tcp->dest);

        bpf_printk("TCP: src_port=%d dst_port=%d", src_port, dst_port);

    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4_hdr;
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;

        __u16 src_port = bpf_ntohs(udp->source);
        __u16 dst_port = bpf_ntohs(udp->dest);

        bpf_printk("UDP: src_port=%d dst_port=%d", src_port, dst_port);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
