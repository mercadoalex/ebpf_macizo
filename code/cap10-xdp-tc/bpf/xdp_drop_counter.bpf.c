//go:build ignore

// xdp_drop_counter.bpf.c — Capítulo 10: XDP con conteo de paquetes
//
// Programa XDP que demuestra las acciones XDP_PASS y XDP_DROP.
// Parsea headers Ethernet e IP para identificar paquetes ICMP y los
// descarta (bloqueando ping). Mantiene contadores de paquetes
// aceptados vs descartados en un array map.
//
// Conceptos demostrados:
// - Parseo de Ethernet header con bounds checking
// - Parseo de IP header
// - Decisiones XDP_PASS vs XDP_DROP
// - Contadores atómicos en maps
// - Conversión de byte order con bpf_htons
//
// Attach point: XDP hook en interfaz de red

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Array map para estadísticas: index 0 = passed, index 1 = dropped
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} pkt_count SEC(".maps");

static __always_inline void count_action(__u32 action) {
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &action);
    if (count)
        __sync_fetch_and_add(count, 1);
}

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parsear Ethernet header — bounds check obligatorio
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        count_action(1);
        return XDP_DROP;
    }

    // Solo procesar IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        count_action(0);
        return XDP_PASS;
    }

    // Parsear IP header — bounds check obligatorio
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        count_action(1);
        return XDP_DROP;
    }

    // Dropear ICMP (protocolo 1 = ping)
    if (ip->protocol == 1) {
        count_action(1);
        return XDP_DROP;
    }

    count_action(0);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
