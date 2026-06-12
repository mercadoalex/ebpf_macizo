//go:build ignore

// xdp_firewall.bpf.c — Solución: Firewall XDP con Blocklist (Capítulo 10)
//
// Copia para bpf2go — versión completa con la lógica implementada.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parsear Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parsear IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    // Obtener IP de origen
    __u32 src_ip = ip->saddr;

    // Buscar en blocklist
    __u64 *blocked = bpf_map_lookup_elem(&blocklist, &src_ip);

    if (blocked) {
        // IP bloqueada → incrementar contadores y DROP
        __sync_fetch_and_add(blocked, 1);

        __u32 key = 1;
        __u64 *drop_count = bpf_map_lookup_elem(&stats, &key);
        if (drop_count)
            __sync_fetch_and_add(drop_count, 1);

        return XDP_DROP;
    }

    // IP permitida → incrementar contador y PASS
    __u32 key = 0;
    __u64 *pass_count = bpf_map_lookup_elem(&stats, &key);
    if (pass_count)
        __sync_fetch_and_add(pass_count, 1);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
