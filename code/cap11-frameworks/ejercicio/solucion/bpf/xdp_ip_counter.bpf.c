//go:build ignore

// xdp_ip_counter.bpf.c — Capítulo 11 Ejercicio SOLUCIÓN
//
// Contador XDP por protocolo + por IP destino.
// Demuestra uso combinado de array map + hash map.
//
// Attach point: XDP hook en interfaz de red

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Índices del array map para cada protocolo
#define PROTO_TCP   0
#define PROTO_UDP   1
#define PROTO_ICMP  2
#define PROTO_OTHER 3
#define MAX_PROTOS  4

// Array map: contadores por protocolo
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_PROTOS);
    __type(key, __u32);
    __type(value, __u64);
} proto_stats SEC(".maps");

// Hash map: contadores por IP de destino
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} ip_stats SEC(".maps");

SEC("xdp")
int xdp_ip_counter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parsear Ethernet header — bounds check obligatorio
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Solo procesar IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parsear IP header — bounds check obligatorio
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // ─── Conteo por protocolo ───────────────────────────────────
    __u32 proto_idx;
    switch (ip->protocol) {
    case 6:  proto_idx = PROTO_TCP;   break;
    case 17: proto_idx = PROTO_UDP;   break;
    case 1:  proto_idx = PROTO_ICMP;  break;
    default: proto_idx = PROTO_OTHER; break;
    }

    __u64 *proto_count = bpf_map_lookup_elem(&proto_stats, &proto_idx);
    if (proto_count)
        __sync_fetch_and_add(proto_count, 1);

    // ─── Conteo por IP destino ──────────────────────────────────
    __u32 dst_ip = ip->daddr;

    __u64 *ip_count = bpf_map_lookup_elem(&ip_stats, &dst_ip);
    if (ip_count) {
        // La IP ya tiene entrada — incrementar
        __sync_fetch_and_add(ip_count, 1);
    } else {
        // Primera vez que vemos esta IP — crear entrada
        __u64 init_val = 1;
        bpf_map_update_elem(&ip_stats, &dst_ip, &init_val, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
