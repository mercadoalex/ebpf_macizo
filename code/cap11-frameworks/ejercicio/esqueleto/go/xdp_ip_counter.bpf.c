//go:build ignore

// xdp_ip_counter.bpf.c — Capítulo 11 Ejercicio: Contador por IP destino
//
// Extiende el programa de referencia para contar paquetes por IP de destino.
// El array map proto_stats ya funciona — tu trabajo es agregar el hash map.
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

// Array map: contadores por protocolo (ya implementado)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_PROTOS);
    __type(key, __u32);
    __type(value, __u64);
} proto_stats SEC(".maps");

// TODO 1: Declarar un hash map llamado "ip_stats"
// - Tipo: BPF_MAP_TYPE_HASH
// - max_entries: 1024
// - Key: __u32 (IP de destino en network byte order)
// - Value: __u64 (contador de paquetes)
//
// Pista: La sintaxis es igual al proto_stats de arriba, pero con
//        __uint(type, BPF_MAP_TYPE_HASH) y __uint(max_entries, 1024)

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

    // ─── Conteo por protocolo (ya implementado) ─────────────────
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

    // ─── Conteo por IP destino (TÚ LO IMPLEMENTAS) ─────────────

    // TODO 2: Extraer la IP de destino del header IP
    // Pista: ip->daddr es un __u32 en network byte order

    // TODO 3: Buscar la IP en el hash map ip_stats
    // Pista: bpf_map_lookup_elem(&ip_stats, &dst_ip)

    // TODO 4: Si existe, incrementar atómicamente. Si no existe,
    //          crear la entrada con valor inicial 1.
    // Pista: usa __sync_fetch_and_add para incrementar,
    //        bpf_map_update_elem para crear

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
