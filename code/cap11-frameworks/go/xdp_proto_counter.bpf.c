//go:build ignore

// xdp_proto_counter.bpf.c — Capítulo 11: Frameworks en acción
//
// Programa XDP de referencia: contador de paquetes por protocolo.
// Clasifica paquetes IPv4 en TCP, UDP, ICMP u "otro" y mantiene
// contadores atómicos en un array map.
//
// Este mismo programa se implementa en:
// - Go (cilium/ebpf) → directorio go/
// - Rust (Aya) → directorio rust/
//
// La comparación demuestra que el código BPF (kernel side) es
// SIEMPRE C, sin importar el framework de user space.
//
// Conceptos demostrados:
// - Parseo de Ethernet + IP headers
// - Clasificación por protocolo L4
// - Contadores atómicos en array map
// - Bounds checking obligatorio para el verifier
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

SEC("xdp")
int xdp_proto_counter(struct xdp_md *ctx) {
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

    // Clasificar protocolo
    __u32 proto_idx;
    switch (ip->protocol) {
    case 6:  // TCP
        proto_idx = PROTO_TCP;
        break;
    case 17: // UDP
        proto_idx = PROTO_UDP;
        break;
    case 1:  // ICMP
        proto_idx = PROTO_ICMP;
        break;
    default:
        proto_idx = PROTO_OTHER;
        break;
    }

    // Incrementar contador atómicamente
    __u64 *count = bpf_map_lookup_elem(&proto_stats, &proto_idx);
    if (count)
        __sync_fetch_and_add(count, 1);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
