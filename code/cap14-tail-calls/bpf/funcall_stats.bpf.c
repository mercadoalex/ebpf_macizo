//go:build ignore

// funcall_stats.bpf.c — Capítulo 14: BPF-to-BPF Function Calls
//
// Demostración de llamadas a funciones BPF-to-BPF (no inline).
// A diferencia de tail calls, las function calls:
//
// - SÍ retornan al llamador (son un CALL real, no un JUMP)
// - Comparten el stack del programa padre
// - Permiten reutilizar lógica sin duplicar código
// - El verifier las analiza como funciones separadas
//
// Este programa XDP usa funciones __noinline para:
// 1. parse_eth() — parsear Ethernet header (reutilizable)
// 2. parse_ip()  — parsear IP header (reutilizable)
// 3. update_stats() — actualizar estadísticas por protocolo
//
// La idea: separar el parsing de la lógica de decisión,
// como harías en cualquier programa bien estructurado.
//
// Comparación con tail calls:
// ┌─────────────────┬─────────────────────┬──────────────────────┐
// │                 │ Tail Calls          │ Function Calls       │
// ├─────────────────┼─────────────────────┼──────────────────────┤
// │ Retorno         │ NO (es un jump)     │ SÍ (retorna)         │
// │ Stack           │ Se resetea          │ Se comparte (512B)   │
// │ Límite          │ 33 encadenados      │ 8 niveles de nesting │
// │ Caso de uso     │ Pipelines, dispatch │ Reutilizar lógica    │
// └─────────────────┴─────────────────────┴──────────────────────┘
//
// Attach point: XDP hook en interfaz de red

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Estadísticas por protocolo
// Keys: 0=total, 1=tcp, 2=udp, 3=icmp, 4=other
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u64);
} proto_stats SEC(".maps");

// Estadísticas de tamaño de paquetes
// Keys: 0=tiny(≤64), 1=small(65-512), 2=medium(513-1500), 3=jumbo(>1500)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} size_stats SEC(".maps");

// ═══════════════════════════════════════════════════════════════════════
// BPF-to-BPF Functions (marcadas __noinline para que el verifier
// las trate como funciones separadas y no las inline)
// ═══════════════════════════════════════════════════════════════════════

// parse_eth — Parsea y valida el header Ethernet.
// Retorna el protocolo EtherType (o 0 si el paquete es inválido).
static __noinline __u16 parse_eth(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    return bpf_ntohs(eth->h_proto);
}

// parse_ip — Parsea y valida el header IP.
// Retorna el protocolo L4 (o 0 si no es IPv4 válido).
static __noinline __u8 parse_ip(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;

    // Validación mínima: IHL ≥ 5
    if (ip->ihl < 5)
        return 0;

    return ip->protocol;
}

// update_proto_stats — Incrementa contador del protocolo correspondiente.
static __noinline void update_proto_stats(__u8 protocol) {
    __u32 key;

    switch (protocol) {
    case IPPROTO_TCP:
        key = 1;
        break;
    case IPPROTO_UDP:
        key = 2;
        break;
    case IPPROTO_ICMP:
        key = 3;
        break;
    default:
        key = 4;
        break;
    }

    __u64 *val = bpf_map_lookup_elem(&proto_stats, &key);
    if (val)
        (*val)++;

    // Total siempre se incrementa
    __u32 total_key = 0;
    __u64 *total = bpf_map_lookup_elem(&proto_stats, &total_key);
    if (total)
        (*total)++;
}

// update_size_stats — Clasifica el paquete por tamaño y actualiza stats.
static __noinline void update_size_stats(__u32 pkt_len) {
    __u32 key;

    if (pkt_len <= 64)
        key = 0;       // tiny
    else if (pkt_len <= 512)
        key = 1;       // small
    else if (pkt_len <= 1500)
        key = 2;       // medium
    else
        key = 3;       // jumbo

    __u64 *val = bpf_map_lookup_elem(&size_stats, &key);
    if (val)
        (*val)++;
}

// ═══════════════════════════════════════════════════════════════════════
// Programa principal XDP
// Usa las funciones de arriba para parsear + recolectar estadísticas.
// ═══════════════════════════════════════════════════════════════════════
SEC("xdp")
int xdp_stats_collector(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Calcular tamaño del paquete
    __u32 pkt_len = data_end - data;

    // Usar function call para parsear Ethernet
    __u16 eth_proto = parse_eth(data, data_end);
    if (eth_proto == 0)
        return XDP_PASS;

    // Solo IPv4 por ahora
    if (eth_proto != ETH_P_IP)
        return XDP_PASS;

    // Usar function call para parsear IP
    __u8 l4_proto = parse_ip(data, data_end);
    if (l4_proto == 0)
        return XDP_PASS;

    // Usar function calls para actualizar estadísticas
    update_proto_stats(l4_proto);
    update_size_stats(pkt_len);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
