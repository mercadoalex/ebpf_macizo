//go:build ignore

// optimized_xdp.bpf.c — Capítulo 18 Ejercicio: XDP optimizado con evidencia medida
//
// Este programa toma un programa XDP de un ejercicio anterior (el firewall
// del Cap 10 o el classifier del Cap 14) y aplica las tres técnicas de
// optimización del capítulo:
//
// 1. Per-CPU maps — eliminar contención en los contadores
// 2. Inlining agresivo — __always_inline en todas las funciones auxiliares
// 3. Branch prediction hints — likely/unlikely en paths calientes
//
// Objetivo: demostrar mejora medible (2x-5x) usando BPF_PROG_TEST_RUN
// como herramienta de profiling antes/después.
//
// Attach point: XDP

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// =============================================================================
// Optimización: Branch hints
// =============================================================================

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

// =============================================================================
// Configuración
// =============================================================================

#define MAX_RULES    1024
#define STATS_PKTS   0
#define STATS_BYTES  1
#define STATS_DROPS  2
#define STATS_PASS   3
#define STATS_MAX    4

// =============================================================================
// Estructuras
// =============================================================================

// Regla de firewall
struct fw_rule {
    __u32 src_ip;      // IP origen (0 = any)
    __u32 dst_ip;      // IP destino (0 = any)
    __u16 dst_port;    // Puerto destino (0 = any)
    __u8  proto;       // Protocolo (0 = any)
    __u8  action;      // 0 = DROP, 1 = PASS
};

// =============================================================================
// Maps — OPTIMIZADO con per-CPU
// =============================================================================

// Reglas del firewall (lookup por src IP como key simple)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);   // src_ip
    __type(value, struct fw_rule);
} rules SEC(".maps");

// Estadísticas per-CPU — zero contention entre cores
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Stats por protocolo per-CPU
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} proto_stats SEC(".maps");

// =============================================================================
// Funciones auxiliares — OPTIMIZADO con __always_inline
// =============================================================================

// Incrementar estadística (inlined → zero call overhead)
static __always_inline void stat_inc(__u32 idx, __u64 value) {
    __u64 *counter = bpf_map_lookup_elem(&stats, &idx);
    if (likely(counter != NULL))
        *counter += value;
}

// Parsear header Ethernet (inlined)
static __always_inline struct iphdr *parse_eth(void *data, void *data_end) {
    struct ethhdr *eth = data;
    if (unlikely((void *)(eth + 1) > data_end))
        return NULL;
    if (unlikely(eth->h_proto != bpf_htons(ETH_P_IP)))
        return NULL;
    return (struct iphdr *)(eth + 1);
}

// Extraer puerto destino L4 (inlined)
static __always_inline __u16 get_dst_port(
    struct iphdr *ip,
    void *data_end
) {
    void *l4 = (void *)ip + (ip->ihl * 4);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if (likely((void *)(tcp + 1) <= data_end))
            return tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if (likely((void *)(udp + 1) <= data_end))
            return udp->dest;
    }
    return 0;
}

// Evaluar regla contra paquete (inlined)
static __always_inline int check_rule(
    struct fw_rule *rule,
    __u32 src_ip,
    __u32 dst_ip,
    __u16 dst_port,
    __u8 proto
) {
    // Verificar cada campo (0 = wildcard/any)
    if (rule->dst_ip != 0 && rule->dst_ip != dst_ip)
        return -1;  // No match
    if (rule->dst_port != 0 && rule->dst_port != dst_port)
        return -1;
    if (rule->proto != 0 && rule->proto != proto)
        return -1;

    return rule->action;  // 0=DROP, 1=PASS
}

// =============================================================================
// Programa XDP principal — OPTIMIZADO
// =============================================================================

SEC("xdp")
int optimized_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parseo optimizado (inlined, con branch hints)
    struct iphdr *ip = parse_eth(data, data_end);
    if (unlikely(ip == NULL))
        return XDP_PASS;  // No es IPv4 → pass

    if (unlikely((void *)(ip + 1) > data_end)) {
        stat_inc(STATS_DROPS, 1);
        return XDP_DROP;
    }

    // Estadísticas per-CPU (sin contención)
    __u32 pkt_len = data_end - data;
    stat_inc(STATS_PKTS, 1);
    stat_inc(STATS_BYTES, pkt_len);

    // Stats por protocolo
    __u32 proto_key = ip->protocol;
    __u64 *proto_cnt = bpf_map_lookup_elem(&proto_stats, &proto_key);
    if (likely(proto_cnt != NULL))
        *proto_cnt += 1;

    // Extraer puerto destino
    __u16 dst_port = get_dst_port(ip, data_end);

    // Lookup de regla por src_ip
    __u32 src_ip = ip->saddr;
    struct fw_rule *rule = bpf_map_lookup_elem(&rules, &src_ip);

    if (likely(rule == NULL)) {
        // No hay regla → acción por defecto: PASS
        stat_inc(STATS_PASS, 1);
        return XDP_PASS;
    }

    // Evaluar regla (inlined)
    int action = check_rule(rule, src_ip, ip->daddr, dst_port, ip->protocol);
    if (action == 0) {
        stat_inc(STATS_DROPS, 1);
        return XDP_DROP;
    }

    stat_inc(STATS_PASS, 1);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
