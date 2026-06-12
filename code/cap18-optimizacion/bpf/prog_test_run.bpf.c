//go:build ignore

// prog_test_run.bpf.c — Capítulo 18: Programa XDP para benchmarking con BPF_PROG_TEST_RUN
//
// Este programa XDP está diseñado específicamente para ser medido con
// BPF_PROG_TEST_RUN (bpf_prog_test_run_opts). No necesita estar adjuntado
// a una interfaz real — el kernel ejecuta el programa con paquetes sintéticos
// y mide el tiempo de ejecución en nanosegundos.
//
// Flujo de benchmarking:
// 1. Se carga el programa en el kernel (pasa el verifier)
// 2. Se construye un paquete sintético (Ethernet + IP + TCP)
// 3. Se invoca BPF_PROG_TEST_RUN con repeat=N
// 4. El kernel ejecuta el programa N veces y reporta duration en ns
// 5. El control plane calcula estadísticas (avg, p50, p99, min, max)
//
// El programa implementa parseo completo de paquetes con clasificación
// por protocolo L4 — suficiente complejidad para obtener mediciones
// representativas de un XDP program real.
//
// Attach point: XDP (pero usado via BPF_PROG_TEST_RUN, no attach real)

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// =============================================================================
// Maps para estadísticas
// =============================================================================

// Contadores por protocolo L4 (per-CPU para evitar contención)
// Key: protocol number (TCP=6, UDP=17, ICMP=1)
// Value: packet count
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u64);
} proto_stats SEC(".maps");

// Contadores globales per-CPU
// Index 0 = total packets, 1 = total bytes, 2 = dropped
#define STAT_TOTAL_PKTS  0
#define STAT_TOTAL_BYTES 1
#define STAT_DROPPED     2
#define STAT_MAX         3

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} global_stats SEC(".maps");

// =============================================================================
// Funciones auxiliares (inlined para rendimiento)
// =============================================================================

static __always_inline void increment_stat(__u32 idx, __u64 value) {
    __u64 *counter = bpf_map_lookup_elem(&global_stats, &idx);
    if (counter)
        *counter += value;
}

static __always_inline void increment_proto(__u32 proto) {
    __u64 *counter = bpf_map_lookup_elem(&proto_stats, &proto);
    if (counter)
        *counter += 1;
}

// =============================================================================
// Programa XDP principal — diseñado para BPF_PROG_TEST_RUN
// =============================================================================

SEC("xdp")
int xdp_bench(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // --- Parseo Ethernet ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        increment_stat(STAT_DROPPED, 1);
        return XDP_DROP;
    }

    // Solo IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // --- Parseo IP ---
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        increment_stat(STAT_DROPPED, 1);
        return XDP_DROP;
    }

    // Validar IHL mínimo
    if (ip->ihl < 5)
        return XDP_DROP;

    // Calcular tamaño del paquete
    __u32 pkt_len = data_end - data;

    // Incrementar stats globales
    increment_stat(STAT_TOTAL_PKTS, 1);
    increment_stat(STAT_TOTAL_BYTES, pkt_len);

    // Clasificar por protocolo L4
    __u32 proto = ip->protocol;
    increment_proto(proto);

    // Parseo L4 para validación de bounds (simula trabajo real)
    void *l4 = (void *)ip + (ip->ihl * 4);

    switch (ip->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) {
            increment_stat(STAT_DROPPED, 1);
            return XDP_DROP;
        }
        // Simular lógica de firewall: drop SYN floods a puerto 0
        if (tcp->syn && !tcp->ack && tcp->dest == 0) {
            increment_stat(STAT_DROPPED, 1);
            return XDP_DROP;
        }
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) {
            increment_stat(STAT_DROPPED, 1);
            return XDP_DROP;
        }
        break;
    }
    case IPPROTO_ICMP: {
        struct icmphdr *icmp = l4;
        if ((void *)(icmp + 1) > data_end) {
            increment_stat(STAT_DROPPED, 1);
            return XDP_DROP;
        }
        break;
    }
    default:
        break;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
