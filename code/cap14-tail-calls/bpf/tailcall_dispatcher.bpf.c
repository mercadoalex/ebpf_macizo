//go:build ignore

// tailcall_dispatcher.bpf.c — Capítulo 14: Tail Calls y Composición
//
// Demostración de tail calls con un dispatcher XDP que usa un prog_array
// para despachar paquetes a handlers específicos según el protocolo.
//
// Arquitectura:
//
//   [Paquete entrante]
//        │
//   ┌────▼────┐
//   │Dispatcher│  ← Parsea L3, decide qué handler invocar
//   └────┬────┘
//        │ bpf_tail_call(ctx, prog_array, proto_index)
//        ▼
//   ┌─────────────────────────────────┐
//   │  prog_array                     │
//   │  [0] → handle_tcp              │
//   │  [1] → handle_udp              │
//   │  [2] → handle_icmp             │
//   └─────────────────────────────────┘
//
// Conceptos demostrados:
// - BPF_MAP_TYPE_PROG_ARRAY para tail calls
// - bpf_tail_call() para saltar a sub-programas
// - Dispatcher pattern: un programa "router" que decide
// - Cada handler tiene su propia lógica y estadísticas
// - Si el tail call falla (programa no cargado), se continúa con XDP_PASS
//
// Limitaciones clave:
// - Máximo 33 tail calls encadenados (stack limit)
// - No se puede retornar al programa que llamó (es un JUMP, no un CALL)
// - El stack se resetea en cada tail call
//
// Attach point: XDP hook en interfaz de red

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Índices del prog_array — cada protocolo tiene su slot
#define PROG_TCP  0
#define PROG_UDP  1
#define PROG_ICMP 2

// Estadísticas por protocolo: [0]=tcp, [1]=udp, [2]=icmp, [3]=other, [4]=dropped
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u64);
} pkt_stats SEC(".maps");

// Prog array para tail calls — el user space mete los programas aquí
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} jmp_table SEC(".maps");

// ─── Helper inline: incrementar stats ──────────────────────────────
static __always_inline void stats_inc(__u32 idx) {
    __u64 *val = bpf_map_lookup_elem(&pkt_stats, &idx);
    if (val)
        (*val)++;
}

// ═══════════════════════════════════════════════════════════════════════
// HANDLER: TCP
// Cuenta paquetes TCP y los deja pasar.
// ═══════════════════════════════════════════════════════════════════════
SEC("xdp")
int handle_tcp(struct xdp_md *ctx) {
    stats_inc(PROG_TCP);
    return XDP_PASS;
}

// ═══════════════════════════════════════════════════════════════════════
// HANDLER: UDP
// Cuenta paquetes UDP y los deja pasar.
// ═══════════════════════════════════════════════════════════════════════
SEC("xdp")
int handle_udp(struct xdp_md *ctx) {
    stats_inc(PROG_UDP);
    return XDP_PASS;
}

// ═══════════════════════════════════════════════════════════════════════
// HANDLER: ICMP
// Cuenta paquetes ICMP. Dropea echo request (bloquea ping).
// ═══════════════════════════════════════════════════════════════════════
SEC("xdp")
int handle_icmp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    struct icmphdr *icmp = (void *)ip + (ip->ihl * 4);
    if ((void *)(icmp + 1) > data_end)
        return XDP_DROP;

    stats_inc(PROG_ICMP);

    // Dropear echo request (tipo 8) — bloquea ping
    if (icmp->type == ICMP_ECHO) {
        __u32 drop_key = 4;
        stats_inc(drop_key);
        return XDP_DROP;
    }

    return XDP_PASS;
}

// ═══════════════════════════════════════════════════════════════════════
// DISPATCHER: Punto de entrada principal
// Parsea el protocolo L4 y salta al handler correspondiente.
// Si el handler no está cargado en prog_array, pasa el paquete.
// ═══════════════════════════════════════════════════════════════════════
SEC("xdp")
int xdp_dispatcher(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parsear Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Solo IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Parsear IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Despachar según protocolo L4
    switch (ip->protocol) {
    case IPPROTO_TCP:
        bpf_tail_call(ctx, &jmp_table, PROG_TCP);
        break;
    case IPPROTO_UDP:
        bpf_tail_call(ctx, &jmp_table, PROG_UDP);
        break;
    case IPPROTO_ICMP:
        bpf_tail_call(ctx, &jmp_table, PROG_ICMP);
        break;
    }

    // Si llegamos aquí: el tail call falló (handler no cargado) o protocolo sin handler
    __u32 other_key = 3;
    stats_inc(other_key);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
