//go:build ignore

// classifier.bpf.c — Solución Ejercicio Ninja: Classifier Multi-Protocolo
//
// Implementación completa de un classifier XDP que combina:
// - Tail calls para despacho a handlers por protocolo
// - BPF-to-BPF function calls para lógica compartida de parsing
// - Per-CPU maps para estadísticas de alto rendimiento (sin locks)
// - Map de contexto para pasar datos entre dispatcher y handlers
//
// Arquitectura:
//
//   [Paquete]
//      │
//   ┌──▼────────────────┐
//   │  xdp_classifier    │  ← Punto de entrada
//   │  (dispatcher)      │     - Usa parse_packet() [BPF-to-BPF]
//   │                    │     - Guarda contexto en ctx_map
//   └──────┬─────────────┘     - Tail call al handler
//          │
//    bpf_tail_call(ctx, progs, proto)
//          │
//   ┌──────▼─────────────────────────────────────────────┐
//   │ prog_array                                         │
//   │ [0] classify_tcp   ← Clasifica por puerto         │
//   │ [1] classify_udp   ← Clasifica DNS vs otros      │
//   │ [2] classify_icmp  ← Clasifica tipo ICMP         │
//   │ [3] classify_other ← Catch-all                    │
//   └───────────────────────────────────────────────────┘
//
// Contexto compartido (ctx_map):
//   El dispatcher guarda {src_ip, dst_ip, pkt_len, l4_offset}
//   en un per-CPU array ANTES del tail call. El handler lo lee
//   en lugar de re-parsear el paquete. Esto demuestra el patrón
//   de "pasar datos entre tail calls" sin stack sharing.
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

// ─── Constantes ─────────────────────────────────────────────────────
#define HANDLER_TCP   0
#define HANDLER_UDP   1
#define HANDLER_ICMP  2
#define HANDLER_OTHER 3
#define MAX_HANDLERS  4

// Categorías de clasificación (stats keys)
#define CLASS_HTTP      0   // TCP puertos 80/443
#define CLASS_SSH       1   // TCP puerto 22
#define CLASS_DNS       2   // UDP puerto 53
#define CLASS_ICMP_ECHO 3   // ICMP echo request/reply
#define CLASS_ICMP_OTHER 4  // ICMP otros tipos
#define CLASS_TCP_OTHER 5   // TCP otros puertos
#define CLASS_UDP_OTHER 6   // UDP otros puertos
#define CLASS_UNKNOWN   7   // Protocolos no clasificados
#define CLASS_TOTAL     8   // Total de paquetes procesados
#define NUM_CLASSES     9

// ─── Estructura de contexto compartido entre tail calls ─────────────
struct pkt_context {
    __u32 src_ip;       // IP de origen (network byte order)
    __u32 dst_ip;       // IP de destino (network byte order)
    __u32 pkt_len;      // Tamaño total del paquete
    __u16 l4_offset;    // Offset al header L4 desde inicio del paquete
    __u8  protocol;     // Protocolo L4 (IPPROTO_*)
    __u8  _pad;         // Padding para alineación
};

// ─── Maps ───────────────────────────────────────────────────────────

// Estadísticas de clasificación per-CPU (alta performance)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, NUM_CLASSES);
    __type(key, __u32);
    __type(value, __u64);
} class_stats SEC(".maps");

// Prog array para tail calls
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_HANDLERS);
    __type(key, __u32);
    __type(value, __u32);
} handler_progs SEC(".maps");

// Contexto per-CPU para pasar datos entre dispatcher y handlers
// Usamos per-CPU array con 1 entrada: cada CPU tiene su propio slot,
// no hay race conditions.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pkt_context);
} ctx_map SEC(".maps");

// ─── BPF-to-BPF Functions (lógica compartida) ──────────────────────

// classify_inc — Incrementa un contador de clasificación.
static __noinline void classify_inc(__u32 class_id) {
    __u64 *val = bpf_map_lookup_elem(&class_stats, &class_id);
    if (val)
        (*val)++;
}

// parse_packet — Parsea Ethernet + IP, llena el contexto.
// Retorna 0 si OK, -1 si el paquete es inválido o no es IPv4.
static __noinline int parse_packet(void *data, void *data_end,
                                    struct pkt_context *pctx) {
    // Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    // IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    if (ip->ihl < 5)
        return -1;

    __u16 ip_hdr_len = ip->ihl * 4;

    // Verificar que el header IP no excede el paquete
    if ((void *)ip + ip_hdr_len > data_end)
        return -1;

    // Llenar contexto
    pctx->src_ip = ip->saddr;
    pctx->dst_ip = ip->daddr;
    pctx->pkt_len = data_end - data;
    pctx->l4_offset = sizeof(struct ethhdr) + ip_hdr_len;
    pctx->protocol = ip->protocol;

    return 0;
}

// get_context — Helper para que los handlers lean el contexto.
// Retorna puntero al contexto o NULL si no existe.
static __noinline struct pkt_context *get_context(void) {
    __u32 key = 0;
    return bpf_map_lookup_elem(&ctx_map, &key);
}

// ═══════════════════════════════════════════════════════════════════════
// HANDLER: TCP — Clasifica por puerto destino
// ═══════════════════════════════════════════════════════════════════════
SEC("xdp")
int classify_tcp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Leer contexto preparado por el dispatcher
    struct pkt_context *pctx = get_context();
    if (!pctx)
        return XDP_PASS;

    // Bounds check para TCP header usando el offset guardado
    struct tcphdr *tcp = data + pctx->l4_offset;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u16 dport = bpf_ntohs(tcp->dest);

    // Clasificar por puerto
    if (dport == 80 || dport == 443) {
        classify_inc(CLASS_HTTP);
    } else if (dport == 22) {
        classify_inc(CLASS_SSH);
    } else {
        classify_inc(CLASS_TCP_OTHER);
    }

    return XDP_PASS;
}

// ═══════════════════════════════════════════════════════════════════════
// HANDLER: UDP — Clasifica DNS vs otros
// ═══════════════════════════════════════════════════════════════════════
SEC("xdp")
int classify_udp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct pkt_context *pctx = get_context();
    if (!pctx)
        return XDP_PASS;

    struct udphdr *udp = data + pctx->l4_offset;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u16 dport = bpf_ntohs(udp->dest);
    __u16 sport = bpf_ntohs(udp->source);

    // DNS usa puerto 53 (destino o source para respuestas)
    if (dport == 53 || sport == 53) {
        classify_inc(CLASS_DNS);
    } else {
        classify_inc(CLASS_UDP_OTHER);
    }

    return XDP_PASS;
}

// ═══════════════════════════════════════════════════════════════════════
// HANDLER: ICMP — Clasifica por tipo
// ═══════════════════════════════════════════════════════════════════════
SEC("xdp")
int classify_icmp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct pkt_context *pctx = get_context();
    if (!pctx)
        return XDP_PASS;

    struct icmphdr *icmp = data + pctx->l4_offset;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    // Echo request (8) o echo reply (0)
    if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
        classify_inc(CLASS_ICMP_ECHO);
    } else {
        classify_inc(CLASS_ICMP_OTHER);
    }

    return XDP_PASS;
}

// ═══════════════════════════════════════════════════════════════════════
// HANDLER: Other — Catch-all para protocolos sin handler específico
// ═══════════════════════════════════════════════════════════════════════
SEC("xdp")
int classify_other(struct xdp_md *ctx) {
    classify_inc(CLASS_UNKNOWN);
    return XDP_PASS;
}

// ═══════════════════════════════════════════════════════════════════════
// DISPATCHER: Punto de entrada XDP
// Parsea el paquete, guarda contexto, y despacha al handler.
// ═══════════════════════════════════════════════════════════════════════
SEC("xdp")
int xdp_classifier(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Obtener slot per-CPU para guardar contexto
    __u32 key = 0;
    struct pkt_context *pctx = bpf_map_lookup_elem(&ctx_map, &key);
    if (!pctx)
        return XDP_PASS;

    // Usar BPF-to-BPF function call para parsear
    if (parse_packet(data, data_end, pctx) < 0)
        return XDP_PASS;

    // Incrementar total
    classify_inc(CLASS_TOTAL);

    // Despachar al handler por protocolo via tail call
    switch (pctx->protocol) {
    case IPPROTO_TCP:
        bpf_tail_call(ctx, &handler_progs, HANDLER_TCP);
        break;
    case IPPROTO_UDP:
        bpf_tail_call(ctx, &handler_progs, HANDLER_UDP);
        break;
    case IPPROTO_ICMP:
        bpf_tail_call(ctx, &handler_progs, HANDLER_ICMP);
        break;
    default:
        bpf_tail_call(ctx, &handler_progs, HANDLER_OTHER);
        break;
    }

    // Fallback si el tail call falla (handler no instalado)
    classify_inc(CLASS_UNKNOWN);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
