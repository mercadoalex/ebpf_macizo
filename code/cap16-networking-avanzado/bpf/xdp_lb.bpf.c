//go:build ignore

// xdp_lb.bpf.c — Capítulo 16: XDP Load Balancer con Consistent Hashing
//
// Load balancer L4 basado en XDP que distribuye tráfico TCP/UDP entre
// backends usando consistent hashing (estilo Maglev). El control plane
// pre-calcula el ring de hashing e inyecta la tabla como map.
//
// Arquitectura:
// - Parseo de 5-tuple (src_ip, dst_ip, src_port, dst_port, proto)
// - Hash determinístico → posición en ring → backend_id
// - Reescritura de headers (dst IP + dst MAC)
// - Reenvío con XDP_TX
//
// El control plane (Go) gestiona:
// - Llenado del consistent hash ring
// - Health checks de backends
// - Estadísticas per-CPU
// - Hot reload de backends sin downtime
//
// Attach point: XDP hook en interfaz de red (native mode recomendado)

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// =============================================================================
// Configuración
// =============================================================================

// Tamaño del ring de consistent hashing (número primo para mejor distribución)
#define CH_RING_SIZE 65537

// Máximo de backends soportados
#define MAX_BACKENDS 1024

// Índices para el array de stats
#define STATS_PACKETS  0
#define STATS_BYTES    1
#define STATS_DROPS    2
#define STATS_MAX      3

// =============================================================================
// Estructuras
// =============================================================================

// Información de un backend
struct backend_info {
    __u32 ip;           // IP del backend (network byte order)
    __u8  mac[6];       // MAC del backend
    __u16 flags;        // 0 = activo, 1 = down
};

// VIP (Virtual IP) — la IP pública del servicio
struct vip_info {
    __u32 vip;          // IP virtual (network byte order)
    __u16 port;         // Puerto del servicio (network byte order)
    __u16 proto;        // IPPROTO_TCP o IPPROTO_UDP
};

// =============================================================================
// Maps
// =============================================================================

// Ring de consistent hashing: posición → backend_id
// Pre-calculado por el control plane. Cada posición del array contiene
// el ID del backend que debe recibir el tráfico hasheado a esa posición.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CH_RING_SIZE);
    __type(key, __u32);
    __type(value, __u32);  // backend_id
} ch_ring SEC(".maps");

// Tabla de backends: backend_id → backend_info
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, struct backend_info);
} backends SEC(".maps");

// VIP configurada: el control plane escribe aquí la VIP que el LB sirve
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct vip_info);
} vip_config SEC(".maps");

// Estadísticas per-CPU: evita contención entre cores
// Index 0 = packets, 1 = bytes, 2 = drops
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Stats por backend (per-CPU): backend_id → packet count
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, __u64);
} backend_stats SEC(".maps");

// =============================================================================
// Funciones auxiliares
// =============================================================================

static __always_inline void stats_increment(__u32 idx, __u64 value) {
    __u64 *counter = bpf_map_lookup_elem(&stats, &idx);
    if (counter)
        *counter += value;
}

// Hash de 5-tuple — determinístico y rápido.
// Usa multiplicación por golden ratio + shifts para distribución uniforme.
static __always_inline __u32 hash_5tuple(
    __u32 src_ip, __u32 dst_ip,
    __u16 src_port, __u16 dst_port,
    __u8 proto
) {
    __u32 hash = src_ip;
    hash ^= dst_ip;
    hash ^= ((__u32)src_port << 16) | (__u32)dst_port;
    hash ^= (__u32)proto;

    // Mezcla final (murmurhash-style finalizer)
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;

    return hash;
}

// Recalcula IP checksum de forma incremental.
// Usa el truco de RFC 1624: solo actualiza el campo que cambió.
static __always_inline void update_ip_checksum(
    struct iphdr *ip,
    __u32 old_addr,
    __u32 new_addr
) {
    __u32 sum = (~(__u32)ip->check & 0xFFFF);
    sum += (~old_addr & 0xFFFF) + (~(old_addr >> 16) & 0xFFFF);
    sum += (new_addr & 0xFFFF) + (new_addr >> 16);

    // Fold 32-bit → 16-bit
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    ip->check = ~sum;
}

// =============================================================================
// Programa XDP principal
// =============================================================================

SEC("xdp")
int xdp_lb(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // --- Parseo Ethernet ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        stats_increment(STATS_DROPS, 1);
        return XDP_DROP;
    }

    // Solo IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // --- Parseo IP ---
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        stats_increment(STATS_DROPS, 1);
        return XDP_DROP;
    }

    // Solo TCP y UDP
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // --- Verificar que el paquete es para nuestra VIP ---
    __u32 vip_key = 0;
    struct vip_info *vip = bpf_map_lookup_elem(&vip_config, &vip_key);
    if (!vip)
        return XDP_PASS;

    if (ip->daddr != vip->vip)
        return XDP_PASS;

    // --- Extraer puertos L4 ---
    __u16 src_port = 0, dst_port = 0;
    void *l4 = (void *)ip + (ip->ihl * 4);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) {
            stats_increment(STATS_DROPS, 1);
            return XDP_DROP;
        }
        src_port = tcp->source;
        dst_port = tcp->dest;
    } else {  // UDP
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) {
            stats_increment(STATS_DROPS, 1);
            return XDP_DROP;
        }
        src_port = udp->source;
        dst_port = udp->dest;
    }

    // Verificar que el puerto destino coincide con la VIP
    if (dst_port != vip->port)
        return XDP_PASS;

    // --- Consistent hash: 5-tuple → ring position → backend ---
    __u32 hash = hash_5tuple(ip->saddr, ip->daddr, src_port, dst_port, ip->protocol);
    __u32 ring_idx = hash % CH_RING_SIZE;

    __u32 *backend_id = bpf_map_lookup_elem(&ch_ring, &ring_idx);
    if (!backend_id)
        return XDP_PASS;

    struct backend_info *backend = bpf_map_lookup_elem(&backends, backend_id);
    if (!backend)
        return XDP_PASS;

    // Backend marcado como down — pasar al stack (fallback)
    if (backend->flags != 0) {
        stats_increment(STATS_DROPS, 1);
        return XDP_PASS;
    }

    // --- Reescribir headers ---
    __u32 old_daddr = ip->daddr;
    ip->daddr = backend->ip;

    // Checksum incremental
    update_ip_checksum(ip, old_daddr, backend->ip);

    // Reescribir MAC destino
    __builtin_memcpy(eth->h_dest, backend->mac, 6);

    // --- Estadísticas ---
    __u32 pkt_len = data_end - data;
    stats_increment(STATS_PACKETS, 1);
    stats_increment(STATS_BYTES, pkt_len);

    // Stats por backend
    __u64 *bstats = bpf_map_lookup_elem(&backend_stats, backend_id);
    if (bstats)
        *bstats += 1;

    // --- Reenviar ---
    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
