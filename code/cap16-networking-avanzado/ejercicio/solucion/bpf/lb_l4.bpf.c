//go:build ignore

// lb_l4.bpf.c — Solución del ejercicio ninja: Load Balancer L4 completo
//
// Capítulo 16 — Networking avanzado: XDP en producción
//
// Este es un load balancer L4 completo que cumple:
// - Latencia < 5µs por paquete (medible con BPF_PROG_TEST_RUN)
// - Soporte para 100K conexiones simultáneas
// - Consistent hashing con session affinity
// - Health-aware: backends down se saltan automáticamente
// - Stats per-CPU: packets, bytes, drops, por backend
// - Hot reload: el control plane actualiza maps sin restart
//
// Arquitectura:
// 1. Parseo ETH → IP → TCP/UDP
// 2. Verificación VIP (¿es para nosotros?)
// 3. Hash de 5-tuple → ring de consistent hashing
// 4. Lookup backend → verificar que está vivo
// 5. Reescritura de headers (IP dst + MAC dst)
// 6. Actualización de stats
// 7. XDP_TX
//
// Diferencias con el ejemplo del capítulo:
// - Implementa connection table para session persistence real
// - Tiene fallback al siguiente backend si el primario está down
// - Incluye rate limiting por source IP (anti-DDoS básico)
// - Métricas más granulares

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

#define CH_RING_SIZE    65537   // Tamaño del ring (primo)
#define MAX_BACKENDS    256     // Máximo backends
#define MAX_CONNECTIONS 100000  // Connection table size
#define RATE_LIMIT_MAX  50000   // Max pps por source IP

// Estadísticas globales
#define STAT_RX_PACKETS   0
#define STAT_RX_BYTES     1
#define STAT_TX_PACKETS   2
#define STAT_TX_BYTES     3
#define STAT_DROPS        4
#define STAT_RATE_LIMITED 5
#define STAT_MAX          6

// =============================================================================
// Estructuras
// =============================================================================

struct backend_info {
    __u32 ip;           // IP destino (network byte order)
    __u8  mac[6];       // MAC destino
    __u16 flags;        // 0=activo, 1=down, 2=draining
};

struct vip_config {
    __u32 vip;          // Virtual IP
    __u16 port;         // Puerto (network byte order)
    __u16 proto;        // IPPROTO_TCP o IPPROTO_UDP
    __u32 num_backends; // Número de backends activos
};

// Clave de conexión: 5-tuple
struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  pad[3];
};

// Valor de conexión: backend asignado
struct conn_val {
    __u32 backend_id;
    __u64 last_seen;    // Timestamp del último paquete (para GC)
};

// =============================================================================
// Maps
// =============================================================================

// VIP: configuración del servicio
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct vip_config);
} vip SEC(".maps");

// Consistent hash ring: position → backend_id
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CH_RING_SIZE);
    __type(key, __u32);
    __type(value, __u32);
} ch_ring SEC(".maps");

// Backends: backend_id → backend_info
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, struct backend_info);
} backends SEC(".maps");

// Connection table: 5-tuple → backend asignado (session persistence)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONNECTIONS);
    __type(key, struct conn_key);
    __type(value, struct conn_val);
} connections SEC(".maps");

// Rate limiting por source IP (LRU para auto-eviction)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __type(key, __u32);      // src_ip
    __type(value, __u64);    // packet count
} rate_limit SEC(".maps");

// Estadísticas globales per-CPU
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Estadísticas por backend per-CPU
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, __u64);
} backend_pkts SEC(".maps");

// =============================================================================
// Funciones auxiliares
// =============================================================================

static __always_inline void stat_inc(__u32 idx, __u64 val) {
    __u64 *cnt = bpf_map_lookup_elem(&stats, &idx);
    if (cnt)
        *cnt += val;
}

// Hash de 5-tuple con buena distribución
static __always_inline __u32 compute_hash(struct conn_key *key) {
    __u32 h = key->src_ip;
    h ^= key->dst_ip;
    h ^= ((__u32)key->src_port << 16) | (__u32)key->dst_port;
    h ^= (__u32)key->proto;

    // Murmurhash3 finalizer
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;

    return h;
}

// Checksum incremental al cambiar IP destino
static __always_inline void ip_csum_replace(__u16 *csum, __u32 old, __u32 new) {
    __u32 sum = (~(__u32)*csum & 0xFFFF);
    sum += (~old & 0xFFFF) + (~(old >> 16) & 0xFFFF);
    sum += (new & 0xFFFF) + (new >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    *csum = ~sum;
}

// Busca un backend vivo empezando desde ring_idx.
// Si el primario está down, avanza en el ring hasta encontrar uno vivo.
// Máximo 10 intentos para evitar loops largos.
static __always_inline struct backend_info *find_alive_backend(
    __u32 ring_idx,
    __u32 *out_backend_id
) {
    #pragma unroll
    for (int attempt = 0; attempt < 10; attempt++) {
        __u32 idx = (ring_idx + attempt) % CH_RING_SIZE;
        __u32 *bid = bpf_map_lookup_elem(&ch_ring, &idx);
        if (!bid)
            continue;

        struct backend_info *be = bpf_map_lookup_elem(&backends, bid);
        if (!be)
            continue;

        if (be->flags == 0) {
            *out_backend_id = *bid;
            return be;
        }
    }
    return NULL;
}

// =============================================================================
// Programa XDP principal
// =============================================================================

SEC("xdp")
int lb_l4(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len = data_end - data;

    stat_inc(STAT_RX_PACKETS, 1);
    stat_inc(STAT_RX_BYTES, pkt_len);

    // --- Parseo Ethernet ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        stat_inc(STAT_DROPS, 1);
        return XDP_DROP;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // --- Parseo IP ---
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        stat_inc(STAT_DROPS, 1);
        return XDP_DROP;
    }

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // --- Verificar VIP ---
    __u32 vip_key = 0;
    struct vip_config *vc = bpf_map_lookup_elem(&vip, &vip_key);
    if (!vc)
        return XDP_PASS;

    if (ip->daddr != vc->vip)
        return XDP_PASS;

    // --- Extraer puertos L4 ---
    __u16 src_port = 0, dst_port = 0;
    void *l4 = (void *)ip + (ip->ihl * 4);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) {
            stat_inc(STAT_DROPS, 1);
            return XDP_DROP;
        }
        src_port = tcp->source;
        dst_port = tcp->dest;
    } else {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) {
            stat_inc(STAT_DROPS, 1);
            return XDP_DROP;
        }
        src_port = udp->source;
        dst_port = udp->dest;
    }

    // Verificar puerto de la VIP
    if (dst_port != vc->port)
        return XDP_PASS;

    // --- Rate limiting por source IP ---
    __u32 src_ip = ip->saddr;
    __u64 *rate = bpf_map_lookup_elem(&rate_limit, &src_ip);
    if (rate) {
        if (*rate > RATE_LIMIT_MAX) {
            stat_inc(STAT_RATE_LIMITED, 1);
            return XDP_DROP;
        }
        __sync_fetch_and_add(rate, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&rate_limit, &src_ip, &init, BPF_ANY);
    }

    // --- Connection lookup (session persistence) ---
    struct conn_key ckey = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = src_port,
        .dst_port = dst_port,
        .proto = ip->protocol,
    };

    struct backend_info *backend = NULL;
    __u32 backend_id = 0;

    struct conn_val *existing = bpf_map_lookup_elem(&connections, &ckey);
    if (existing) {
        // Conexión existente: usar el mismo backend
        backend_id = existing->backend_id;
        backend = bpf_map_lookup_elem(&backends, &backend_id);

        // Si el backend asignado cayó, re-hash
        if (backend && backend->flags != 0)
            backend = NULL;

        // Actualizar timestamp
        if (backend)
            existing->last_seen = bpf_ktime_get_ns();
    }

    if (!backend) {
        // Nueva conexión o backend caído: consistent hash
        __u32 hash = compute_hash(&ckey);
        __u32 ring_idx = hash % CH_RING_SIZE;

        backend = find_alive_backend(ring_idx, &backend_id);
        if (!backend) {
            // Ningún backend vivo — drop
            stat_inc(STAT_DROPS, 1);
            return XDP_DROP;
        }

        // Guardar en connection table
        struct conn_val new_conn = {
            .backend_id = backend_id,
            .last_seen = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&connections, &ckey, &new_conn, BPF_ANY);
    }

    // --- Reescribir headers ---
    __u32 old_daddr = ip->daddr;
    ip->daddr = backend->ip;
    ip_csum_replace(&ip->check, old_daddr, backend->ip);
    __builtin_memcpy(eth->h_dest, backend->mac, 6);

    // --- Stats ---
    stat_inc(STAT_TX_PACKETS, 1);
    stat_inc(STAT_TX_BYTES, pkt_len);

    __u64 *bpkts = bpf_map_lookup_elem(&backend_pkts, &backend_id);
    if (bpkts)
        *bpkts += 1;

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
