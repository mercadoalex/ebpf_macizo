//go:build ignore

// xdp_redirect.bpf.c — Capítulo 16: XDP Redirect entre interfaces con devmap
//
// Programa XDP que demuestra el uso de bpf_redirect_map() con devmap
// para reenviar paquetes entre interfaces de red sin pasar por el
// kernel stack. Incluye un programa de egress que reescribe la MAC
// source en la interfaz de destino.
//
// Conceptos demostrados:
// - BPF_MAP_TYPE_DEVMAP para almacenar interfaces destino
// - bpf_redirect_map() para reenvío rápido
// - Programa XDP de egress en devmap (kernel >= 5.8)
// - Forwarding basado en IP destino
// - Estadísticas de redirect por interfaz
//
// Uso típico:
// - Router XDP entre VLANs
// - Bridge L2 de alta velocidad
// - Traffic splitting (mirror port)
//
// Attach point: XDP hook en interfaz de ingress

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// =============================================================================
// Estructuras
// =============================================================================

// Entrada de la tabla de routing: IP destino → interfaz de salida
struct route_entry {
    __u32 prefix;       // Network address
    __u32 prefixlen;    // Mask length
    __u32 devmap_idx;   // Index en el devmap
    __u8  next_hop_mac[6];  // MAC del next hop
    __u16 pad;
};

// MAC address de la interfaz local (para reescribir en egress)
struct mac_addr {
    __u8 addr[6];
    __u16 pad;
};

// =============================================================================
// Maps
// =============================================================================

// Devmap: almacena interfaces de destino para redirect.
// El control plane registra las interfaces con sus ifindex.
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 64);
    __type(key, __u32);       // index posicional
    __type(value, __u32);     // ifindex destino
} tx_port SEC(".maps");

// Tabla de routing simplificada: IP destino → info de routing
// En producción usarías LPM_TRIE, aquí usamos hash para claridad.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);               // IP destino (host order)
    __type(value, struct route_entry);
} routes SEC(".maps");

// MAC local de cada interfaz: devmap_idx → MAC de la interfaz
// Usado por el programa de egress para reescribir source MAC.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct mac_addr);
} local_macs SEC(".maps");

// Estadísticas de redirect per-CPU: devmap_idx → counter
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} redirect_stats SEC(".maps");

// Estadísticas globales
#define STATS_RX       0
#define STATS_REDIRECT 1
#define STATS_PASS     2
#define STATS_DROP     3
#define STATS_MAX      4

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_MAX);
    __type(key, __u32);
    __type(value, __u64);
} global_stats SEC(".maps");

// =============================================================================
// Helpers
// =============================================================================

static __always_inline void count_stat(__u32 idx) {
    __u64 *cnt = bpf_map_lookup_elem(&global_stats, &idx);
    if (cnt)
        *cnt += 1;
}

// =============================================================================
// Programa XDP de ingress: decide a dónde redirigir el paquete
// =============================================================================

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    count_stat(STATS_RX);

    // --- Parseo Ethernet ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        count_stat(STATS_DROP);
        return XDP_DROP;
    }

    // Solo IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        count_stat(STATS_PASS);
        return XDP_PASS;
    }

    // --- Parseo IP ---
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        count_stat(STATS_DROP);
        return XDP_DROP;
    }

    // --- Lookup en tabla de routing ---
    __u32 dst_ip = ip->daddr;
    struct route_entry *route = bpf_map_lookup_elem(&routes, &dst_ip);
    if (!route) {
        // No hay ruta para este destino: subir al stack del kernel
        count_stat(STATS_PASS);
        return XDP_PASS;
    }

    // --- Reescribir MAC destino con next-hop MAC ---
    __builtin_memcpy(eth->h_dest, route->next_hop_mac, 6);

    // --- Actualizar TTL ---
    if (ip->ttl <= 1) {
        // TTL expirado: dejar que el kernel genere ICMP Time Exceeded
        count_stat(STATS_PASS);
        return XDP_PASS;
    }

    // Decrementar TTL y actualizar checksum incrementalmente
    __u16 old_ttl = ip->ttl;
    ip->ttl -= 1;
    __u32 csum = (~(__u32)ip->check & 0xFFFF);
    csum += (~old_ttl & 0xFF) + ip->ttl;
    csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = ~csum;

    // --- Estadísticas de redirect ---
    __u32 dest_idx = route->devmap_idx;
    __u64 *rstat = bpf_map_lookup_elem(&redirect_stats, &dest_idx);
    if (rstat)
        *rstat += 1;

    count_stat(STATS_REDIRECT);

    // --- Redirect a la interfaz destino vía devmap ---
    return bpf_redirect_map(&tx_port, dest_idx, 0);
}

// =============================================================================
// Programa XDP de egress: se ejecuta en la interfaz destino antes de TX
// (requiere kernel >= 5.8 y devmap con programa asociado)
//
// Este programa reescribe la MAC source con la MAC de la interfaz
// de salida para que el paquete sea válido en la red destino.
// =============================================================================

SEC("xdp")
int xdp_egress_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    // Obtener la MAC de la interfaz de egress.
    // El ingress_ifindex nos dice de dónde viene — usamos egress ifindex
    // En práctica, el control plane asigna la MAC correcta por devmap_idx.
    __u32 egress_idx = ctx->egress_ifindex;

    // Buscar MAC local indexada por ifindex
    struct mac_addr *local = bpf_map_lookup_elem(&local_macs, &egress_idx);
    if (local)
        __builtin_memcpy(eth->h_source, local->addr, 6);

    return XDP_PASS;  // En egress, PASS = transmitir el paquete
}

char LICENSE[] SEC("license") = "GPL";
