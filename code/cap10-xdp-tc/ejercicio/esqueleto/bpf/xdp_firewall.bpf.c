//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Map que contiene las IPs bloqueadas
// Key: IP en network byte order (__u32)
// Value: contador de paquetes dropeados (__u64)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} blocklist SEC(".maps");

// Map de estadísticas: index 0 = passed, index 1 = dropped
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // ─── PASO 1: Parsear Ethernet header ───────────────────
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    // Solo IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // ─── PASO 2: Parsear IP header ────────────────────────
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    // ─── PASO 3: TU CÓDIGO AQUÍ ──────────────────────────
    // TODO: Obtener la IP de origen del paquete (ip->saddr)
    // TODO: Buscar la IP en el map "blocklist" con bpf_map_lookup_elem
    // TODO: Si está en la blocklist:
    //         - Incrementar el contador de drops en "stats" (index 1)
    //           Usa: __u32 key = 1;
    //                __u64 *count = bpf_map_lookup_elem(&stats, &key);
    //                if (count) __sync_fetch_and_add(count, 1);
    //         - Incrementar el contador por IP en "blocklist"
    //           (el value del lookup ya es un puntero al contador)
    //         - Retornar XDP_DROP
    // TODO: Si NO está en la blocklist:
    //         - Incrementar el contador de passed en "stats" (index 0)
    //         - Retornar XDP_PASS

    return XDP_PASS; // Placeholder — reemplazar con tu lógica
}

char LICENSE[] SEC("license") = "GPL";
