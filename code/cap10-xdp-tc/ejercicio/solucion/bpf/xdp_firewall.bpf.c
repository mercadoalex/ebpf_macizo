//go:build ignore

// xdp_firewall.bpf.c — Solución: Firewall XDP con Blocklist (Capítulo 10)
//
// Programa eBPF completo que implementa un firewall XDP basado en
// una blocklist de IPs almacenada en un hash map. Las IPs bloqueadas
// se configuran desde user space.
//
// Flujo:
// 1. Parsear Ethernet + IP headers (con bounds checking)
// 2. Extraer IP de origen
// 3. Buscar en blocklist
// 4. DROP si está bloqueada, PASS si no
// 5. Mantener contadores globales y por IP
//
// Attach point: XDP hook en interfaz de red

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Map que contiene las IPs bloqueadas.
// Key: IP en network byte order (__u32)
// Value: contador de paquetes dropeados para esa IP (__u64)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} blocklist SEC(".maps");

// Map de estadísticas globales: index 0 = passed, index 1 = dropped
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

    // ─── PASO 3: Lógica del firewall ─────────────────────

    // Obtener la IP de origen (ya en network byte order)
    __u32 src_ip = ip->saddr;

    // Buscar en la blocklist
    __u64 *blocked = bpf_map_lookup_elem(&blocklist, &src_ip);

    if (blocked) {
        // IP está en la blocklist → DROP

        // Incrementar contador por IP
        __sync_fetch_and_add(blocked, 1);

        // Incrementar contador global de drops (index 1)
        __u32 key = 1;
        __u64 *drop_count = bpf_map_lookup_elem(&stats, &key);
        if (drop_count)
            __sync_fetch_and_add(drop_count, 1);

        return XDP_DROP;
    }

    // IP no está bloqueada → PASS

    // Incrementar contador global de passed (index 0)
    __u32 key = 0;
    __u64 *pass_count = bpf_map_lookup_elem(&stats, &key);
    if (pass_count)
        __sync_fetch_and_add(pass_count, 1);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
