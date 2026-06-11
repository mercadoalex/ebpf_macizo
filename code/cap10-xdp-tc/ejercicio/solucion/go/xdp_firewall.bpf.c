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

static __always_inline void increment_stat(__u32 index) {
    __u64 *count = bpf_map_lookup_elem(&stats, &index);
    if (count)
        __sync_fetch_and_add(count, 1);
}

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

    // ─── PASO 3: Lógica del firewall ──────────────────────
    __u32 src_ip = ip->saddr;

    // Buscar la IP en la blocklist
    __u64 *blocked = bpf_map_lookup_elem(&blocklist, &src_ip);
    if (blocked) {
        // IP está en la blocklist — incrementar contadores y dropear
        __sync_fetch_and_add(blocked, 1);
        increment_stat(1); // index 1 = dropped
        return XDP_DROP;
    }

    // IP no está bloqueada — dejar pasar
    increment_stat(0); // index 0 = passed
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
