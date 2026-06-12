//go:build ignore

// xdp_lb.bpf.c — Copia para go generate (Capítulo 16)
//
// Este archivo es una copia del programa BPF para que bpf2go pueda
// compilarlo directamente desde el directorio Go. El código fuente
// canónico está en ../bpf/xdp_lb.bpf.c

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define CH_RING_SIZE 65537
#define MAX_BACKENDS 1024

#define STATS_PACKETS  0
#define STATS_BYTES    1
#define STATS_DROPS    2
#define STATS_MAX      3

struct backend_info {
    __u32 ip;
    __u8  mac[6];
    __u16 flags;
};

struct vip_info {
    __u32 vip;
    __u16 port;
    __u16 proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CH_RING_SIZE);
    __type(key, __u32);
    __type(value, __u32);
} ch_ring SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, struct backend_info);
} backends SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct vip_info);
} vip_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, __u64);
} backend_stats SEC(".maps");

static __always_inline void stats_increment(__u32 idx, __u64 value) {
    __u64 *counter = bpf_map_lookup_elem(&stats, &idx);
    if (counter)
        *counter += value;
}

static __always_inline __u32 hash_5tuple(
    __u32 src_ip, __u32 dst_ip,
    __u16 src_port, __u16 dst_port,
    __u8 proto
) {
    __u32 hash = src_ip;
    hash ^= dst_ip;
    hash ^= ((__u32)src_port << 16) | (__u32)dst_port;
    hash ^= (__u32)proto;

    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;

    return hash;
}

static __always_inline void update_ip_checksum(
    struct iphdr *ip,
    __u32 old_addr,
    __u32 new_addr
) {
    __u32 sum = (~(__u32)ip->check & 0xFFFF);
    sum += (~old_addr & 0xFFFF) + (~(old_addr >> 16) & 0xFFFF);
    sum += (new_addr & 0xFFFF) + (new_addr >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    ip->check = ~sum;
}

SEC("xdp")
int xdp_lb(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        stats_increment(STATS_DROPS, 1);
        return XDP_DROP;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        stats_increment(STATS_DROPS, 1);
        return XDP_DROP;
    }

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 vip_key = 0;
    struct vip_info *vip = bpf_map_lookup_elem(&vip_config, &vip_key);
    if (!vip)
        return XDP_PASS;

    if (ip->daddr != vip->vip)
        return XDP_PASS;

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
    } else {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) {
            stats_increment(STATS_DROPS, 1);
            return XDP_DROP;
        }
        src_port = udp->source;
        dst_port = udp->dest;
    }

    if (dst_port != vip->port)
        return XDP_PASS;

    __u32 hash = hash_5tuple(ip->saddr, ip->daddr, src_port, dst_port, ip->protocol);
    __u32 ring_idx = hash % CH_RING_SIZE;

    __u32 *backend_id = bpf_map_lookup_elem(&ch_ring, &ring_idx);
    if (!backend_id)
        return XDP_PASS;

    struct backend_info *backend = bpf_map_lookup_elem(&backends, backend_id);
    if (!backend)
        return XDP_PASS;

    if (backend->flags != 0) {
        stats_increment(STATS_DROPS, 1);
        return XDP_PASS;
    }

    __u32 old_daddr = ip->daddr;
    ip->daddr = backend->ip;
    update_ip_checksum(ip, old_daddr, backend->ip);
    __builtin_memcpy(eth->h_dest, backend->mac, 6);

    __u32 pkt_len = data_end - data;
    stats_increment(STATS_PACKETS, 1);
    stats_increment(STATS_BYTES, pkt_len);

    __u64 *bstats = bpf_map_lookup_elem(&backend_stats, backend_id);
    if (bstats)
        *bstats += 1;

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
