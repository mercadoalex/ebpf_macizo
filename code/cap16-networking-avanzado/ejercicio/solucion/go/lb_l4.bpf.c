//go:build ignore

// lb_l4.bpf.c — Copia para go generate (Ejercicio Cap 16 — Solución)
//
// Copia del programa BPF del load balancer L4 para compilación
// con bpf2go desde el directorio Go.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define CH_RING_SIZE    65537
#define MAX_BACKENDS    256
#define MAX_CONNECTIONS 100000
#define RATE_LIMIT_MAX  50000

#define STAT_RX_PACKETS   0
#define STAT_RX_BYTES     1
#define STAT_TX_PACKETS   2
#define STAT_TX_BYTES     3
#define STAT_DROPS        4
#define STAT_RATE_LIMITED 5
#define STAT_MAX          6

struct backend_info {
    __u32 ip;
    __u8  mac[6];
    __u16 flags;
};

struct vip_config {
    __u32 vip;
    __u16 port;
    __u16 proto;
    __u32 num_backends;
};

struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  pad[3];
};

struct conn_val {
    __u32 backend_id;
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct vip_config);
} vip SEC(".maps");

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
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONNECTIONS);
    __type(key, struct conn_key);
    __type(value, struct conn_val);
} connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __type(key, __u32);
    __type(value, __u64);
} rate_limit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32);
    __type(value, __u64);
} backend_pkts SEC(".maps");

static __always_inline void stat_inc(__u32 idx, __u64 val) {
    __u64 *cnt = bpf_map_lookup_elem(&stats, &idx);
    if (cnt)
        *cnt += val;
}

static __always_inline __u32 compute_hash(struct conn_key *key) {
    __u32 h = key->src_ip;
    h ^= key->dst_ip;
    h ^= ((__u32)key->src_port << 16) | (__u32)key->dst_port;
    h ^= (__u32)key->proto;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

static __always_inline void ip_csum_replace(__u16 *csum, __u32 old, __u32 new) {
    __u32 sum = (~(__u32)*csum & 0xFFFF);
    sum += (~old & 0xFFFF) + (~(old >> 16) & 0xFFFF);
    sum += (new & 0xFFFF) + (new >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    *csum = ~sum;
}

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

SEC("xdp")
int lb_l4(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len = data_end - data;

    stat_inc(STAT_RX_PACKETS, 1);
    stat_inc(STAT_RX_BYTES, pkt_len);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        stat_inc(STAT_DROPS, 1);
        return XDP_DROP;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        stat_inc(STAT_DROPS, 1);
        return XDP_DROP;
    }

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 vip_key = 0;
    struct vip_config *vc = bpf_map_lookup_elem(&vip, &vip_key);
    if (!vc)
        return XDP_PASS;

    if (ip->daddr != vc->vip)
        return XDP_PASS;

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

    if (dst_port != vc->port)
        return XDP_PASS;

    // Rate limiting
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

    // Connection lookup
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
        backend_id = existing->backend_id;
        backend = bpf_map_lookup_elem(&backends, &backend_id);
        if (backend && backend->flags != 0)
            backend = NULL;
        if (backend)
            existing->last_seen = bpf_ktime_get_ns();
    }

    if (!backend) {
        __u32 hash = compute_hash(&ckey);
        __u32 ring_idx = hash % CH_RING_SIZE;

        backend = find_alive_backend(ring_idx, &backend_id);
        if (!backend) {
            stat_inc(STAT_DROPS, 1);
            return XDP_DROP;
        }

        struct conn_val new_conn = {
            .backend_id = backend_id,
            .last_seen = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&connections, &ckey, &new_conn, BPF_ANY);
    }

    // Rewrite
    __u32 old_daddr = ip->daddr;
    ip->daddr = backend->ip;
    ip_csum_replace(&ip->check, old_daddr, backend->ip);
    __builtin_memcpy(eth->h_dest, backend->mac, 6);

    stat_inc(STAT_TX_PACKETS, 1);
    stat_inc(STAT_TX_BYTES, pkt_len);

    __u64 *bpkts = bpf_map_lookup_elem(&backend_pkts, &backend_id);
    if (bpkts)
        *bpkts += 1;

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
