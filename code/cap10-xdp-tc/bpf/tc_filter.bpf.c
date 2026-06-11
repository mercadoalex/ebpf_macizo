//go:build ignore

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("classifier")
int tc_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parsear Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Solo IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // Parsear IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // Solo TCP
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // Parsear TCP
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    // Bloquear tráfico al puerto 8080
    if (bpf_ntohs(tcp->dest) == 8080) {
        bpf_printk("TC: bloqueando paquete a puerto 8080");
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
