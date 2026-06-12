//go:build ignore

// xdp_firewall.bpf.c — Ejercicio: Firewall XDP con Blocklist (Capítulo 10)
//
// INSTRUCCIONES:
// Completa los TODOs para implementar un firewall XDP que:
// 1. Parsea el header Ethernet e IP (ya hecho)
// 2. Busca la IP de origen en una blocklist (hash map)
// 3. Descarta paquetes de IPs bloqueadas, deja pasar el resto
// 4. Mantiene contadores de paquetes passed/dropped
//
// Attach point: XDP hook en interfaz de red
// Maps: blocklist (hash), stats (array)

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

    // ─── PASO 3: TU CÓDIGO AQUÍ ──────────────────────────

    // TODO 1: Obtener la IP de origen del paquete.
    //
    // La IP de origen está en el campo ip->saddr.
    // Es un __u32 en network byte order — no necesitas convertir.
    //
    // __u32 src_ip = ???;

    // TODO 2: Buscar la IP en el map "blocklist".
    //
    // Usa bpf_map_lookup_elem(&blocklist, &src_ip).
    // Retorna un puntero __u64* al contador, o NULL si la IP
    // no está en la blocklist.
    //
    // __u64 *blocked = ???;

    // TODO 3: Si la IP está bloqueada (blocked != NULL):
    //   a) Incrementar el contador por IP: __sync_fetch_and_add(blocked, 1)
    //   b) Incrementar el contador global de drops en "stats" (index 1):
    //      - __u32 key = 1;
    //      - __u64 *drop_count = bpf_map_lookup_elem(&stats, &key);
    //      - if (drop_count) __sync_fetch_and_add(drop_count, 1);
    //   c) Retornar XDP_DROP

    // TODO 4: Si la IP NO está bloqueada:
    //   a) Incrementar el contador de passed en "stats" (index 0):
    //      - __u32 key = 0;
    //      - __u64 *pass_count = bpf_map_lookup_elem(&stats, &key);
    //      - if (pass_count) __sync_fetch_and_add(pass_count, 1);
    //   b) Retornar XDP_PASS

    return XDP_PASS; // Placeholder — reemplazar con tu lógica
}

char LICENSE[] SEC("license") = "GPL";
