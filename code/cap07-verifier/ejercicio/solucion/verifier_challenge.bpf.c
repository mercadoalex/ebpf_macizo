//go:build ignore

// verifier_challenge.bpf.c — SOLUCIÓN del ejercicio Capítulo 7
//
// PROGRAMA: Contador de paquetes TCP por IP de origen (XDP)
//
// Versión corregida con los 3 errores del verifier resueltos:
//   1. ✅ Bounds check en header Ethernet antes de acceder a eth->h_proto
//   2. ✅ Null check en resultado de bpf_map_lookup_elem
//   3. ✅ Struct packet_count inicializada con = {} antes de pasarla a helper
//
// Este programa:
// - Parsea paquetes entrantes (Ethernet → IP → TCP)
// - Cuenta paquetes TCP por IP de origen en un hash map
// - Almacena los primeros 256 bytes de payload por IP

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Estructura para estadísticas por IP
struct packet_count {
    __u64 count;
    __u64 bytes;
    char last_payload[256];
};

// Map: IP de origen → estadísticas
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct packet_count);
} stats SEC(".maps");

SEC("xdp")
int count_tcp_packets(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // --- Parsear header Ethernet ---
    struct ethhdr *eth = data;

    // ✅ FIX 1: Bounds check para el header Ethernet.
    // Verificamos que el paquete es lo suficientemente grande
    // para contener un header Ethernet completo antes de accederlo.
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // --- Parsear header IP ---
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    // Solo TCP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // ✅ FIX 2: Null check en map lookup.
    // Si la key existe, actualizamos. Si no, creamos entrada nueva.
    struct packet_count *counter = bpf_map_lookup_elem(&stats, &src_ip);
    if (counter) {
        // IP ya conocida — actualizar contadores
        counter->count += 1;
        counter->bytes += (data_end - data);
    }

    // ✅ FIX 3: Inicializar la struct completa con = {}.
    // Zero initialization garantiza que TODOS los 272 bytes
    // (8 + 8 + 256) están definidos antes de pasar a helpers.
    // Sin esto, last_payload tendría basura del stack.
    struct packet_count new_entry = {};
    new_entry.count = 1;
    new_entry.bytes = (data_end - data);

    // Copiar payload (ahora es seguro porque last_payload está a ceros)
    int payload_len = data_end - (void *)(ip + 1);
    int copy_len = payload_len;
    if (copy_len > 256)
        copy_len = 256;
    if (copy_len > 0)
        bpf_probe_read_kernel(&new_entry.last_payload, copy_len,
                              (void *)(ip + 1));

    // Solo insertar si es una IP nueva (counter == NULL)
    if (!counter) {
        bpf_map_update_elem(&stats, &src_ip, &new_entry, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
