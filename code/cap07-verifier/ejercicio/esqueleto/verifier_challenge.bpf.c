//go:build ignore

// verifier_challenge.bpf.c — Ejercicio Capítulo 7: Desafío del Verifier
//
// PROGRAMA: Contador de paquetes TCP por IP de origen (XDP)
//
// Este programa XDP tiene 3 ERRORES que hacen que el verifier lo
// rechace. Tu misión: encontrar los 3 errores, entender por qué
// el verifier los rechaza, y corregirlos.
//
// Los 3 errores son:
//   1. Falta bounds check en el header Ethernet antes de leer eth->h_proto
//   2. Dereferencia del resultado de bpf_map_lookup_elem sin null check
//   3. Struct packet_count sin inicialización completa (sin = {})
//
// PISTAS:
//   - Pista 1: El verifier necesita PRUEBA de que tus punteros
//     apuntan a memoria válida dentro del paquete.
//   - Pista 2: bpf_map_lookup_elem puede retornar NULL.
//   - Pista 3: Cuando pasas una struct a un helper, TODOS los
//     bytes deben estar inicializados.
//
// Compila con:
//   go generate && go build -o verifier-challenge
//   sudo ./verifier-challenge

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

    // ❌ ERROR 1: No hay bounds check para el header Ethernet.
    // El verifier no sabe si el paquete es lo suficientemente grande
    // para contener un header Ethernet completo.
    // ¿Qué falta aquí?

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

    // ❌ ERROR 2: Null dereference en map lookup.
    // bpf_map_lookup_elem puede retornar NULL si la key no existe.
    // ¿Qué pasa con el retorno de lookup?
    struct packet_count *counter = bpf_map_lookup_elem(&stats, &src_ip);
    counter->count += 1;
    counter->bytes += (data_end - data);

    // ❌ ERROR 3: Struct parcialmente inicializada.
    // ¿Qué tiene de malo este struct en el stack?
    // ¿Cuántos bytes tiene struct packet_count? ¿Cuántos inicializaste?
    struct packet_count new_entry;
    new_entry.count = 1;
    new_entry.bytes = (data_end - data);

    // Intenta copiar payload al campo last_payload
    int payload_len = data_end - (void *)(ip + 1);
    int copy_len = payload_len;
    if (copy_len > 256)
        copy_len = 256;

    bpf_probe_read_kernel(&new_entry.last_payload, copy_len,
                          (void *)(ip + 1));

    if (!counter) {
        bpf_map_update_elem(&stats, &src_ip, &new_entry, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
