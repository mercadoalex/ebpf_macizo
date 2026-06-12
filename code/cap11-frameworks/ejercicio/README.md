# Ejercicio — Capítulo 11: Extender el Contador XDP (Conteo por IP Destino)

📋 **Nivel:** Intermedio
📚 **Conceptos previos:** Hash maps (Cap 6), bounds checking (Cap 7), XDP (Cap 10), cilium/ebpf (Cap 11)
🖥️ **Entorno:** Lab con Docker/Vagrant del Capítulo 3
🎯 **Problema:** Extender el programa de referencia para contar paquetes por IP de destino usando un hash map

## Contexto

El programa de referencia de este capítulo cuenta paquetes por protocolo (TCP, UDP, ICMP, otro) usando un array map. Eso está bien para clasificación general, pero en la vida real quieres saber **quién recibe más tráfico** — es decir, contar paquetes por IP de destino.

Tu trabajo: extender el programa XDP para que además de contar por protocolo, también cuente paquetes por IP de destino en un hash map.

## Lo que vas a hacer

1. **Completar el programa BPF** (`esqueleto/bpf/xdp_ip_counter.bpf.c`):
   - TODO 1: Declarar el hash map para conteo por IP destino
   - TODO 2: Extraer la IP de destino del header IP
   - TODO 3: Buscar o crear la entrada en el hash map
   - TODO 4: Incrementar el contador

2. **Completar el loader en Go** (`esqueleto/go/main.go`):
   - TODO 1: Iterar sobre el hash map de IPs para mostrar las stats
   - TODO 2: Convertir la IP de network byte order a formato legible

## Estructura de los maps

```
┌─────────────────────────────────────────┐
│ Array Map: proto_stats (ya implementado)│
│                                         │
│  Index (__u32)  │  Value (__u64)        │
│ ───────────────┼──────────────          │
│  0 (TCP)       │  12345                │
│  1 (UDP)       │  6789                 │
│  2 (ICMP)      │  42                   │
│  3 (Otro)      │  5                    │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│ Hash Map: ip_stats (TÚ LO IMPLEMENTAS) │
│                                         │
│  Key (__u32)        │  Value (__u64)    │
│ ──────────────────┼──────────────       │
│  192.168.1.1       │  5432 (pkts)      │
│  10.0.0.1          │  2341 (pkts)      │
│  172.16.0.5        │  891 (pkts)       │
└─────────────────────────────────────────┘
```

## Criterios de éxito

- [ ] El programa se carga sin errores del verifier
- [ ] Se adjunta a la interfaz de red exitosamente
- [ ] Los contadores por protocolo siguen funcionando (no romper lo existente)
- [ ] Se muestra un conteo de paquetes por IP de destino
- [ ] Las IPs se muestran en formato legible (e.g., "192.168.1.1")
- [ ] El hash map no crece sin límite (usa max_entries razonable, e.g., 1024)

## Pistas

1. La IP de destino está en `ip->daddr` — es un `__u32` en network byte order.
2. Para el hash map, el patrón "lookup or init" es:
   ```c
   __u64 *count = bpf_map_lookup_elem(&ip_stats, &dst_ip);
   if (count) {
       __sync_fetch_and_add(count, 1);
   } else {
       __u64 init_val = 1;
       bpf_map_update_elem(&ip_stats, &dst_ip, &init_val, BPF_ANY);
   }
   ```
3. En Go, para iterar sobre un hash map usa `objs.IpStats.Iterate()`.
4. Para convertir un `uint32` en network byte order a IP legible:
   ```go
   ip := make(net.IP, 4)
   binary.BigEndian.PutUint32(ip, key)
   fmt.Println(ip.String())
   ```

## Caso de prueba

```bash
# Terminal 1: Ejecutar el programa
sudo ./ip-counter lo

# Terminal 2: Generar tráfico
ping -c 5 127.0.0.1
curl http://127.0.0.1/

# Terminal 1: Resultado esperado
# 📊 Proto: TCP=3 | UDP=0 | ICMP=10 | Otro=0
# 📊 Top IPs destino:
#    127.0.0.1 → 13 paquetes
```

## Si te atoras

Revisa la solución completa en `solucion/`. Pero intenta primero — son ~10 líneas
extra en el BPF y ~20 líneas en el loader Go.
