# Ejercicio — Capítulo 10: Firewall XDP con Blocklist Dinámica

📋 **Nivel:** Intermedio
📚 **Conceptos previos:** Hash maps (Cap 6), bounds checking (Cap 7), helpers de maps (Cap 8)
🖥️ **Entorno:** Lab con Docker/Vagrant del Capítulo 3
🎯 **Problema:** Implementar un firewall XDP que bloquee tráfico entrante de IPs específicas usando un hash map como blocklist

## Contexto

Tienes un servidor que recibe tráfico de diversas fuentes. Quieres bloquear IPs específicas **antes** de que los paquetes lleguen al network stack. El blocklist se configura desde user space (puedes agregar y remover IPs en caliente).

## Lo que vas a hacer

1. **Completar el programa BPF** (`esqueleto/bpf/xdp_firewall.bpf.c`):
   - TODO 1: Obtener la IP de origen del paquete
   - TODO 2: Buscar la IP en el map "blocklist"
   - TODO 3: Si está bloqueada, incrementar contadores y retornar XDP_DROP
   - TODO 4: Si no está bloqueada, incrementar contador de passed y retornar XDP_PASS

2. **El loader en Go ya está completo** (`esqueleto/go/main.go`):
   - Carga el programa BPF
   - Puebla la blocklist con IPs de ejemplo
   - Adjunta XDP a la interfaz
   - Muestra stats cada 2 segundos

## Estructura de los maps

```
┌─────────────────────────────────────────┐
│ Hash Map: blocklist                     │
│                                         │
│  Key (__u32)       │  Value (__u64)     │
│ ──────────────────┼──────────────       │
│  192.168.1.100    │  42 (drops)        │
│  10.0.0.50        │  128 (drops)       │
│  ...              │  ...               │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│ Array Map: stats                        │
│                                         │
│  Index (__u32)  │  Value (__u64)        │
│ ───────────────┼──────────────          │
│  0 (passed)    │  15234                │
│  1 (dropped)   │  892                  │
└─────────────────────────────────────────┘
```

## Criterios de éxito

- [ ] El programa se carga sin errores del verifier
- [ ] Se adjunta a la interfaz de red exitosamente
- [ ] Paquetes de IPs en la blocklist son descartados (no llegan a la app)
- [ ] Paquetes de IPs no bloqueadas pasan normalmente
- [ ] Los contadores se actualizan correctamente (puedes verificar con el ticker de stats)
- [ ] Puedes agregar/remover IPs en caliente desde user space

## Pistas

1. La IP de origen está en `ip->saddr` — ya es un `__u32` en network byte order. No necesitas convertir antes de buscar en el map.
2. Para buscar en el map: `bpf_map_lookup_elem(&blocklist, &src_ip)`. Si retorna non-NULL, la IP está bloqueada.
3. Para incrementar contadores atómicamente, usa `__sync_fetch_and_add(pointer, 1)`.
4. No olvides que `bpf_map_lookup_elem` puede retornar NULL — el verifier te obliga a checkear antes de derreferenciar.

## Caso de prueba

```bash
# Terminal 1: Ejecutar el firewall
sudo ./firewall

# Terminal 2: Probar con ping desde la IP bloqueada
# (si la IP de tu máquina está en la blocklist)
ping <IP_del_servidor>
# Resultado esperado: 100% packet loss

# Terminal 3: Ver las stats
# Resultado esperado: el contador de "dropped" incrementa
```

## Si te atoras

Revisa la solución completa en `solucion/`. Pero intenta primero — la lógica del
programa BPF son ~15 líneas y usa patrones que ya conoces de los Capítulos 6 y 8.
