# Ejercicio Capítulo 10: Firewall XDP Básico

## Nivel: Intermedio

## Problema

Implementar un firewall XDP que bloquee tráfico entrante de IPs específicas
usando un hash map como blocklist. Las IPs se configuran desde user space y
pueden agregarse/removerse en caliente.

## Estructura

```
esqueleto/
├── bpf/
│   ├── Makefile
│   └── xdp_firewall.bpf.c    ← Programa BPF con parseo listo, falta la lógica
└── go/
    ├── go.mod
    ├── main.go                ← Loader en Go (completo)
    └── xdp_firewall.bpf.c    ← Copia para go generate

solucion/
├── bpf/
│   ├── Makefile
│   └── xdp_firewall.bpf.c    ← Solución completa
└── go/
    ├── go.mod
    ├── main.go                ← Loader con stats por IP
    └── xdp_firewall.bpf.c    ← Solución completa
```

## Qué debes implementar

En `esqueleto/bpf/xdp_firewall.bpf.c`, busca los comentarios `// TODO:` en el PASO 3.
Debes:

1. Obtener la IP de origen del paquete (`ip->saddr`)
2. Buscar la IP en el map `blocklist`
3. Si está: incrementar contadores y retornar `XDP_DROP`
4. Si no está: incrementar contador de passed y retornar `XDP_PASS`

## Conceptos requeridos

- Maps tipo hash (Capítulo 6)
- `bpf_map_lookup_elem` y `__sync_fetch_and_add` (Capítulo 8)
- Bounds checking (Capítulo 7)

## Compilar y ejecutar

```bash
cd esqueleto/go
go generate
go build -o firewall
sudo ./firewall
```

## Verificar

```bash
# En otra terminal, hacer ping desde una IP bloqueada
ping <IP_del_servidor>
# Resultado esperado: 100% packet loss si la IP de origen está en la blocklist
```
