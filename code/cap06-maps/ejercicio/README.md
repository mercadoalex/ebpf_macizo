# Ejercicio — Capítulo 6: Contador de Syscalls por Proceso

📋 **Nivel:** Intermedio
📚 **Conceptos previos:** Hash maps, `bpf_map_lookup_elem`, `bpf_map_update_elem`, cilium/ebpf en Go
🖥️ **Entorno:** VM o contenedor con kernel >= 5.10 y toolchain eBPF configurado (Capítulo 3)

## Problema

Implementar un **contador de syscalls por proceso** usando un hash map BPF.

Tu programa debe:
- Engancharse al tracepoint `raw_syscalls/sys_enter` para capturar TODAS las syscalls
- Mantener un hash map con clave = PID y valor = número de syscalls ejecutadas
- Desde Go, leer periódicamente el map y mostrar los procesos más activos

## Lo que vas a hacer

1. **Completar el programa BPF** (`esqueleto/bpf/syscall_counter.bpf.c`):
   - TODO 1: Obtener el PID del proceso actual
   - TODO 2: Buscar si el PID ya existe en el map
   - TODO 3: Incrementar el contador o insertar un nuevo entry

2. **Completar el consumer en Go** (`esqueleto/go/main.go`):
   - TODO 1: Iterar sobre las entradas del hash map
   - TODO 2: Mostrar los top 5 PIDs por número de syscalls

## Estructura del hash map

```
┌─────────────────────────────────────────┐
│ Hash Map: syscall_count                 │
│                                         │
│  Key (__u32)  │  Value (__u64)          │
│ ─────────────┼────────────────          │
│  PID 1234    │  4521 syscalls           │
│  PID 5678    │  128 syscalls            │
│  PID 999     │  89012 syscalls          │
│  ...         │  ...                     │
└─────────────────────────────────────────┘
```

## Criterios de éxito

- [ ] El programa BPF se carga sin errores del verifier
- [ ] El hash map se crea con key=u32, value=u64, max_entries=10240
- [ ] Cada syscall incrementa el contador del PID correspondiente
- [ ] El programa Go lee el map cada 3 segundos y muestra stats
- [ ] Se muestran los top 5 PIDs ordenados por cantidad de syscalls

## Pistas

1. `bpf_get_current_pid_tgid()` retorna un `__u64` — los 32 bits altos son el PID (TGID).
   Necesitas hacer `>> 32` para extraer el PID.

2. `bpf_map_lookup_elem(&map, &key)` retorna un puntero al valor, o `NULL` si la clave
   no existe. Siempre verifica contra NULL antes de usar el puntero.

3. Para incrementar atómicamente, usa `__sync_fetch_and_add(ptr, 1)` — necesario porque
   múltiples CPUs pueden ejecutar el programa BPF simultáneamente.

4. En Go, `map.Iterate()` te da un iterador sobre todas las entradas del hash map.
   Cada llamada a `iter.Next(&key, &value)` llena key y value con la siguiente entrada.

## Caso de prueba

Una vez que tu solución esté corriendo:

```bash
# En otra terminal, genera actividad:
for i in $(seq 1 100); do ls /tmp > /dev/null; done

# Tu programa debería mostrar el PID del shell con un conteo alto
```

## Si te atoras

Revisa la solución completa en `solucion/`. Pero intenta primero — la lógica del programa
BPF son ~10 líneas y la del consumer en Go son ~15 líneas.
