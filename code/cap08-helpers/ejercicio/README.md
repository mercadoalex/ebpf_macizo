# Ejercicio — Capítulo 8: Medir latencia de syscalls con bpf_ktime_get_ns

📋 **Nivel:** Intermedio
📚 **Conceptos previos:** Helper functions (bpf_ktime_get_ns, bpf_get_current_pid_tgid, bpf_get_current_comm), hash maps, ring buffer, kprobes
🖥️ **Entorno:** VM o contenedor con kernel >= 5.10 y toolchain eBPF configurado (Capítulo 3)

## Objetivo

Medir la latencia (duración) de la syscall `openat2` usando kprobes y la helper
function `bpf_ktime_get_ns()`. El resultado es la latencia en nanosegundos
de cada llamada, reportada al user space via ring buffer.

## 🎯 Problema

Necesitas saber cuánto tarda el kernel en resolver cada llamada a `openat2` —
la syscall que está detrás de `open()`, `fopen()`, y cualquier apertura de archivo.

La estrategia es:
1. **kprobe** en la entrada de `do_sys_openat2`: guardar timestamp en un hash map (key = TID)
2. **kretprobe** en la salida de `do_sys_openat2`: recuperar timestamp, calcular delta, enviar al ring buffer

## Lo que vas a hacer

### Parte 1: Programa BPF (`esqueleto/bpf/latency.bpf.c`)

Completar 10 TODOs en el programa BPF:
- Definir el hash map para timestamps (TODO 1)
- Definir el ring buffer para eventos (TODO 2)
- En el kprobe: obtener TID, timestamp, guardar en map (TODOs 3-5)
- En el kretprobe: lookup, calcular delta, enviar evento, cleanup (TODOs 6-10)

### Parte 2: Consumer en Go (`esqueleto/go/main.go`)

Completar 5 TODOs en el consumer:
- Adjuntar kprobe y kretprobe (TODOs 1-2)
- Crear reader del ring buffer (TODO 3)
- Cerrar reader en signal handler (TODO 4)
- Implementar loop de lectura de eventos (TODO 5)

## Instrucciones

### Paso 1: Completa el programa BPF

```bash
cd esqueleto/bpf/
# Edita latency.bpf.c — completa los 10 TODOs
```

### Paso 2: Verifica que compila

```bash
make
```

Si ves `✓ Compilado: latency.bpf.c → latency.bpf.o`, tu código C es correcto
sintácticamente (el verifier lo validará al cargar).

### Paso 3: Completa el consumer en Go

```bash
cd ../go/
# Edita main.go — completa los 5 TODOs
```

### Paso 4: Genera código y compila

```bash
go generate ./...
go build -o latency .
```

### Paso 5: Ejecuta

```bash
sudo ./latency
```

### Paso 6: Genera tráfico en otra terminal

```bash
ls /tmp
cat /etc/hostname
find /usr -name "*.h" | head -5
```

Cada operación de archivo dispara `openat2` y deberías ver líneas con la latencia medida.

## Resultado esperado

```
✅ Programa de latencia cargado — midiendo do_sys_openat2()
   Kprobe guarda timestamp de entrada, kretprobe calcula delta

PID      TID      COMM             LATENCIA
------------------------------------------------------
1234     1234     ls               45.123µs
1235     1235     cat              12.891µs
1236     1236     find             8.456µs
```

## Criterios de éxito

- [ ] El programa BPF se carga sin errores del verifier
- [ ] El kprobe y kretprobe se adjuntan exitosamente a `do_sys_openat2`
- [ ] Cada apertura de archivo genera un evento con PID, TID, nombre del proceso y latencia
- [ ] La latencia reportada es razonable (microsegundos, no 0 ni valores absurdos)
- [ ] El hash map se limpia después de cada medición (no acumula entradas viejas)
- [ ] Ctrl+C termina limpiamente sin errores

## Pistas

1. `bpf_get_current_pid_tgid()` retorna un `__u64`. Los 32 bits bajos son el TID — úsalo como key del map.

2. Para el hash map, la sintaxis BTF es:
   ```c
   struct {
       __uint(type, BPF_MAP_TYPE_HASH);
       __uint(max_entries, 10240);
       __type(key, __u32);
       __type(value, __u64);
   } start_time SEC(".maps");
   ```

3. `bpf_map_lookup_elem` retorna un puntero o NULL. **Siempre** verifica NULL antes de dereferenciarlo — el verifier lo rechaza si no lo haces.

4. En Go, `link.Kprobe()` y `link.Kretprobe()` tienen la misma firma. El primer argumento es el nombre del símbolo del kernel (`"do_sys_openat2"`).

5. El ring buffer reader en Go bloquea en `rd.Read()` hasta que hay un evento. Ciérralo con `rd.Close()` para desbloquearlo limpiamente.

## Si te atoras

Revisa la solución completa en `solucion/`. Pero intenta primero — el patrón
kprobe+kretprobe+hashmap es uno de los más usados en observabilidad con eBPF,
y este ejercicio te da la base para medir latencia de cualquier función del kernel.

## ¿Por qué este ejercicio?

El patrón de medir latencia con kprobe/kretprobe + hash map + ring buffer es
**el patrón fundamental de tracing con eBPF**. Herramientas como `funclatency`
de bcc-tools y los tracers de Cilium usan exactamente esta estrategia.

Dominar este patrón te permite medir la latencia de cualquier función del kernel:
syscalls, operaciones de disco, locks, scheduling, networking — lo que necesites.
