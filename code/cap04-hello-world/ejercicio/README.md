# Ejercicio — Capítulo 4: Execve Tracer

📋 **Nivel:** Novato
📚 **Conceptos previos:** Tracepoints, bpf_printk, carga de programas con cilium/ebpf
🖥️ **Entorno:** VM o contenedor con kernel >= 5.10 y toolchain eBPF configurado (Capítulo 3)

## Objetivo

Escribir un programa eBPF que se adjunte al tracepoint `sys_enter_execve` y, cada vez
que un proceso ejecute un nuevo programa, imprima:

```
execve: PID=<pid> COMM=<nombre_del_proceso>
```

en `/sys/kernel/debug/tracing/trace_pipe`.

## Lo que vas a hacer

1. **Completar el programa BPF** (`esqueleto/bpf/hello.bpf.c`): rellenar los `TODO`
   donde se deben usar las helper functions:
   - `bpf_get_current_pid_tgid()` — para obtener el PID
   - `bpf_get_current_comm()` — para obtener el nombre del proceso
   - `bpf_printk()` — para imprimir al trace_pipe

2. **El loader en Go ya está completo** — no necesitas modificarlo.
   Solo revísalo para entender cómo carga y adjunta el programa.

## Instrucciones paso a paso

### Paso 1: Abre el esqueleto del programa BPF

```bash
cd ejercicio/esqueleto/bpf/
cat hello.bpf.c
```

Verás tres secciones marcadas con `// TODO:`. Tu trabajo es completarlas.

### Paso 2: Completa los TODOs

1. **TODO 1:** Obtener el PID del proceso actual usando `bpf_get_current_pid_tgid()`.
   Recuerda que esta función retorna un `__u64` donde los 32 bits altos son el PID (TGID).
   Necesitas hacer `>> 32` para extraer el PID.

2. **TODO 2:** Obtener el nombre del proceso usando `bpf_get_current_comm()`.
   Esta función recibe un puntero al buffer y el tamaño. El buffer debe ser `char[16]`.

3. **TODO 3:** Imprimir con `bpf_printk()` en el formato: `"execve: PID=%d COMM=%s"`

### Paso 3: Compila el programa BPF

```bash
make
```

Si compila sin errores, tu programa C está bien escrito sintácticamente.

### Paso 4: Genera el código Go y ejecuta

```bash
cd ../go/
go generate ./...
go build -o hello .
sudo ./hello
```

### Paso 5: Verifica la salida

En otra terminal:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Ejecuta comandos como `ls`, `cat /etc/hostname`, etc. y deberías ver líneas como:
```
<...>-12345 [001] d... 1234.567890: bpf_trace_printk: execve: PID=12345 COMM=ls
```

## Resultado esperado

- El programa se carga sin errores del verifier ✓
- Se adjunta al tracepoint `sys_enter_execve` ✓
- Cada `execve()` produce una línea en trace_pipe con PID y COMM ✓
- Ctrl+C en el loader termina limpiamente ✓

## Si te atoras

Revisa la solución completa en `solucion/`. Pero intenta primero — son solo 3 líneas
de código las que tienes que escribir.

## ¿Por qué este ejercicio?

Este es el patrón fundamental de eBPF: engancharte a un evento del kernel,
extraer información del contexto, y reportarla. Todo lo que viene después en el libro
son variaciones más sofisticadas de este mismo ciclo.
