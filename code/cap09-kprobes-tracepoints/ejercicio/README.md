# Ejercicio — Capítulo 9: Tracer de operaciones de filesystem (opensnoop)

📋 **Nivel:** Intermedio
📚 **Conceptos previos:** Kprobes y kretprobes (este capítulo), Hash maps (Capítulo 6), Ring buffer (Capítulo 8), Helper functions de contexto (Capítulo 8)
🖥️ **Entorno:** VM o contenedor con kernel 5.8+ y el lab del Capítulo 3
🎯 **Problema:** Construir una herramienta que registre qué archivos abre cada proceso, cuánto tiempo tarda la operación, y si tuvo éxito o falló.

## Lo que vas a hacer

Combinar:
- Un **kprobe** en la entrada de `do_sys_openat2` (para capturar el nombre del archivo)
- Un **kretprobe** en la salida de `do_sys_openat2` (para capturar el fd o error de retorno)
- Un **hash map** para correlacionar entrada con salida (usando TID como clave)
- Un **ring buffer** para enviar los eventos completos a user space

El resultado es un mini-`opensnoop` — una de las herramientas de tracing más útiles que existen.

## Lo que vas a completar

1. **Programa BPF** (`esqueleto/bpf/opensnoop.bpf.c`):
   - Completar el kprobe de entrada: guardar timestamp y leer filename
   - Completar el kretprobe de salida: calcular latencia, llenar evento, enviar por ring buffer

2. **Loader en Go** (`esqueleto/go/main.go`):
   - Adjuntar kprobe y kretprobe a `do_sys_openat2`
   - Crear reader del ring buffer
   - Loop de lectura e impresión de eventos

## Criterios de éxito

- [ ] El programa se carga sin errores del verifier
- [ ] Se adjuntan kprobe y kretprobe a `do_sys_openat2`
- [ ] Al ejecutar `ls`, `cat /etc/hostname`, o abrir cualquier archivo, aparecen eventos
- [ ] Los eventos muestran el nombre del archivo correcto
- [ ] La latencia está en un rango razonable (1-100 µs para archivos locales)
- [ ] Los archivos que fallan (no existen) muestran un valor de retorno negativo

## Pistas

1. El segundo argumento de `do_sys_openat2` es un puntero a string en user space. Usa `bpf_probe_read_user_str` (no `bpf_probe_read_kernel_str`) para leerlo.
2. El `struct start_data` es grande (>128 bytes). Decláralo como variable local — el verifier permite hasta ~512 bytes de stack. Si te da problemas, reduce `MAX_FILENAME_LEN`.
3. No olvides borrar la entrada del map `inflight` después de leerla en el kretprobe. Si no, el map crece indefinidamente.
4. En Go, el campo `Ret` necesita ser `int32` (no `uint32`) porque los errores son negativos.

## Caso de prueba

Con el programa corriendo:

```bash
# En otra terminal:
cat /etc/hostname
cat /archivo/que/no/existe
ls /tmp
```

Deberías ver:

```
Tracing openat... (Ctrl+C para salir)
PID      COMM             UID    LATENCIA   RET    FILENAME
5431     cat              1000   12 µs      3      /etc/hostname
5432     cat              1000   8 µs       -2     /archivo/que/no/existe
5433     ls               1000   15 µs      3      /tmp
```

El valor `-2` en RET corresponde a `ENOENT` (archivo no existe). Los fd positivos (3, 4, 5...) son file descriptors válidos.

## Si te atoras

Revisa la solución completa en `solucion/`. Pero intenta primero — el patrón kprobe + kretprobe con map intermedio es uno de los más importantes en tracing eBPF.
