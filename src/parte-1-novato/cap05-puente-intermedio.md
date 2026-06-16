# Capítulo 5: De novato a intermedio — El puente

> "Ya viste la luz al otro lado de la pared. Ahora toca escalar."

---

## Términos nuevos en este capítulo

Este capítulo no introduce términos nuevos. Es un punto de consolidación. Todos los términos que aparecen aquí fueron definidos en los capítulos 1-4. Si alguno te suena ajeno, vuelve atrás antes de continuar.

---

## Objetivos

Al terminar este capítulo vas a poder:

1. Articular con claridad los conceptos fundamentales de eBPF que ya dominas
2. Identificar exactamente qué limitaciones tiene lo que sabes hasta ahora
3. Entender qué herramientas y conceptos necesitas para escribir programas eBPF útiles de verdad

## Prerrequisitos

- Haber completado los capítulos 1 al 4 sin saltarte ninguno
- Tener tu laboratorio funcional (Capítulo 3)
- Haber ejecutado exitosamente el Hello World (Capítulo 4)

---

## Lo que ya sabes — Resumen ejecutivo del Nivel Novato

Paremos un momento. En cuatro capítulos pasaste de no saber qué era el kernel a tener un programa corriendo dentro de él. Eso no es trivial.

Esto es lo que ahora puedes hacer y explicar:

### El kernel y su arquitectura

Sabes que el kernel es el intermediario entre tu código y el hardware. Entiendes la separación entre user space y kernel space — no como algo abstracto, sino como una frontera real con consecuencias reales. Sabes que las system calls son el único canal legítimo para cruzar esa frontera, y usaste `strace` para observarlas en acción.

### El modelo eBPF

Entiendes que eBPF es una máquina virtual dentro del kernel que permite ejecutar código custom de forma segura. Conoces el pipeline completo:

1. Escribir código en C (lado BPF)
2. Compilar a bytecode con clang/LLVM
3. El verifier analiza tu programa
4. El JIT lo compila a instrucciones nativas
5. Se adjunta a un hook
6. Se ejecuta cada vez que el hook se dispara

Sabes que el verifier existe para garantizar que tu código no va a crashear el kernel. Sabes que hay diferentes tipos de programas y diferentes hooks donde adjuntarlos.

### El toolchain

Tienes un entorno funcional con:
- clang/LLVM para compilar código BPF
- Go con cilium/ebpf para el lado user space
- `bpftool` para inspeccionar programas cargados
- Un kernel con soporte eBPF habilitado

### Tu primer programa

Escribiste un programa BPF en C que se adjunta a un tracepoint, usaste `bpf_trace_printk` para generar output, cargaste ese programa desde Go con cilium/ebpf, y observaste la salida en `trace_pipe`.

El ciclo completo: escribir → compilar → cargar → adjuntar → observar.

> 💡 **Perspectiva**: Si puedes explicar estos cuatro bloques a otro desarrollador sin mirar notas, estás listo para el siguiente nivel. Si alguno te genera dudas, vuelve al capítulo correspondiente. No hay vergüenza en repasar.

---

## Lo que todavía no puedes hacer — Motivación para el siguiente nivel

Ahora las malas noticias. Lo que sabes es suficiente para entender eBPF conceptualmente y ejecutar programas de juguete. Pero no es suficiente para hacer nada útil en producción. Veamos las paredes:

### No tienes estado persistente

Tu programa Hello World se ejecuta, imprime algo, y se olvida de todo. No puede contar cuántas veces se disparó. No puede recordar qué PIDs vio antes. No puede acumular datos.

**¿Por qué?** Porque no sabes usar **maps** — las estructuras de datos que viven en kernel space y permiten a tu programa BPF almacenar información entre ejecuciones y compartirla con user space.

Sin maps, tu programa es un eco: entra un evento, sale un string, fin de la historia.

### No puedes comunicar datos estructurados

`bpf_trace_printk` es un mecanismo de debug. Imprime texto plano a un buffer compartido por todos los programas BPF del sistema. No escala. No es parseable de forma confiable. No sirve para producción.

**¿Qué necesitas?** Perf events y ring buffers — mecanismos diseñados para pasar datos estructurados del kernel al user space de forma eficiente y sin pérdida.

### El verifier te va a rechazar código real

En el Hello World, el verifier te dejó pasar porque tu programa era trivial. En cuanto intentes hacer algo no trivial — loops, acceso a estructuras del kernel, aritmética de punteros — el verifier va a decir que no.

**¿Qué necesitas?** Entender las reglas del verifier, los patrones que lo hacen feliz, y los trucos para escribir código que pase verificación sin sacrificar funcionalidad.

### Tu arsenal de funciones es patético

Solo conoces `bpf_trace_printk`. El kernel ofrece decenas de helper functions: obtener timestamps, leer memoria de procesos, manipular paquetes de red, interactuar con maps, generar números aleatorios, y mucho más.

**¿Qué necesitas?** Un tour por las helper functions organizadas por caso de uso, con la matriz de compatibilidad que te dice cuáles están disponibles en cada tipo de programa.

### No puedes instrumentar funciones específicas del kernel

Hasta ahora usaste un tracepoint genérico. Pero el poder real de eBPF está en poder engancharte a funciones específicas del kernel — kprobes, kretprobes, fentry/fexit — para observar exactamente lo que te interesa.

**¿Qué necesitas?** Entender los diferentes tipos de attach points, sus trade-offs de estabilidad, y cómo acceder a los argumentos de las funciones instrumentadas.

### Networking es territorio desconocido

XDP (eXpress Data Path) permite procesar paquetes de red antes de que lleguen al network stack del kernel. TC (Traffic Control) permite filtrar tráfico después. Ambos son casos de uso enormes de eBPF en producción — y no sabes nada de ellos.

**¿Qué necesitas?** Aprender a parsear headers de paquetes en eBPF, las acciones de XDP (PASS, DROP, REDIRECT), y cuándo usar XDP vs TC.

> 🔥 **Advertencia**: No intentes saltarte al Nivel Intermedio sin asegurarte de que tu base es sólida. Los capítulos 6-13 asumen que dominas todo lo anterior. Si te quedan dudas, resuelve las ahora. Después es más caro.

---

## El mapa de lo que viene — Preview del Nivel Intermedio

El Nivel Intermedio son 8 capítulos (6 al 13) que te llevan de "entiendo eBPF" a "puedo escribir programas eBPF útiles". Esta es la ruta:

```mermaid
graph TD
    subgraph "✅ Lo que ya sabes — Nivel Novato"
        A[Kernel y user/kernel space]
        B[Modelo eBPF y pipeline]
        C[Toolchain: clang + Go + bpftool]
        D[Hello World con tracepoints]
    end

    subgraph "🎯 Lo que vas a aprender — Nivel Intermedio"
        E[Cap 6: Maps — estado persistente]
        F[Cap 7: Verifier — reglas del juego]
        G[Cap 8: Helper functions — el arsenal]
        H[Cap 9: Kprobes y Tracepoints avanzados]
        I[Cap 10: XDP y TC — networking]
        J[Cap 11: Frameworks — cilium/ebpf, Aya]
        K[Cap 12: User ↔ Kernel — comunicación real]
        L[Cap 13: Puente a Ninja]
    end

    A --> E
    B --> F
    C --> J
    D --> E
    D --> H
    E --> G
    E --> K
    F --> G
    G --> H
    G --> I
    H --> K
    I --> J
    K --> L
```

### La secuencia tiene lógica

**Capítulo 6 (Maps)** va primero porque sin estado persistente no puedes hacer nada interesante. Todo lo demás depende de maps.

**Capítulo 7 (Verifier)** va segundo porque en cuanto empieces a escribir código real con maps y punteros, el verifier te va a detener. Mejor entenderlo temprano.

**Capítulo 8 (Helper functions)** amplía tu vocabulario de lo que puedes hacer dentro de un programa BPF.

**Capítulos 9 y 10 (Kprobes/Tracepoints y XDP/TC)** son los dos grandes dominios de aplicación: observabilidad y networking.

**Capítulo 11 (Frameworks)** es donde ves el ecosistema completo y por qué Go con cilium/ebpf es nuestra elección principal (y Aya como alternativa en Rust).

**Capítulo 12 (Comunicación User↔Kernel)** cierra el ciclo: datos estructurados fluyendo del kernel a tu aplicación de forma eficiente.

**Capítulo 13** es otro puente — como este — que te preparará para el Nivel Ninja.

### Lo que va a cambiar

A partir del Capítulo 6, los ejercicios ya no son paso a paso. Se te da un esqueleto de código con secciones marcadas como TODO, criterios de éxito para validar tu solución, y pistas parciales — pero no la solución completa.

Esto es intencional. En el Nivel Novato aprendiste siguiendo instrucciones. En el Nivel Intermedio empiezas a pensar por tu cuenta. Ese es el salto.

---

## Ejercicio integrador: Syscall Tracer — Tu primera herramienta de observabilidad

📋 **Nivel:** Novato (integración de Capítulos 1-4)
📚 **Conceptos:** Tracepoints, bpf_trace_printk, loader Go, ciclo completo de un programa eBPF
🖥️ **Entorno:** Tu laboratorio del Capítulo 3

### El reto

Construir un **syscall tracer** que muestre en tiempo real qué procesos están ejecutando qué syscalls. Es tu primera herramienta de observabilidad — primitiva, pero funcional.

A diferencia del Hello World (que solo registraba `execve`), este tracer va a cubrir múltiples syscalls y mostrar información útil de cada una.

### Requisitos funcionales

Tu tracer debe:

1. **Adjuntarse a 3 tracepoints de syscalls:** `sys_enter_openat` (apertura de archivos), `sys_enter_execve` (ejecución de programas), y `sys_enter_connect` (conexiones de red)
2. **Imprimir para cada evento:** nombre de la syscall, PID del proceso, y nombre del proceso (`comm`)
3. **Usar `bpf_trace_printk`** para generar la salida (sí, es debug — pero en este nivel es lo que tenemos)
4. **Cargarse y adjuntarse desde un loader en Go** usando cilium/ebpf
5. **Salir limpiamente con Ctrl+C** (signal handling en Go)

### Estructura esperada

```
code/cap05-puente/ejercicio/
├── esqueleto/
│   ├── bpf/
│   │   ├── syscall_tracer.bpf.c   ← Programa BPF (completar TODOs)
│   │   └── Makefile
│   └── go/
│       ├── main.go                 ← Loader Go (completar TODOs)
│       ├── go.mod
│       └── syscall_tracer.bpf.c    ← Copia para go generate
└── solucion/
    └── ...                         ← Implementación completa
```

### Esqueleto BPF (C)

```c
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// TODO: Programa 1 — Detectar apertura de archivos
// Adjuntar a: tracepoint/syscalls/sys_enter_openat
// Imprimir: "OPEN pid=%d comm=%s"
// Helpers necesarios: bpf_get_current_pid_tgid(), bpf_get_current_comm(), bpf_trace_printk()
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(void *ctx) {
    // TODO: Obtener PID (bpf_get_current_pid_tgid() >> 32)
    // TODO: Obtener comm (bpf_get_current_comm())
    // TODO: Imprimir con bpf_trace_printk()
    return 0;
}

// TODO: Programa 2 — Detectar ejecución de programas
// Adjuntar a: tracepoint/syscalls/sys_enter_execve
// Imprimir: "EXEC pid=%d comm=%s"
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx) {
    // TODO: Misma lógica que arriba, cambiando el prefijo a "EXEC"
    return 0;
}

// TODO: Programa 3 — Detectar conexiones de red
// Adjuntar a: tracepoint/syscalls/sys_enter_connect
// Imprimir: "CONNECT pid=%d comm=%s"
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(void *ctx) {
    // TODO: Misma lógica, prefijo "CONNECT"
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### Esqueleto User Space (Go)

```go
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 tracer syscall_tracer.bpf.c

import (
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

func main() {
    // TODO 1: Remover memlock (rlimit.RemoveMemlock())

    // TODO 2: Cargar objetos BPF (loadTracerObjects())
    //   No olvides defer objs.Close()

    // TODO 3: Adjuntar los 3 programas a sus tracepoints:
    //   link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
    //   link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
    //   link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnect, nil)
    //   No olvides defer para cada uno

    // TODO 4: Imprimir instrucciones al usuario
    fmt.Println("Syscall Tracer activo. Ver output con:")
    fmt.Println("  sudo cat /sys/kernel/debug/tracing/trace_pipe")
    fmt.Println("Ctrl+C para salir.")

    // TODO 5: Esperar señal de interrupción
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
    <-sig

    fmt.Println("\n👋 Tracer detenido.")
}
```

### Criterios de éxito

- [ ] Los 3 programas BPF compilan sin errores con clang
- [ ] Los 3 programas pasan el verifier al cargarse
- [ ] Se adjuntan correctamente a los 3 tracepoints
- [ ] Ejecutar `ls /tmp` genera al menos un evento "OPEN" y uno "EXEC" en trace_pipe
- [ ] Ejecutar `curl google.com` genera un evento "CONNECT"
- [ ] Cada evento muestra el PID y nombre del proceso correctos
- [ ] El programa sale limpiamente con Ctrl+C sin dejar hooks colgados

### Validación

```bash
# Terminal 1: ejecutar el tracer
sudo ./syscall-tracer

# Terminal 2: leer la salida
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Terminal 3: generar actividad
ls /tmp
cat /etc/hostname
curl -s google.com > /dev/null
```

**Resultado esperado en trace_pipe:**

```
 tracer-1234  [002] .... 5123.456: 0: EXEC pid=5678 comm=ls
 tracer-1234  [002] .... 5123.457: 0: OPEN pid=5678 comm=ls
 tracer-1234  [002] .... 5123.458: 0: OPEN pid=5678 comm=ls
 tracer-1234  [001] .... 5125.100: 0: EXEC pid=5680 comm=cat
 tracer-1234  [001] .... 5125.101: 0: OPEN pid=5680 comm=cat
 tracer-1234  [003] .... 5127.200: 0: EXEC pid=5682 comm=curl
 tracer-1234  [003] .... 5127.201: 0: CONNECT pid=5682 comm=curl
```

<!-- [INSERTA IMAGEN AQUI: Captura mostrando el syscall tracer corriendo en una terminal y trace_pipe mostrando eventos de OPEN, EXEC y CONNECT en otra terminal] -->

### Pistas

1. `bpf_get_current_pid_tgid()` retorna un `u64` donde los 32 bits superiores son el PID (shift >> 32)
2. `bpf_get_current_comm()` necesita un buffer de al menos 16 bytes
3. `bpf_trace_printk()` tiene un límite de 3 argumentos después del format string — planea tus prints con eso en mente
4. En Go, `loadTracerObjects()` es generado automáticamente por `go generate` — los nombres de los programas se derivan de los nombres de funciones C (TraceOpenat, TraceExecve, TraceConnect)
5. Si trace_pipe no muestra nada, verifica que no hay otro programa leyendo el mismo buffer

### ¿Por qué este ejercicio importa?

Este tracer, aunque usa `bpf_trace_printk` (que no es producción), demuestra que entiendes:

- **El kernel como fuente de datos** (Cap 1) — estás observando operaciones internas
- **El modelo eBPF** (Cap 2) — programa C compilado → verifier → hook → output
- **El toolchain** (Cap 3) — clang, Go, cilium/ebpf trabajando juntos
- **El ciclo completo** (Cap 4) — escribir, compilar, cargar, adjuntar, observar

Es lo mínimo que un developer debe poder hacer con eBPF. Si puedes construir esto sin ayuda, el Nivel Intermedio no te va a asustar.

---

## Ejercicio: Auto-evaluación — ¿Estás listo para el siguiente nivel?

📋 **Nivel:** Novato (consolidación)
📚 **Conceptos previos:** Capítulos 1-4 completos

### Checklist de conceptos

Marca cada punto que puedas explicar sin consultar el libro. Sé honesto — esto es para ti, no para nadie más.

**Kernel y arquitectura (Capítulo 1):**

- [ ] Puedo explicar qué hace el kernel y por qué existe la separación user/kernel space
- [ ] Puedo describir qué es una system call y por qué es necesaria
- [ ] Sé usar `strace` para ver qué syscalls hace un programa
- [ ] Puedo nombrar al menos 3 subsistemas del kernel (scheduler, networking, filesystem, memory)

**eBPF conceptual (Capítulo 2):**

- [ ] Puedo explicar la diferencia entre BPF clásico y eBPF
- [ ] Puedo describir el pipeline completo: escribir → compilar → verificar → JIT → adjuntar → ejecutar
- [ ] Sé qué hace el verifier y por qué es necesario
- [ ] Puedo nombrar al menos 3 tipos de hooks donde se adjuntan programas eBPF
- [ ] Puedo nombrar al menos 3 proyectos del ecosistema eBPF

**Toolchain (Capítulo 3):**

- [ ] Tengo un entorno funcional con clang/LLVM, Go, y bpftool
- [ ] Puedo compilar un programa BPF con clang y verificar que genera bytecode
- [ ] Puedo usar `bpftool prog list` para ver programas cargados en el kernel
- [ ] Entiendo por qué usamos Go con cilium/ebpf como stack principal

**Programación BPF (Capítulo 4):**

- [ ] Puedo escribir un programa BPF mínimo en C que se adjunte a un tracepoint
- [ ] Puedo escribir un loader en Go que cargue y adjunte ese programa
- [ ] Sé qué es `bpf_trace_printk` y puedo observar su output en trace_pipe
- [ ] Entiendo que trace_printk es solo para debug, no para producción
- [ ] Puedo identificar las dos partes de un programa eBPF: kernel side (C) y user space (Go)

### Evaluación

**16-18 puntos marcados:** Estás sólido. Avanza al Capítulo 6 con confianza.

<!-- [INSERTA IMAGEN AQUI: Diagrama visual tipo roadmap mostrando el camino del libro desde Novato (caps 1-5) hasta Intermedio (caps 6-13) y Ninja, con las dependencias entre conceptos] -->

**12-15 puntos:** Tienes gaps. Identifica qué capítulos necesitas repasar y dedícales 30 minutos antes de continuar.

**Menos de 12:** Vuelve a los capítulos 1-4. No es una derrota — es inversión. El Nivel Intermedio asume que todo esto es segunda naturaleza.

---

## Resumen

Lo que te llevas de este capítulo:

1. **Ya tienes una base real** — kernel, modelo eBPF, toolchain, y un programa funcional
2. **Lo que sabes no es suficiente** — sin maps, helper functions, y comunicación real kernel↔user, no puedes escribir programas útiles
3. **El Nivel Intermedio sigue un orden lógico** — maps primero, verifier segundo, luego se expande a dominios específicos
4. **Los ejercicios van a cambiar** — de paso a paso a esqueletos con TODOs. Tú completas la lógica
5. **La auto-evaluación es tu herramienta** — si hay gaps, es mejor resolverlos ahora que arrastrarlos

---

## Para saber más

- 📖 [eBPF Documentation — What is eBPF?](https://ebpf.io/what-is-ebpf/) — revisión rápida del modelo si necesitas refrescar conceptos
- 📝 [Brendan Gregg — BPF Performance Tools](https://www.brendangregg.com/bpf-performance-tools-book.html) — referencia complementaria con enfoque en observabilidad
- 💻 [cilium/ebpf — Getting Started](https://ebpf-go.dev/guides/getting-started/) — documentación oficial del framework que usamos, punto de partida para el Nivel Intermedio
