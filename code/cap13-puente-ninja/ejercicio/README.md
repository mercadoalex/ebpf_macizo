# Ejercicio Integrador — Capítulo 13: Process Lifecycle Monitor

📋 **Nivel:** Intermedio (consolidación de todo el nivel)
📚 **Conceptos previos:** Maps (Cap 6), Helpers (Cap 8), Tracepoints (Cap 9), Ring buffer (Cap 12)
🖥️ **Entorno:** Lab con Docker/Vagrant del Capítulo 3, kernel 5.8+
🎯 **Problema:** Construir un tool de observabilidad completo que combine TODAS las piezas del Nivel Intermedio.

## Contexto

Este es el ejercicio integrador del Nivel Intermedio. No introduce nada nuevo — solo combina lo que ya sabes de formas que no habías combinado. Si puedes completarlo sin consultar los capítulos anteriores, estás listo para el Nivel Ninja.

Vas a crear un **process lifecycle monitor**: una herramienta que trackea la creación y destrucción de procesos en tiempo real, reportando estadísticas y eventos al user space.

## Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                     KERNEL SPACE (C)                             │
│                                                                 │
│  ┌─────────────────────┐     ┌─────────────────────────────┐   │
│  │ tp/sched/            │     │ Hash Map: process_info_map  │   │
│  │ sched_process_fork   │────▶│  key: pid (__u32)           │   │
│  │                      │     │  val: {start_time, comm}    │   │
│  └─────────┬────────────┘     └──────────────┬──────────────┘   │
│            │                                 │                   │
│            │ emit FORK event                 │ lookup + delete   │
│            ▼                                 ▼                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │ Ring Buffer: events (256KB)                              │    │
│  │  struct event { type, pid, ppid, timestamp,              │    │
│  │                 duration_ns, comm }                       │    │
│  └───────────────────────────┬─────────────────────────────┘    │
│                              │                                   │
│  ┌─────────────────────┐     │                                   │
│  │ tp/sched/            │     │                                   │
│  │ sched_process_exit   │─────┘ emit EXIT event (con duración)   │
│  └─────────────────────┘                                         │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                     USER SPACE (Go)                              │
│                                                                 │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │ Ring Buffer       │  │ Stats            │  │ Terminal     │  │
│  │ Consumer          │─▶│ Aggregator       │─▶│ Output       │  │
│  └──────────────────┘  └──────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Lo que vas a hacer

### Lado kernel (BPF en C):

1. **Definir maps** — Un hash map para guardar info de procesos activos + un ring buffer para emitir eventos
2. **handle_fork** — Cuando se crea un proceso: registrar PID/timestamp/comm en el map, emitir evento FORK por ring buffer
3. **handle_exit** — Cuando un proceso termina: buscar en el map, calcular duración de vida, eliminar del map, emitir evento EXIT con duración

### Lado user space (Go):

1. **Cargar y adjuntar** — Cargar el programa BPF y adjuntar a los tracepoints
2. **Ring buffer consumer** — Leer eventos del ring buffer en un loop
3. **Formatear output** — Mostrar FORK y EXIT con formato legible, incluyendo duración en formato humano para exits
4. **Stats** — Mantener un contador de procesos activos (fork incrementa, exit decrementa)

## Estructura del evento

```c
struct event {
    __u8  type;         // EVENT_FORK=1, EVENT_EXIT=2
    __u32 pid;          // PID del proceso
    __u32 ppid;         // PID del padre (en fork)
    __u64 timestamp;    // Timestamp del evento
    __u64 duration_ns;  // Duración de vida en ns (solo EXIT, 0 si desconocido)
    char  comm[16];     // Nombre del proceso
};
```

**Nota:** Hay padding implícito en esta struct. El layout real en memoria tiene padding después de `type` para alinear `pid`. La struct en Go debe reflejar esto.

## Criterios de éxito

- [ ] El programa BPF se carga sin errores del verifier
- [ ] Se adjunta a `sched_process_fork` y `sched_process_exit`
- [ ] Al hacer fork (ejecutar cualquier comando) aparece un evento FORK con PID y comm
- [ ] Al terminar un proceso aparece un evento EXIT con PID, comm y duración
- [ ] La duración se muestra en formato legible (ms, s, min)
- [ ] El hash map se limpia correctamente (no hay memory leak)
- [ ] El consumer se cierra limpiamente con Ctrl+C
- [ ] Se muestra un contador de procesos activos observados

## Caso de prueba

```bash
# Terminal 1: Ejecutar el monitor
cd go/
go generate ./...
go build -o process-monitor .
sudo ./process-monitor

# Terminal 2: Generar eventos
sleep 2 &       # → FORK, luego EXIT con duration ~2s
ls              # → FORK, EXIT rápido (< 50ms)
cat /dev/null   # → FORK, EXIT rápido
```

Resultado esperado:
```
═══════════════════════════════════════════════════════════════
  Process Lifecycle Monitor — Capítulo 13
═══════════════════════════════════════════════════════════════

  ✅ Monitor activo. Ctrl+C para salir.
  📊 Procesos activos observados: 0

  🍴 [FORK] PID=4521  PPID=1200  comm=sleep
  📊 Procesos activos observados: 1
  🍴 [FORK] PID=4522  PPID=1200  comm=ls
  📊 Procesos activos observados: 2
  💀 [EXIT] PID=4522  comm=ls       duration=12.3ms
  📊 Procesos activos observados: 1
  🍴 [FORK] PID=4523  PPID=1200  comm=cat
  📊 Procesos activos observados: 2
  💀 [EXIT] PID=4523  comm=cat      duration=3.1ms
  📊 Procesos activos observados: 1
  💀 [EXIT] PID=4521  comm=sleep    duration=2.001s
  📊 Procesos activos observados: 0
```

<!-- [INSERTA IMAGEN AQUI: Captura mostrando el process lifecycle monitor corriendo, con eventos FORK y EXIT apareciendo en tiempo real mientras se ejecutan comandos en otra terminal] -->

## Si te atoras

Revisa la solución completa en `solucion/`. El concepto clave es:
- **Fork**: guardar info en map + emitir evento → el map funciona como "registro de nacimiento"
- **Exit**: buscar en map + calcular duración + eliminar + emitir evento → el map se autolimpia

Si el proceso se creó antes de cargar el programa, no estará en el map. Eso es normal — simplemente emites el EXIT sin duración (duration_ns = 0).
