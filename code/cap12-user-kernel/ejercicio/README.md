# Ejercicio — Capítulo 12: Event Logger con Ring Buffer

📋 **Nivel:** Intermedio
📚 **Conceptos previos:** Maps (Cap 6), Helper functions (Cap 8), Ring buffer (Cap 12 — forma moderna)
🖥️ **Entorno:** Lab con Docker/Vagrant del Capítulo 3
🎯 **Problema:** Implementar un event logger que envíe eventos estructurados del kernel a user space via ring buffer, con un consumer en Go que los procese.

## Contexto

Quieres construir un sistema de logging que capture eventos de procesos en tiempo real. El programa BPF captura `execve` y `exit` de procesos, empaqueta la información en un struct, y la envía via ring buffer. Tu consumer en Go lee esos eventos y los muestra formateados.

Este patrón (BPF produce → ring buffer → Go consume) es la base de herramientas como Tetragon, Falco, y prácticamente cualquier tool de observabilidad basada en eBPF.

## Lo que vas a hacer

1. **El programa BPF ya está completo** (`esqueleto/bpf/event_logger.bpf.c`):
   - Captura execve y exit de procesos
   - Empaqueta eventos con tipo, PID, timestamp, comm
   - Los envía via ring buffer

2. **Completar el consumer en Go** (`esqueleto/go/main.go`):
   - TODO 1: Abrir el ring buffer reader usando `ringbuf.NewReader()`
   - TODO 2: Leer eventos en un loop con `reader.Read()`
   - TODO 3: Deserializar el evento (binary.Read con la struct Event)
   - TODO 4: Formatear y mostrar el evento según su tipo (EXEC vs EXIT)

## Estructura del evento

```
┌─────────────────────────────────────────────────────────────────┐
│ struct process_event (enviado via ring buffer)                   │
│                                                                 │
│  Field           │ Type     │ Descripción                       │
│ ─────────────────┼──────────┼─────────────────────────────      │
│  event_type      │ __u32    │ 1=EXEC, 2=EXIT                   │
│  pid             │ __u32    │ PID del proceso                   │
│  ppid            │ __u32    │ PID del padre                     │
│  exit_code       │ __u32    │ Código de salida (solo EXIT)      │
│  timestamp_ns    │ __u64    │ Timestamp en nanosegundos         │
│  comm            │ char[16] │ Nombre del proceso                │
└─────────────────────────────────────────────────────────────────┘
```

## Criterios de éxito

- [ ] El programa BPF se carga sin errores del verifier
- [ ] Se adjunta exitosamente a los tracepoints de execve y sched_process_exit
- [ ] El consumer en Go abre el ring buffer y lee eventos
- [ ] Los eventos de EXEC muestran: tipo, PID, PPID, y nombre del comando
- [ ] Los eventos de EXIT muestran: tipo, PID, y código de salida
- [ ] El consumer se cierra limpiamente con Ctrl+C

## Pistas

1. Para abrir el ring buffer reader: `rd, err := ringbuf.NewReader(objs.Events)`
2. Para leer un evento: `record, err := rd.Read()` — bloquea hasta que haya un evento disponible.
3. Deserializar: `binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &evt)`
4. El tipo de evento está en `evt.EventType`: 1 = exec (proceso nuevo), 2 = exit (proceso termina).
5. No olvides cerrar el reader con `defer rd.Close()` y usar `rd.Close()` en el handler de señales para interrumpir el `Read()` bloqueante.

## Caso de prueba

```bash
# Terminal 1: Ejecutar el event logger
cd go/
go generate ./...
go build -o event-logger .
sudo ./event-logger

# Terminal 2: Generar eventos
ls            # → debería aparecer un evento EXEC para "ls"
sleep 1       # → evento EXEC para "sleep", luego evento EXIT
echo hola     # → evento EXEC para "echo"
```

Resultado esperado:
```
═══════════════════════════════════════════════════════════════
  Capítulo 12 — Ejercicio: Event Logger con Ring Buffer
═══════════════════════════════════════════════════════════════

  ✅ Event logger activo. Ctrl+C para salir.

  🟢 [EXEC] PID=12345  PPID=1000   comm=ls
  🟢 [EXEC] PID=12346  PPID=1000   comm=sleep
  🔴 [EXIT] PID=12346  exit_code=0  comm=sleep
  🟢 [EXEC] PID=12347  PPID=1000   comm=echo
  🔴 [EXIT] PID=12347  exit_code=0  comm=echo
```

<!-- [INSERTA IMAGEN AQUI: Captura mostrando el event logger corriendo y capturando eventos de procesos en tiempo real] -->

## Si te atoras

Revisa la solución completa en `solucion/`. El consumer en Go son ~40 líneas de código real.
La parte más importante es entender el flujo: BPF reserva → llena → submit → Go lee → deserializa.
