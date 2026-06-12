// Capítulo 13 — Ejercicio Integrador: Process Lifecycle Monitor
//
// Este programa carga el process_monitor BPF, lo adjunta a los tracepoints
// de fork y exit, y consume los eventos del ring buffer mostrándolos
// en la terminal con estadísticas en tiempo real.
//
// TU TRABAJO: Implementar los TODOs para completar el monitor.
//
// Uso:
//   go generate ./...
//   go build -o process-monitor .
//   sudo ./process-monitor

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 processmonitor process_monitor.bpf.c

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Tipos de evento — deben coincidir con los #define en el BPF.
const (
	EventFork = 1
	EventExit = 2
)

// Event corresponde a struct event en process_monitor.bpf.c.
// El layout DEBE coincidir exactamente con la definición en C (incluyendo padding).
type Event struct {
	Type       uint8
	Pad1       [3]byte  // Padding después de type
	PID        uint32
	PPID       uint32
	Pad2       uint32   // Padding antes de timestamp
	Timestamp  uint64
	DurationNs uint64
	Comm       [16]byte
}

// Contador atómico de procesos activos observados.
var activeProcesses int64

func main() {
	// Remover memlock (necesario para cargar programas BPF).
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Process Lifecycle Monitor — Capítulo 13")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// ─────────────────────────────────────────────────────────────────────────
	// TODO 1: Cargar los objetos BPF.
	//
	// Usa loadProcessmonitorObjects() para cargar el programa compilado.
	// Asigna a una variable "objs" y maneja el error.
	// No olvides: defer objs.Close()
	//
	// Pista:
	//   objs := processmonitorObjects{}
	//   if err := loadProcessmonitorObjects(&objs, nil); err != nil {
	//       log.Fatalf("Error cargando objetos BPF: %v", err)
	//   }
	//   defer objs.Close()
	// ─────────────────────────────────────────────────────────────────────────

	// >>> TU CÓDIGO AQUÍ <<<

	// ─────────────────────────────────────────────────────────────────────────
	// TODO 2: Adjuntar a los tracepoints.
	//
	// Necesitas adjuntar a DOS tracepoints:
	//   a) "sched" / "sched_process_fork" → objs.HandleFork
	//   b) "sched" / "sched_process_exit" → objs.HandleExit
	//
	// Usa link.Tracepoint() para cada uno. Maneja errores y defer Close().
	//
	// Pista:
	//   tpFork, err := link.Tracepoint("sched", "sched_process_fork", objs.HandleFork, nil)
	//   tpExit, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleExit, nil)
	// ─────────────────────────────────────────────────────────────────────────

	// >>> TU CÓDIGO AQUÍ <<<
	_ = link.Tracepoint // Elimina esta línea cuando implementes el TODO

	// ─────────────────────────────────────────────────────────────────────────
	// TODO 3: Abrir el ring buffer reader.
	//
	// Usa ringbuf.NewReader() pasándole el map "Events" del objeto BPF.
	// Asigna a "rd" y maneja el error. defer rd.Close()
	//
	// Pista: rd, err := ringbuf.NewReader(objs.Events)
	// ─────────────────────────────────────────────────────────────────────────

	// >>> TU CÓDIGO AQUÍ <<<
	_ = ringbuf.NewReader // Elimina esta línea cuando implementes el TODO

	fmt.Println("  ✅ Monitor activo. Ctrl+C para salir.")
	fmt.Printf("  📊 Procesos activos observados: %d\n\n", atomic.LoadInt64(&activeProcesses))

	// Manejar Ctrl+C para salida limpia.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sig
		fmt.Println("\n  👋 Cerrando process monitor...")
		// TODO: Cerrar el reader aquí para interrumpir el Read() bloqueante.
		// rd.Close()
		os.Exit(0)
	}()

	// ─────────────────────────────────────────────────────────────────────────
	// TODO 4: Loop de lectura de eventos.
	//
	// Implementa un for loop infinito que:
	//   a) Llame a rd.Read() para obtener un record
	//   b) Maneje errores (si el reader se cierra, salir del loop)
	//   c) Deserialice el record.RawSample en un Event
	//   d) Llame a handleEvent(evt) para procesarlo
	//
	// Pista:
	//   for {
	//       record, err := rd.Read()
	//       if err != nil { break }
	//       var evt Event
	//       binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &evt)
	//       handleEvent(evt)
	//   }
	// ─────────────────────────────────────────────────────────────────────────

	// >>> TU CÓDIGO AQUÍ <<<
	_ = bytes.NewBuffer  // Elimina esta línea cuando implementes el TODO
	_ = binary.Read      // Elimina esta línea cuando implementes el TODO

	// Si llegas aquí sin implementar los TODOs, el programa termina inmediatamente.
	fmt.Println("  ⚠️  No implementaste los TODOs. Revisa el código.")
}

// handleEvent procesa un evento y actualiza estadísticas.
func handleEvent(evt Event) {
	comm := cString(evt.Comm[:])

	switch evt.Type {
	case EventFork:
		atomic.AddInt64(&activeProcesses, 1)
		fmt.Printf("  🍴 [FORK] PID=%-6d PPID=%-6d comm=%s\n",
			evt.PID, evt.PPID, comm)
	case EventExit:
		atomic.AddInt64(&activeProcesses, -1)
		if evt.DurationNs > 0 {
			fmt.Printf("  💀 [EXIT] PID=%-6d comm=%-16s duration=%s\n",
				evt.PID, comm, formatDuration(evt.DurationNs))
		} else {
			fmt.Printf("  💀 [EXIT] PID=%-6d comm=%-16s duration=unknown\n",
				evt.PID, comm)
		}
	default:
		fmt.Printf("  ❓ [????] PID=%-6d type=%d\n", evt.PID, evt.Type)
	}

	fmt.Printf("  📊 Procesos activos observados: %d\n", atomic.LoadInt64(&activeProcesses))
}

// formatDuration convierte nanosegundos a formato legible.
func formatDuration(ns uint64) string {
	d := time.Duration(ns) * time.Nanosecond
	switch {
	case d < time.Millisecond:
		return fmt.Sprintf("%.1fµs", float64(ns)/1000.0)
	case d < time.Second:
		return fmt.Sprintf("%.1fms", float64(ns)/1e6)
	case d < time.Minute:
		return fmt.Sprintf("%.3fs", float64(ns)/1e9)
	default:
		return fmt.Sprintf("%.1fmin", float64(ns)/6e10)
	}
}

// cString convierte un byte array C (NULL-terminated) a string Go.
func cString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return string(b[:n])
}
