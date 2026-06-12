// Capítulo 13 — Process Lifecycle Monitor (Implementación de referencia)
//
// Ejercicio integrador del Nivel Intermedio. Este programa Go es el
// consumer que lee eventos del ring buffer y muestra el ciclo de vida
// de procesos en tiempo real.
//
// Combina todos los conceptos del nivel:
//   - Carga de programas BPF (Cap 4)
//   - Adjuntar a tracepoints (Cap 9)
//   - Lectura de ring buffer (Cap 12)
//   - Formateo de eventos estructurados
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

	// ─── Cargar objetos BPF ─────────────────────────────────────────────────
	objs := processmonitorObjects{}
	if err := loadProcessmonitorObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando objetos BPF: %v", err)
	}
	defer objs.Close()

	// ─── Adjuntar a tracepoints ─────────────────────────────────────────────

	// sched/sched_process_fork — detecta creación de procesos.
	tpFork, err := link.Tracepoint("sched", "sched_process_fork", objs.HandleFork, nil)
	if err != nil {
		log.Fatalf("Error adjuntando handle_fork: %v", err)
	}
	defer tpFork.Close()

	// sched/sched_process_exit — detecta terminación de procesos.
	tpExit, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleExit, nil)
	if err != nil {
		log.Fatalf("Error adjuntando handle_exit: %v", err)
	}
	defer tpExit.Close()

	// ─── Abrir ring buffer reader ───────────────────────────────────────────
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Error abriendo ring buffer reader: %v", err)
	}
	defer rd.Close()

	fmt.Println("  ✅ Monitor activo. Ctrl+C para salir.")
	fmt.Printf("  📊 Procesos activos observados: %d\n\n", atomic.LoadInt64(&activeProcesses))

	// ─── Manejar Ctrl+C ─────────────────────────────────────────────────────
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sig
		fmt.Println("\n  👋 Cerrando process monitor...")
		rd.Close()
	}()

	// ─── Loop de lectura de eventos ─────────────────────────────────────────
	for {
		record, err := rd.Read()
		if err != nil {
			break
		}

		var evt Event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &evt); err != nil {
			log.Printf("  ⚠️  Error deserializando evento: %v", err)
			continue
		}

		handleEvent(evt)
	}

	fmt.Println("  👋 Process monitor terminado.")
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
