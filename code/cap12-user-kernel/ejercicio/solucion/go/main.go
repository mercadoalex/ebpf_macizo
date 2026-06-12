// Capítulo 12 — Solución: Event Logger con Ring Buffer
//
// Este programa carga el event_logger BPF, lo adjunta a los tracepoints
// de execve y exit, y consume los eventos del ring buffer mostrándolos
// formateados en la terminal.
//
// Uso:
//   go generate ./...
//   go build -o event-logger .
//   sudo ./event-logger

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 eventlogger event_logger.bpf.c

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Tipos de evento — deben coincidir con los #define en el BPF.
const (
	EventExec = 1
	EventExit = 2
)

// Event corresponde a struct process_event en event_logger.bpf.c.
// El layout DEBE coincidir exactamente con la definición en C.
type Event struct {
	EventType   uint32
	PID         uint32
	PPID        uint32
	ExitCode    uint32
	TimestampNs uint64
	Comm        [16]byte
}

func main() {
	// Remover memlock.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Cargar objetos BPF.
	objs := eventloggerObjects{}
	if err := loadEventloggerObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando objetos BPF: %v", err)
	}
	defer objs.Close()

	// Adjuntar a tracepoint de execve.
	tpExec, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExec, nil)
	if err != nil {
		log.Fatalf("Error adjuntando trace_exec: %v", err)
	}
	defer tpExec.Close()

	// Adjuntar a tracepoint de exit.
	tpExit, err := link.Tracepoint("sched", "sched_process_exit", objs.TraceExit, nil)
	if err != nil {
		log.Fatalf("Error adjuntando trace_exit: %v", err)
	}
	defer tpExit.Close()

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Capítulo 12 — Solución: Event Logger con Ring Buffer")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// ─── Abrir el ring buffer reader ────────────────────────────────────────
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Error abriendo ring buffer reader: %v", err)
	}
	defer rd.Close()

	fmt.Println("  ✅ Event logger activo. Ctrl+C para salir.")
	fmt.Println()

	// ─── Manejar Ctrl+C ─────────────────────────────────────────────────────
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sig
		fmt.Println("\n  👋 Cerrando event logger...")
		rd.Close() // Interrumpe el Read() bloqueante.
	}()

	// ─── Loop de lectura de eventos ─────────────────────────────────────────
	for {
		record, err := rd.Read()
		if err != nil {
			// Reader cerrado (por signal handler o error).
			break
		}

		var evt Event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &evt); err != nil {
			log.Printf("  ⚠️  Error deserializando evento: %v", err)
			continue
		}

		printEvent(evt)
	}

	fmt.Println("  👋 Event logger terminado.")
}

// printEvent formatea y muestra un evento según su tipo.
func printEvent(evt Event) {
	comm := cString(evt.Comm[:])

	switch evt.EventType {
	case EventExec:
		fmt.Printf("  🟢 [EXEC] PID=%-6d PPID=%-6d comm=%s\n",
			evt.PID, evt.PPID, comm)
	case EventExit:
		fmt.Printf("  🔴 [EXIT] PID=%-6d exit_code=%-3d comm=%s\n",
			evt.PID, evt.ExitCode, comm)
	default:
		fmt.Printf("  ❓ [????] PID=%-6d type=%d comm=%s\n",
			evt.PID, evt.EventType, comm)
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
