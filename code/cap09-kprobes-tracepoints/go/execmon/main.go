// Capítulo 9 — Loader en Go: Monitor de procesos nuevos (tracepoint)
//
// Este programa usa el tracepoint sched/sched_process_exec para detectar
// cada vez que un proceso ejecuta exec(). Muestra PID, PPID, UID y nombre.
//
// Uso:
//   go generate ./...
//   go build -o execmon .
//   sudo ./execmon
//   # En otra terminal: ejecuta ls, cat, etc.

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 execmon execmon.bpf.c

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

// ExecEvent mapea el struct exec_event del programa BPF.
type ExecEvent struct {
	PID  uint32
	PPID uint32
	UID  uint32
	Comm [16]byte
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := execmonObjects{}
	if err := loadExecmonObjects(&objs, nil); err != nil {
		log.Fatalf("cargando objetos: %v", err)
	}
	defer objs.Close()

	// Adjuntar al tracepoint sched/sched_process_exec
	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceExec, nil)
	if err != nil {
		log.Fatalf("tracepoint: %v", err)
	}
	defer tp.Close()

	// Crear reader del ring buffer
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ring buffer: %v", err)
	}
	defer rd.Close()

	// Goroutine que cierra el reader al recibir señal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	fmt.Println("📡 Monitoreando procesos nuevos... (Ctrl+C para salir)")
	fmt.Printf("%-8s %-8s %-6s %s\n", "PID", "PPID", "UID", "COMM")

	for {
		record, err := rd.Read()
		if err != nil {
			break
		}

		var event ExecEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			continue
		}

		comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
		fmt.Printf("%-8d %-8d %-6d %s\n", event.PID, event.PPID, event.UID, comm)
	}

	fmt.Println("\n👋 Saliendo...")
}
