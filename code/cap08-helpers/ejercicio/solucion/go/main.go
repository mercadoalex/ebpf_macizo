// Capítulo 8 — Solución: Medición de latencia de syscalls (Consumer en Go)
//
// Este programa carga el BPF que mide latencia de do_sys_openat2 y consume
// los eventos de latencia desde el ring buffer.
//
// Uso:
//   go generate ./...
//   go build -o latency .
//   sudo ./latency

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 latency latency.bpf.c

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// latencyEvent debe coincidir con el struct latency_event del programa BPF.
type latencyEvent struct {
	PID     uint32
	TID     uint32
	DeltaNs uint64
	Comm    [16]byte
}

func main() {
	// Cargar los objetos BPF generados por bpf2go.
	objs := latencyObjects{}
	if err := loadLatencyObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando objetos BPF: %v", err)
	}
	defer objs.Close()

	// Adjuntar kprobe a do_sys_openat2 (entrada de la función).
	kp, err := link.Kprobe("do_sys_openat2", objs.KprobeOpenat2, nil)
	if err != nil {
		log.Fatalf("Error adjuntando kprobe: %v", err)
	}
	defer kp.Close()

	// Adjuntar kretprobe a do_sys_openat2 (salida de la función).
	krp, err := link.Kretprobe("do_sys_openat2", objs.KretprobeOpenat2, nil)
	if err != nil {
		log.Fatalf("Error adjuntando kretprobe: %v", err)
	}
	defer krp.Close()

	// Crear reader del ring buffer.
	rd, err := ringbuf.NewReader(objs.Events, nil)
	if err != nil {
		log.Fatalf("Error creando reader del ring buffer: %v", err)
	}
	defer rd.Close()

	fmt.Println("✅ Programa de latencia cargado — midiendo do_sys_openat2()")
	fmt.Println("   Kprobe guarda timestamp de entrada, kretprobe calcula delta")
	fmt.Println("")
	fmt.Printf("%-8s %-8s %-16s %s\n", "PID", "TID", "COMM", "LATENCIA")
	fmt.Println("------------------------------------------------------")

	// Goroutine para cerrar el reader cuando llegue Ctrl+C.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n👋 Deteniendo...")
		rd.Close()
	}()

	// Loop de lectura de eventos del ring buffer.
	for {
		record, err := rd.Read()
		if err != nil {
			// Reader cerrado (Ctrl+C) — salimos limpiamente.
			break
		}

		// Deserializar el evento.
		var e latencyEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("Error parseando evento: %v", err)
			continue
		}

		// Extraer nombre como string limpio.
		comm := nullTermStr(e.Comm[:])

		// Formatear latencia de forma legible.
		latency := time.Duration(e.DeltaNs) * time.Nanosecond

		fmt.Printf("%-8d %-8d %-16s %v\n", e.PID, e.TID, comm, latency)
	}
}

// nullTermStr convierte un byte slice con null terminator a string Go.
func nullTermStr(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i == -1 {
		return string(b)
	}
	return string(b[:i])
}
