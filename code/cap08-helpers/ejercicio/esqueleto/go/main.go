// Capítulo 8 — Ejercicio: Medición de latencia de syscalls (Consumer en Go)
//
// Este consumer lee eventos de latencia del ring buffer y los imprime.
//
// TU TRABAJO: completar los TODOs para leer y mostrar los eventos de latencia
// que el programa BPF envía al ring buffer.
//
// Una vez que completes tanto el programa BPF (bpf/latency.bpf.c) como este consumer:
//   1. cd go/
//   2. go generate ./...
//   3. go build -o latency .
//   4. sudo ./latency

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
// El orden y tamaño de los campos importa — si no coincide, leerás basura.
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

	// TODO 1: Adjuntar el kprobe a do_sys_openat2.
	//
	// Usa link.Kprobe() para adjuntar objs.KprobeOpenat2 a "do_sys_openat2".
	// Firma: link.Kprobe(symbol string, prog *ebpf.Program, opts *link.KprobeOptions) (link.Link, error)
	//
	// No olvides: defer kp.Close()

	// TODO 2: Adjuntar el kretprobe a do_sys_openat2.
	//
	// Usa link.Kretprobe() para adjuntar objs.KretprobeOpenat2 a "do_sys_openat2".
	// Firma: link.Kretprobe(symbol string, prog *ebpf.Program, opts *link.KretprobeOptions) (link.Link, error)
	//
	// No olvides: defer krp.Close()

	// TODO 3: Crear un reader del ring buffer.
	//
	// Usa ringbuf.NewReader(objs.Events, nil).
	// Esto te da un *ringbuf.Reader que puedes usar para leer eventos.
	//
	// No olvides: defer rd.Close()

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
		// TODO 4: Cerrar el reader del ring buffer aquí para que el loop termine.
		// rd.Close()
		os.Exit(0)
	}()

	// TODO 5: Loop de lectura de eventos del ring buffer.
	//
	// Estructura del loop:
	//   for {
	//       record, err := rd.Read()
	//       if err != nil { break }
	//
	//       var e latencyEvent
	//       binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e)
	//
	//       comm := nullTermStr(e.Comm[:])
	//       latency := time.Duration(e.DeltaNs) * time.Nanosecond
	//
	//       fmt.Printf(...)
	//   }

	// Placeholders para que compile — reemplaza con tu implementación.
	_ = bytes.NewBuffer(nil)
	_ = binary.LittleEndian
	_ = time.Nanosecond
	_ = link.Kprobe
	_ = ringbuf.NewReader
	_ = log.Printf
	select {}
}

// nullTermStr convierte un byte slice con null terminator a string Go.
func nullTermStr(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i == -1 {
		return string(b)
	}
	return string(b[:i])
}
