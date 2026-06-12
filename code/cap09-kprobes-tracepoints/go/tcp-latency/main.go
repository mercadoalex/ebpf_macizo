// Capítulo 9 — Loader en Go: Medición de latencia de tcp_connect
//
// Este programa usa kprobe + kretprobe para medir cuánto tarda
// cada llamada a tcp_connect() en el kernel. Emite eventos via
// ring buffer con PID, latencia, resultado y nombre del proceso.
//
// Uso:
//   go generate ./...
//   go build -o tcp-latency .
//   sudo ./tcp-latency
//   # En otra terminal: curl https://example.com

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 tcpLatency tcp_latency.bpf.c

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

// Event mapea el struct event del programa BPF.
// Los campos deben coincidir en orden y tamaño con el struct en C.
type Event struct {
	PID     uint32
	_       [4]byte // padding para alinear delta_ns a 8 bytes
	DeltaNs uint64
	Ret     int64
	Comm    [16]byte
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := tcpLatencyObjects{}
	if err := loadTcpLatencyObjects(&objs, nil); err != nil {
		log.Fatalf("cargando objetos: %v", err)
	}
	defer objs.Close()

	// Adjuntar kprobe a tcp_connect (entrada)
	kp, err := link.Kprobe("tcp_connect", objs.TraceTcpConnectEntry, nil)
	if err != nil {
		log.Fatalf("kprobe: %v", err)
	}
	defer kp.Close()

	// Adjuntar kretprobe a tcp_connect (salida)
	krp, err := link.Kretprobe("tcp_connect", objs.TraceTcpConnectExit, nil)
	if err != nil {
		log.Fatalf("kretprobe: %v", err)
	}
	defer krp.Close()

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

	fmt.Println("📡 Midiendo latencia de tcp_connect... (Ctrl+C para salir)")
	fmt.Printf("%-8s %-16s %-12s %s\n", "PID", "COMM", "LATENCIA", "RESULTADO")

	for {
		record, err := rd.Read()
		if err != nil {
			break
		}

		var event Event
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			continue
		}

		comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
		resultado := "OK"
		if event.Ret < 0 {
			resultado = fmt.Sprintf("ERROR(%d)", event.Ret)
		}
		fmt.Printf("%-8d %-16s %-12s %s\n",
			event.PID, comm,
			fmt.Sprintf("%d µs", event.DeltaNs/1000),
			resultado)
	}

	fmt.Println("\n👋 Saliendo...")
}
