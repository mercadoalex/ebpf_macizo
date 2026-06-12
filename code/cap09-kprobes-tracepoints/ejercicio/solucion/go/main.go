// Capítulo 9 — Solución: Mini-opensnoop (Loader en Go)
//
// Este programa carga los programas BPF de kprobe/kretprobe para
// interceptar do_sys_openat2 y mostrar cada operación open() con:
//   - PID y nombre del proceso
//   - UID del usuario
//   - Latencia de la operación
//   - Resultado (fd o error)
//   - Nombre del archivo
//
// Uso:
//   go generate ./...
//   go build -o opensnoop .
//   sudo ./opensnoop

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 opensnoop opensnoop.bpf.c

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

// OpenEvent mapea el struct open_event del programa BPF.
// Los campos deben coincidir exactamente en orden y tamaño.
type OpenEvent struct {
	PID      uint32
	UID      uint32
	DeltaNs  uint64
	Ret      int32
	Comm     [16]byte
	Filename [128]byte
}

func main() {
	// Eliminar límite de memoria para BPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Cargar objetos BPF
	objs := opensnoopObjects{}
	if err := loadOpensnoopObjects(&objs, nil); err != nil {
		log.Fatalf("cargando objetos: %v", err)
	}
	defer objs.Close()

	// Adjuntar kprobe a do_sys_openat2 (captura entrada: filename + timestamp)
	kp, err := link.Kprobe("do_sys_openat2", objs.TraceOpenEntry, nil)
	if err != nil {
		log.Fatalf("kprobe: %v", err)
	}
	defer kp.Close()

	// Adjuntar kretprobe a do_sys_openat2 (captura salida: fd/error + calcula latencia)
	krp, err := link.Kretprobe("do_sys_openat2", objs.TraceOpenExit, nil)
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

	// Goroutine que cierra el reader al recibir Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	fmt.Println("📡 Tracing openat... (Ctrl+C para salir)")
	fmt.Printf("%-8s %-16s %-6s %-10s %-6s %s\n",
		"PID", "COMM", "UID", "LATENCIA", "RET", "FILENAME")

	// Loop principal: leer eventos del ring buffer e imprimirlos
	for {
		record, err := rd.Read()
		if err != nil {
			break
		}

		var event OpenEvent
		if err := binary.Read(bytes.NewReader(record.RawSample),
			binary.LittleEndian, &event); err != nil {
			continue
		}

		comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
		filename := string(bytes.TrimRight(event.Filename[:], "\x00"))
		fmt.Printf("%-8d %-16s %-6d %-10s %-6d %s\n",
			event.PID, comm, event.UID,
			fmt.Sprintf("%d µs", event.DeltaNs/1000),
			event.Ret, filename)
	}

	fmt.Println("\n👋 Saliendo...")
}
