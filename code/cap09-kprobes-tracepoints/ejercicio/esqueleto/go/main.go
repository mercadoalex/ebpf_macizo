// Capítulo 9 — Ejercicio: Mini-opensnoop (Loader en Go - Esqueleto)
//
// INSTRUCCIONES:
// Completa los TODOs para implementar el loader que:
//   1. Adjunta kprobe y kretprobe a do_sys_openat2
//   2. Lee eventos del ring buffer
//   3. Imprime información de cada operación open()
//
// Una vez que completes los TODOs en el programa BPF y en este archivo:
//   1. cd go/
//   2. go generate ./...
//   3. go build -o opensnoop .
//   4. sudo ./opensnoop

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
// ¡Cuidado con el orden y tamaño de los campos!
type OpenEvent struct {
	PID      uint32
	UID      uint32
	DeltaNs  uint64
	Ret      int32
	Comm     [16]byte
	Filename [128]byte
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := opensnoopObjects{}
	if err := loadOpensnoopObjects(&objs, nil); err != nil {
		log.Fatalf("cargando objetos: %v", err)
	}
	defer objs.Close()

	// TODO 1: Adjuntar kprobe a do_sys_openat2
	// Pista:
	//   kp, err := link.Kprobe("do_sys_openat2", objs.TraceOpenEntry, nil)
	//   if err != nil {
	//       log.Fatalf("kprobe: %v", err)
	//   }
	//   defer kp.Close()

	// TODO 2: Adjuntar kretprobe a do_sys_openat2
	// Pista:
	//   krp, err := link.Kretprobe("do_sys_openat2", objs.TraceOpenExit, nil)
	//   if err != nil {
	//       log.Fatalf("kretprobe: %v", err)
	//   }
	//   defer krp.Close()

	// TODO 3: Crear reader del ring buffer
	// Pista:
	//   rd, err := ringbuf.NewReader(objs.Events)
	//   if err != nil {
	//       log.Fatalf("ring buffer: %v", err)
	//   }
	//   defer rd.Close()

	// TODO 4: Goroutine que cierra el reader al recibir señal
	// Pista:
	//   sig := make(chan os.Signal, 1)
	//   signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	//   go func() {
	//       <-sig
	//       rd.Close()
	//   }()

	fmt.Println("📡 Tracing openat... (Ctrl+C para salir)")
	fmt.Printf("%-8s %-16s %-6s %-10s %-6s %s\n",
		"PID", "COMM", "UID", "LATENCIA", "RET", "FILENAME")

	// TODO 5: Loop leyendo eventos del ring buffer
	// Pista:
	//   for {
	//       record, err := rd.Read()
	//       if err != nil {
	//           break
	//       }
	//       var event OpenEvent
	//       if err := binary.Read(bytes.NewReader(record.RawSample),
	//           binary.LittleEndian, &event); err != nil {
	//           continue
	//       }
	//       comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
	//       filename := string(bytes.TrimRight(event.Filename[:], "\x00"))
	//       fmt.Printf("%-8d %-16s %-6d %-10s %-6d %s\n",
	//           event.PID, comm, event.UID,
	//           fmt.Sprintf("%d µs", event.DeltaNs/1000),
	//           event.Ret, filename)
	//   }

	// Evitar warnings de imports no usados (quita estas líneas al implementar)
	_ = link.Kprobe
	_ = ringbuf.NewReader
	_ = binary.LittleEndian
	_ = bytes.NewReader
	_ = signal.Notify
	_ = syscall.SIGINT
	_ = os.Interrupt
}
