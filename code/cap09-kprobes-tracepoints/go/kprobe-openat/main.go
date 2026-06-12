// Capítulo 9 — Loader en Go: Kprobe en do_sys_openat2
//
// Este programa carga un kprobe que intercepta la función do_sys_openat2
// del kernel y registra qué archivos abre cada proceso via bpf_printk.
//
// Uso:
//   go generate ./...
//   go build -o kprobe-openat .
//   sudo ./kprobe-openat
//   # En otra terminal: sudo cat /sys/kernel/debug/tracing/trace_pipe

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 kprobe kprobe_openat.bpf.c

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Eliminar límite de memoria para BPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Cargar objetos BPF generados por bpf2go
	objs := kprobeObjects{}
	if err := loadKprobeObjects(&objs, nil); err != nil {
		log.Fatalf("cargando objetos BPF: %v", err)
	}
	defer objs.Close()

	// Adjuntar kprobe a do_sys_openat2
	kp, err := link.Kprobe("do_sys_openat2", objs.TraceOpenat, nil)
	if err != nil {
		log.Fatalf("adjuntando kprobe: %v", err)
	}
	defer kp.Close()

	fmt.Println("✅ Kprobe adjuntado a do_sys_openat2")
	fmt.Println("")
	fmt.Println("📡 Para ver la salida, abre otra terminal y ejecuta:")
	fmt.Println("   sudo cat /sys/kernel/debug/tracing/trace_pipe")
	fmt.Println("")
	fmt.Println("   Cada vez que un proceso abra un archivo, verás:")
	fmt.Println("   pid=<PID> open: <filename>")
	fmt.Println("")
	fmt.Println("   Presiona Ctrl+C para salir...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sig:
			fmt.Println("\n👋 Saliendo...")
			return
		case <-ticker.C:
			fmt.Println("... escuchando (Ctrl+C para salir)")
		}
	}
}
