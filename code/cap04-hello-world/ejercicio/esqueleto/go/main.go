// Capítulo 4 — Ejercicio: Execve Tracer (Loader en Go)
//
// Este loader ya está completo. Tu trabajo es completar el programa BPF
// en bpf/hello.bpf.c (los TODOs).
//
// Una vez que completes el programa BPF:
//   1. cd go/
//   2. go generate ./...
//   3. go build -o hello .
//   4. sudo ./hello

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 hello hello.bpf.c

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
)

func main() {
	// Cargar los objetos BPF generados por bpf2go.
	objs := helloObjects{}
	if err := loadHelloObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando objetos BPF: %v", err)
	}
	defer objs.Close()

	// Adjuntar al tracepoint syscalls/sys_enter_execve.
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HelloExecve, nil)
	if err != nil {
		log.Fatalf("Error adjuntando tracepoint: %v", err)
	}
	defer tp.Close()

	fmt.Println("✅ Programa BPF cargado y adjuntado exitosamente")
	fmt.Println("   Hook: tracepoint/syscalls/sys_enter_execve")
	fmt.Println("")
	fmt.Println("📡 Para ver la salida del programa BPF, abre otra terminal y ejecuta:")
	fmt.Println("   sudo cat /sys/kernel/debug/tracing/trace_pipe")
	fmt.Println("")
	fmt.Println("   Prueba ejecutando comandos en otra terminal (ls, cat, etc.)")
	fmt.Println("   Presiona Ctrl+C para salir...")

	// Esperar señal de terminación
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\n👋 Programa BPF removido. Adiós.")
}
