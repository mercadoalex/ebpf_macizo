// Capítulo 3 — Programa mínimo con cilium/ebpf
//
// Este loader en Go demuestra el flujo completo:
// 1. Compila el programa BPF con bpf2go (via go generate)
// 2. Carga el programa en el kernel
// 3. Lo adjunta al tracepoint sys_enter_execve
// 4. Espera a que el usuario lo detenga con Ctrl+C
//
// El programa BPF no hace nada — solo valida que el toolchain funciona end-to-end.

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 minimal minimal.bpf.c

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
	// loadMinimalObjects() es una función generada automáticamente.
	objs := minimalObjects{}
	if err := loadMinimalObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando objetos BPF: %v", err)
	}
	defer objs.Close()

	// Adjuntar el programa al tracepoint syscalls/sys_enter_execve.
	// Se dispara cada vez que un proceso hace execve() (ejecuta un programa nuevo).
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.MinimalProg, nil)
	if err != nil {
		log.Fatalf("Error adjuntando tracepoint: %v", err)
	}
	defer tp.Close()

	fmt.Println("✅ Programa BPF cargado y adjuntado exitosamente")
	fmt.Println("   Hook: tracepoint/syscalls/sys_enter_execve")
	fmt.Println("   (no hace nada, pero demuestra que el toolchain funciona)")
	fmt.Println("   Presiona Ctrl+C para salir...")

	// Esperar señal de terminación
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\n👋 Programa BPF removido. Adiós.")
}
