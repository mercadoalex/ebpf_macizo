// Capítulo 4 — Hello World: Tu primer hook eBPF
//
// Este loader en Go demuestra el ciclo completo de un programa eBPF real:
// 1. Compila el programa BPF con bpf2go (via go generate)
// 2. Carga el programa en el kernel
// 3. Lo adjunta al tracepoint sys_enter_execve
// 4. Imprime instrucciones para ver la salida en trace_pipe
// 5. Espera a que el usuario lo detenga con Ctrl+C
//
// A diferencia del programa mínimo del Capítulo 3, este programa
// HACE algo observable: imprime el PID y nombre de cada proceso
// que ejecuta execve().

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
	// loadHelloObjects() es generada automáticamente por bpf2go
	// a partir de hello.bpf.c → hello_bpfel.go / hello_bpfeb.go
	objs := helloObjects{}
	if err := loadHelloObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando objetos BPF: %v", err)
	}
	defer objs.Close()

	// Adjuntar al tracepoint syscalls/sys_enter_execve.
	// Se dispara cada vez que un proceso llama a execve() — es decir,
	// cada vez que se ejecuta un programa nuevo.
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
	fmt.Println("   Cada vez que un proceso ejecute execve(), verás algo como:")
	fmt.Println("   <...>-12345 [001] d... 1234.567890: bpf_trace_printk: execve: PID=12345 COMM=ls")
	fmt.Println("")
	fmt.Println("   Prueba ejecutando comandos en otra terminal (ls, cat, etc.)")
	fmt.Println("   Presiona Ctrl+C para salir...")

	// Esperar señal de terminación
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\n👋 Programa BPF removido. Adiós.")
}
