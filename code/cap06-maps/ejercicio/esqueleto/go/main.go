// Capítulo 6 — Ejercicio: Contador de Syscalls por Proceso (Consumer en Go)
//
// INSTRUCCIONES:
// Este loader carga el programa BPF y lo adjunta al tracepoint.
// Tu trabajo es completar los 2 TODOs en la función readMap() para:
//   1. Iterar sobre las entradas del hash map
//   2. Mostrar los top 5 PIDs ordenados por cantidad de syscalls
//
// Una vez que completes los TODOs en el programa BPF y en este archivo:
//   1. cd go/
//   2. go generate ./...
//   3. go build -o syscall-counter .
//   4. sudo ./syscall-counter

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 counter syscall_counter.bpf.c

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
)

// pidCount almacena un par PID + conteo para ordenar.
type pidCount struct {
	PID   uint32
	Count uint64
}

func main() {
	// Cargar los objetos BPF generados por bpf2go.
	objs := counterObjects{}
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando objetos BPF: %v", err)
	}
	defer objs.Close()

	// Adjuntar al tracepoint raw_syscalls/sys_enter.
	tp, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.CountSyscalls, nil)
	if err != nil {
		log.Fatalf("Error adjuntando tracepoint: %v", err)
	}
	defer tp.Close()

	fmt.Println("✅ Programa BPF cargado y adjuntado exitosamente")
	fmt.Println("   Hook: tracepoint/raw_syscalls/sys_enter")
	fmt.Println("   Map:  syscall_count (hash, key=PID, value=count)")
	fmt.Println("")
	fmt.Println("📊 Mostrando top 5 PIDs cada 3 segundos (Ctrl+C para salir)...")
	fmt.Println("")

	// Polling periódico del hash map.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sig:
			fmt.Println("\n👋 Saliendo...")
			return
		case <-ticker.C:
			readMap(objs)
		}
	}
}

// readMap lee el hash map y muestra los top 5 PIDs más activos.
func readMap(objs counterObjects) {
	// TODO 1: Iterar sobre todas las entradas del hash map.
	//
	// Usa objs.SyscallCount.Iterate() para obtener un iterador.
	// Luego, en un for loop, llama a iter.Next(&pid, &count)
	// donde pid es uint32 y count es uint64.
	// Almacena cada par en un slice de pidCount.
	//
	// var entries []pidCount
	// var pid uint32
	// var count uint64
	// iter := ???
	// for ??? {
	//     entries = append(entries, pidCount{PID: pid, Count: count})
	// }

	// TODO 2: Ordenar el slice por Count descendente y mostrar top 5.
	//
	// Usa sort.Slice(entries, func(i, j int) bool { ... })
	// para ordenar por Count de mayor a menor.
	// Luego imprime los primeros 5 (o menos si hay menos de 5).
	//
	// Formato sugerido:
	//   fmt.Printf("  PID=%-6d  syscalls=%d\n", entry.PID, entry.Count)

	_ = objs        // Quita esta línea cuando implementes los TODOs
	_ = sort.Slice  // Quita esta línea cuando implementes los TODOs
	_ = pidCount{}  // Quita esta línea cuando implementes los TODOs
}
