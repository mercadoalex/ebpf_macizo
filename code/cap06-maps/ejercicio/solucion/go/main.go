// Capítulo 6 — Solución: Contador de Syscalls por Proceso (Consumer en Go)
//
// Este programa carga el programa BPF que cuenta syscalls por PID,
// lo adjunta al tracepoint raw_syscalls/sys_enter, y cada 3 segundos
// lee el hash map para mostrar los procesos más activos.
//
// Uso:
//   go generate ./...
//   go build -o syscall-counter .
//   sudo ./syscall-counter

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
	var entries []pidCount
	var pid uint32
	var count uint64

	// Iterar sobre todas las entradas del hash map.
	iter := objs.SyscallCount.Iterate()
	for iter.Next(&pid, &count) {
		entries = append(entries, pidCount{PID: pid, Count: count})
	}

	// Ordenar por Count descendente.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})

	// Mostrar top 5.
	fmt.Println("─────────────────────────────────────────────")
	fmt.Printf("  🏆 Top 5 PIDs (de %d totales):\n", len(entries))

	limit := 5
	if len(entries) < limit {
		limit = len(entries)
	}
	for i := 0; i < limit; i++ {
		fmt.Printf("     PID=%-6d  syscalls=%d\n", entries[i].PID, entries[i].Count)
	}
	fmt.Println("")
}
