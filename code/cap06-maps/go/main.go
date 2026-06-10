// Capítulo 6 — Maps: La memoria compartida
//
// Este programa Go demuestra las 3 formas de interactuar con maps BPF:
//
// 1. Hash map (syscall_count): leer contadores por PID periódicamente
// 2. Array map (stats): leer estadísticas globales
// 3. Ring buffer (events): recibir eventos en tiempo real
//
// El programa carga los 3 programas BPF simultáneamente, los adjunta
// a sus respectivos tracepoints, y muestra los datos en consola.
//
// Uso:
//   go generate ./...
//   go build -o maps-demo .
//   sudo ./maps-demo

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 hashcounter hash_counter.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 arraystats array_stats.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 ringbuf ringbuf_events.bpf.c

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Event corresponde exactamente a struct event en ringbuf_events.bpf.c.
// El orden y tamaño de los campos debe coincidir con la definición en C.
type Event struct {
	PID         uint32
	_           [4]byte // padding para alinear timestamp_ns a 8 bytes
	TimestampNs uint64
	Comm        [16]byte
}

func main() {
	// =========================================================================
	// Cargar los 3 programas BPF
	// =========================================================================

	// 1. Hash counter
	hashObjs := hashcounterObjects{}
	if err := loadHashcounterObjects(&hashObjs, nil); err != nil {
		log.Fatalf("Error cargando hash_counter: %v", err)
	}
	defer hashObjs.Close()

	// 2. Array stats
	arrayObjs := arraystatsObjects{}
	if err := loadArraystatsObjects(&arrayObjs, nil); err != nil {
		log.Fatalf("Error cargando array_stats: %v", err)
	}
	defer arrayObjs.Close()

	// 3. Ring buffer events
	ringObjs := ringbufObjects{}
	if err := loadRingbufObjects(&ringObjs, nil); err != nil {
		log.Fatalf("Error cargando ringbuf_events: %v", err)
	}
	defer ringObjs.Close()

	// =========================================================================
	// Adjuntar a tracepoints
	// =========================================================================

	// Hash counter y array stats se adjuntan al mismo tracepoint genérico.
	tpHash, err := link.Tracepoint("raw_syscalls", "sys_enter", hashObjs.CountSyscalls, nil)
	if err != nil {
		log.Fatalf("Error adjuntando hash counter: %v", err)
	}
	defer tpHash.Close()

	tpArray, err := link.Tracepoint("raw_syscalls", "sys_enter", arrayObjs.TrackStats, nil)
	if err != nil {
		log.Fatalf("Error adjuntando array stats: %v", err)
	}
	defer tpArray.Close()

	// Ring buffer se adjunta a execve (solo eventos de exec, no TODAS las syscalls).
	tpRing, err := link.Tracepoint("syscalls", "sys_enter_execve", ringObjs.ExecEvent, nil)
	if err != nil {
		log.Fatalf("Error adjuntando ring buffer: %v", err)
	}
	defer tpRing.Close()

	fmt.Println("✅ 3 programas BPF cargados y adjuntados:")
	fmt.Println("   • hash_counter → raw_syscalls/sys_enter (cuenta syscalls por PID)")
	fmt.Println("   • array_stats  → raw_syscalls/sys_enter (estadísticas globales)")
	fmt.Println("   • ringbuf_events → syscalls/sys_enter_execve (eventos de exec)")
	fmt.Println("")

	// =========================================================================
	// Consumer del ring buffer (goroutine aparte)
	// =========================================================================

	// Abrir el reader del ring buffer.
	rd, err := ringbuf.NewReader(ringObjs.Events)
	if err != nil {
		log.Fatalf("Error abriendo ring buffer reader: %v", err)
	}
	defer rd.Close()

	// Leer eventos en una goroutine separada.
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				return // Reader cerrado
			}

			var evt Event
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &evt); err != nil {
				continue
			}

			comm := unix_string(evt.Comm[:])
			fmt.Printf("  🔔 [ringbuf] execve: PID=%-6d COMM=%s\n", evt.PID, comm)
		}
	}()

	// =========================================================================
	// Polling periódico de hash map y array map
	// =========================================================================

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	fmt.Println("📊 Mostrando stats cada 3 segundos (Ctrl+C para salir)...")
	fmt.Println("   Los eventos de execve aparecen en tiempo real via ring buffer.")
	fmt.Println("")

	for {
		select {
		case <-sig:
			fmt.Println("\n👋 Saliendo...")
			return

		case <-ticker.C:
			printStats(hashObjs, arrayObjs)
		}
	}
}

// printStats lee los hash map y array map para mostrar las estadísticas actuales.
func printStats(hashObjs hashcounterObjects, arrayObjs arraystatsObjects) {
	fmt.Println("─────────────────────────────────────────────")

	// --- Array stats ---
	var total, system, user uint64
	var key uint32

	key = 0
	if err := arrayObjs.Stats.Lookup(key, &total); err == nil {
		key = 1
		arrayObjs.Stats.Lookup(key, &system)
		key = 2
		arrayObjs.Stats.Lookup(key, &user)
		fmt.Printf("  📈 [array] Total=%d | Sistema(PID<1000)=%d | Usuario(PID≥1000)=%d\n",
			total, system, user)
	}

	// --- Top 5 PIDs del hash map ---
	type pidCount struct {
		PID   uint32
		Count uint64
	}

	var entries []pidCount
	var pid uint32
	var count uint64

	iter := hashObjs.SyscallCount.Iterate()
	for iter.Next(&pid, &count) {
		entries = append(entries, pidCount{PID: pid, Count: count})
	}

	// Ordenar por count descendente.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})

	// Mostrar top 5.
	fmt.Print("  🏆 [hash] Top 5 PIDs: ")
	limit := 5
	if len(entries) < limit {
		limit = len(entries)
	}
	for i := 0; i < limit; i++ {
		fmt.Printf("PID=%d(%d) ", entries[i].PID, entries[i].Count)
	}
	fmt.Println("")
	fmt.Println("")
}

// unix_string convierte un byte array (C string) a string Go.
func unix_string(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return string(b[:n])
}
