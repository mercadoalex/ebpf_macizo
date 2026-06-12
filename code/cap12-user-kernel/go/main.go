// Capítulo 12 — User space ↔ Kernel: La conversación
//
// Este programa Go demuestra las 3 formas de comunicación kernel ↔ user space:
//
// 1. Perf events (clásico): recibir eventos de fork via perf buffer
// 2. Ring buffer (moderno): recibir eventos de openat via ring buffer
// 3. Maps compartidos (bidireccional): configurar y leer stats via maps
//
// El programa carga los 3 programas BPF, adjunta cada uno a su tracepoint,
// y demuestra la lectura de eventos y la escritura de configuración.
//
// Uso:
//   go generate ./...
//   go build -o user-kernel-demo .
//   sudo ./user-kernel-demo
//
// Requiere: kernel 5.8+ (ring buffer), Linux con tracepoints habilitados.

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 perfevents perf_events.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 ringbufevents ringbuf_events.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 sharedmaps shared_maps.bpf.c

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ─── Estructuras de eventos (deben coincidir con las definiciones en C) ──────

// ForkEvent corresponde a struct fork_event en perf_events.bpf.c.
type ForkEvent struct {
	ParentPID   uint32
	ChildPID    uint32
	TimestampNs uint64
	Comm        [16]byte
}

// FileEvent corresponde a struct file_event en ringbuf_events.bpf.c.
type FileEvent struct {
	PID         uint32
	Flags       uint32
	TimestampNs uint64
	Comm        [16]byte
	Filename    [64]byte
}

func main() {
	// Remover memlock (necesario para cargar programas BPF).
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Capítulo 12 — User space ↔ Kernel: La conversación")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// =========================================================================
	// 1. Perf Events — La forma clásica
	// =========================================================================

	perfObjs := perfeventsObjects{}
	if err := loadPerfeventsObjects(&perfObjs, nil); err != nil {
		log.Fatalf("Error cargando perf_events: %v", err)
	}
	defer perfObjs.Close()

	// Adjuntar a tracepoint sched/sched_process_fork.
	tpPerf, err := link.Tracepoint("sched", "sched_process_fork", perfObjs.TraceFork, nil)
	if err != nil {
		log.Fatalf("Error adjuntando perf_events: %v", err)
	}
	defer tpPerf.Close()

	// Abrir perf reader — lee de todos los buffers per-CPU.
	perfReader, err := perf.NewReader(perfObjs.PerfEvents, os.Getpagesize()*16)
	if err != nil {
		log.Fatalf("Error abriendo perf reader: %v", err)
	}
	defer perfReader.Close()

	fmt.Println("  ✅ Perf events: adjuntado a sched/sched_process_fork")

	// =========================================================================
	// 2. Ring Buffer — La forma moderna
	// =========================================================================

	ringObjs := ringbufeventsObjects{}
	if err := loadRingbufeventsObjects(&ringObjs, nil); err != nil {
		log.Fatalf("Error cargando ringbuf_events: %v", err)
	}
	defer ringObjs.Close()

	// Adjuntar a tracepoint syscalls/sys_enter_openat.
	tpRing, err := link.Tracepoint("syscalls", "sys_enter_openat", ringObjs.TraceOpenat, nil)
	if err != nil {
		log.Fatalf("Error adjuntando ringbuf_events: %v", err)
	}
	defer tpRing.Close()

	// Abrir ring buffer reader — un solo buffer compartido.
	ringReader, err := ringbuf.NewReader(ringObjs.Events)
	if err != nil {
		log.Fatalf("Error abriendo ring buffer reader: %v", err)
	}
	defer ringReader.Close()

	fmt.Println("  ✅ Ring buffer: adjuntado a syscalls/sys_enter_openat")

	// =========================================================================
	// 3. Maps compartidos — Comunicación bidireccional
	// =========================================================================

	mapsObjs := sharedmapsObjects{}
	if err := loadSharedmapsObjects(&mapsObjs, nil); err != nil {
		log.Fatalf("Error cargando shared_maps: %v", err)
	}
	defer mapsObjs.Close()

	// Adjuntar a raw_syscalls/sys_enter.
	tpMaps, err := link.Tracepoint("raw_syscalls", "sys_enter", mapsObjs.ConfigurableMonitor, nil)
	if err != nil {
		log.Fatalf("Error adjuntando shared_maps: %v", err)
	}
	defer tpMaps.Close()

	// ─── Escribir configuración desde user space al kernel ───────
	// Habilitar el monitor.
	var keyEnabled uint32 = 0
	var valEnabled uint64 = 1
	if err := mapsObjs.ConfigMap.Put(keyEnabled, valEnabled); err != nil {
		log.Printf("  ⚠️  Error configurando enabled: %v", err)
	}

	// Configurar sample rate = 1 de cada 100.
	var keySampleRate uint32 = 1
	var valSampleRate uint64 = 100
	if err := mapsObjs.ConfigMap.Put(keySampleRate, valSampleRate); err != nil {
		log.Printf("  ⚠️  Error configurando sample_rate: %v", err)
	}

	// Agregar PIDs a la blocklist (ejemplo: bloquear PID 1).
	var blockedPID uint32 = 1
	var dummy uint8 = 1
	if err := mapsObjs.Blocklist.Put(blockedPID, dummy); err != nil {
		log.Printf("  ⚠️  Error agregando a blocklist: %v", err)
	}

	fmt.Println("  ✅ Maps compartidos: monitor habilitado, sample_rate=100, PID 1 bloqueado")
	fmt.Println()
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("  📡 Escuchando eventos. Ctrl+C para salir.")
	fmt.Println("     • Perf: eventos de fork (nuevos procesos)")
	fmt.Println("     • Ring buffer: eventos de openat (archivos abiertos)")
	fmt.Println("     • Maps: stats cada 3 segundos")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println()

	// =========================================================================
	// Consumers — Goroutines que leen eventos
	// =========================================================================

	// Consumer de perf events (fork).
	go func() {
		for {
			record, err := perfReader.Read()
			if err != nil {
				return
			}
			if record.LostSamples > 0 {
				fmt.Printf("  ⚠️  [perf] %d eventos perdidos\n", record.LostSamples)
				continue
			}

			var evt ForkEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &evt); err != nil {
				continue
			}

			comm := cString(evt.Comm[:])
			fmt.Printf("  🍴 [perf] fork: parent=%-6d child=%-6d comm=%s\n",
				evt.ParentPID, evt.ChildPID, comm)
		}
	}()

	// Consumer de ring buffer (openat).
	go func() {
		for {
			record, err := ringReader.Read()
			if err != nil {
				return
			}

			var evt FileEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &evt); err != nil {
				continue
			}

			comm := cString(evt.Comm[:])
			filename := cString(evt.Filename[:])
			fmt.Printf("  📂 [ringbuf] openat: PID=%-6d comm=%-16s file=%s\n",
				evt.PID, comm, filename)
		}
	}()

	// =========================================================================
	// Loop principal — polling de stats + señales
	// =========================================================================

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sig:
			fmt.Println("\n  👋 Programa terminado. Adiós.")
			return

		case <-ticker.C:
			printSharedMapStats(mapsObjs)
		}
	}
}

// printSharedMapStats lee las estadísticas per-CPU del programa de maps compartidos.
func printSharedMapStats(objs sharedmapsObjects) {
	// Per-CPU array: cada lookup retorna un slice con un valor por CPU.
	var keyTotal uint32 = 0
	var keySampled uint32 = 1
	var keyFiltered uint32 = 2

	var totalPerCPU, sampledPerCPU, filteredPerCPU []uint64

	objs.StatsMap.Lookup(keyTotal, &totalPerCPU)
	objs.StatsMap.Lookup(keySampled, &sampledPerCPU)
	objs.StatsMap.Lookup(keyFiltered, &filteredPerCPU)

	// Sumar valores de todas las CPUs.
	var total, sampled, filtered uint64
	for _, v := range totalPerCPU {
		total += v
	}
	for _, v := range sampledPerCPU {
		sampled += v
	}
	for _, v := range filteredPerCPU {
		filtered += v
	}

	fmt.Printf("  📊 [maps] total=%d | sampled=%d | filtered(blocklist)=%d\n",
		total, sampled, filtered)
}

// cString convierte un byte array (C string terminada en NULL) a string Go.
func cString(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return string(b[:n])
}
