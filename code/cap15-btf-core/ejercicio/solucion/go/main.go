// Capítulo 15 — Ejercicio Ninja: Portable Tracer (Solución)
//
// Loader Go que demuestra carga CO-RE con detección de capacidades:
//   1. Verifica si el kernel tiene BTF disponible
//   2. Intenta cargar con CO-RE nativo (cilium/ebpf lo resuelve solo)
//   3. Si falla, intenta con BTF externo como fallback
//   4. Adjunta a kprobes (do_execveat_common y do_exit)
//   5. Consume y formatea eventos del ring buffer
//
// El mismo binario funciona en kernels 5.10, 5.15 y 6.1 sin recompilación.
//
// Uso:
//   go generate ./...
//   go build -o portable-tracer .
//   sudo ./portable-tracer

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 tracer portable_tracer.bpf.c

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// ============================================================================
// Tipos de eventos (deben coincidir con el lado BPF)
// ============================================================================

const (
	EventExec = 1
	EventExit = 2
)

// ExecEvent mapea struct exec_event del .bpf.c.
type ExecEvent struct {
	Type      uint8
	Pad       [3]uint8
	PID       uint32
	PPID      uint32
	UID       uint32
	PIDNsInum uint32
	Comm      [16]byte
}

// ExitEvent mapea struct exit_event del .bpf.c.
type ExitEvent struct {
	Type       uint8
	Pad        [3]uint8
	PID        uint32
	ExitCode   int32
	LifetimeNs uint64
	Comm       [16]byte
}

// ============================================================================
// Main
// ============================================================================

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  Portable Tracer — CO-RE Exercise (Capítulo 15)             ║")
	fmt.Println("║  Funciona en kernels 5.10, 5.15 y 6.1 sin recompilación    ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println("")

	// ========================================================================
	// Paso 1: Verificar BTF del kernel
	// ========================================================================
	btfAvailable := checkBTF()

	// ========================================================================
	// Paso 2: Cargar objetos BPF con CO-RE
	// ========================================================================
	objs := tracerObjects{}
	err := loadWithFallback(&objs, btfAvailable)
	if err != nil {
		log.Fatalf("❌ Error cargando programa BPF: %v", err)
	}
	defer objs.Close()
	fmt.Println("✅ Programa BPF cargado (CO-RE relocations resueltas)")

	// ========================================================================
	// Paso 3: Adjuntar a kprobes
	// ========================================================================
	kpExec, err := link.Kprobe("do_execveat_common", objs.TraceExec, nil)
	if err != nil {
		log.Fatalf("❌ Error adjuntando kprobe/do_execveat_common: %v", err)
	}
	defer kpExec.Close()
	fmt.Println("   Hook: kprobe/do_execveat_common (execve)")

	kpExit, err := link.Kprobe("do_exit", objs.TraceExit, nil)
	if err != nil {
		log.Fatalf("❌ Error adjuntando kprobe/do_exit: %v", err)
	}
	defer kpExit.Close()
	fmt.Println("   Hook: kprobe/do_exit (exit)")

	// ========================================================================
	// Paso 4: Consumir eventos del ring buffer
	// ========================================================================
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("❌ Error abriendo ring buffer: %v", err)
	}
	defer rd.Close()

	// Cerrar reader al recibir señal.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	fmt.Println("")
	fmt.Println("📊 Tracing procesos... (Ctrl+C para salir)")
	fmt.Println("")
	fmt.Printf("%-6s %-8s %-8s %-8s %-6s %-12s %s\n",
		"TYPE", "PID", "PPID", "UID", "NS", "LIFETIME", "COMM")
	fmt.Println("────── ──────── ──────── ──────── ────── ──────────── ────────────────")

	// Loop principal de consumo de eventos.
	for {
		record, err := rd.Read()
		if err != nil {
			break
		}
		handleEvent(record.RawSample)
	}

	fmt.Println("\n👋 Saliendo...")
}

// ============================================================================
// Funciones auxiliares
// ============================================================================

// checkBTF verifica si el kernel actual tiene BTF disponible.
func checkBTF() bool {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	if err != nil {
		fmt.Println("⚠️  WARNING: BTF del kernel NO disponible")
		fmt.Println("   /sys/kernel/btf/vmlinux no encontrado")
		fmt.Println("   CO-RE requiere CONFIG_DEBUG_INFO_BTF=y")
		fmt.Println("   Intentando fallback con BTF externo...")
		fmt.Println("")
		return false
	}
	fmt.Println("✓ BTF del kernel disponible (/sys/kernel/btf/vmlinux)")
	return true
}

// loadWithFallback intenta cargar los objetos BPF con CO-RE.
// Si el kernel tiene BTF nativo, cilium/ebpf resuelve relocations automáticamente.
// Si no, intenta usar un BTF externo (BTFHub pattern).
func loadWithFallback(objs *tracerObjects, btfAvailable bool) error {
	// Intento 1: carga directa (CO-RE nativo)
	// cilium/ebpf automáticamente lee /sys/kernel/btf/vmlinux y resuelve relocations.
	err := loadTracerObjects(objs, nil)
	if err == nil {
		return nil
	}

	if btfAvailable {
		// Si BTF está disponible pero falló, es un error real.
		return fmt.Errorf("BTF disponible pero carga falló: %w", err)
	}

	// Intento 2: fallback con BTF externo.
	// En un proyecto real, aquí cargarías un .btf de BTFHub para el kernel específico.
	// Ejemplo: /opt/btfhub/5.10.0-generic.btf
	fmt.Println("   Intentando con BTF externo...")

	// Buscar BTF externo en ubicaciones comunes.
	btfPaths := []string{
		"/opt/btfhub/vmlinux.btf",
		"/var/lib/btfhub/vmlinux.btf",
		"./vmlinux.btf",
	}

	for _, path := range btfPaths {
		spec, btfErr := btf.LoadSpec(path)
		if btfErr != nil {
			continue
		}

		err = loadTracerObjects(objs, &ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				KernelTypes: spec,
			},
		})
		if err == nil {
			fmt.Printf("   ✓ Cargado con BTF externo: %s\n", path)
			return nil
		}
	}

	return fmt.Errorf("no se pudo cargar (sin BTF nativo ni externo): %w", err)
}

// handleEvent decodifica y muestra un evento del ring buffer.
func handleEvent(data []byte) {
	// El primer byte indica el tipo de evento.
	if len(data) < 1 {
		return
	}

	switch data[0] {
	case EventExec:
		var evt ExecEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			return
		}
		comm := string(bytes.TrimRight(evt.Comm[:], "\x00"))
		fmt.Printf("%-6s %-8d %-8d %-8d %-6d %-12s %s\n",
			"EXEC", evt.PID, evt.PPID, evt.UID, evt.PIDNsInum, "-", comm)

	case EventExit:
		var evt ExitEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
			return
		}
		comm := string(bytes.TrimRight(evt.Comm[:], "\x00"))
		lifetime := formatDuration(evt.LifetimeNs)
		fmt.Printf("%-6s %-8d %-8s %-8s %-6s %-12s %s (code=%d)\n",
			"EXIT", evt.PID, "-", "-", "-", lifetime, comm, evt.ExitCode)
	}
}

// formatDuration convierte nanosegundos a formato legible.
func formatDuration(ns uint64) string {
	if ns == 0 {
		return "unknown"
	}
	d := time.Duration(ns) * time.Nanosecond
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
