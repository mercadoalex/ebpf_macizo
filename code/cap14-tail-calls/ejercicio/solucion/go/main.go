// Capítulo 14 — Solución Ejercicio Ninja: Classifier Multi-Protocolo
//
// Un classifier XDP completo que demuestra:
//
// 1. Tail calls para despacho por protocolo (dispatcher → handlers)
// 2. BPF-to-BPF function calls para parsing compartido
// 3. Per-CPU maps para estadísticas sin locks
// 4. Contexto compartido via map entre tail calls
// 5. Hot-swap de handlers en runtime (sin perder un solo paquete)
//
// El hot-swap demuestra una ventaja clave de tail calls + prog_array:
// puedes reemplazar un handler en caliente actualizando un solo slot
// del prog_array. Esto es imposible con function calls estáticas.
//
// Uso:
//   go generate ./...
//   go build -o classifier .
//   sudo ./classifier [interfaz]
//
// Si no se especifica interfaz, usa "lo" (loopback) para testing.

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 classifier classifier.bpf.c

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Índices del prog_array (deben coincidir con los #define en BPF)
const (
	handlerTCP   = 0
	handlerUDP   = 1
	handlerICMP  = 2
	handlerOther = 3
)

// Clases de clasificación (deben coincidir con CLASS_* en BPF)
const (
	classHTTP      = 0
	classSSH       = 1
	classDNS       = 2
	classICMPEcho  = 3
	classICMPOther = 4
	classTCPOther  = 5
	classUDPOther  = 6
	classUnknown   = 7
	classTotal     = 8
	numClasses     = 9
)

var classLabels = [numClasses]string{
	"HTTP(80/443)",
	"SSH(22)",
	"DNS(53)",
	"ICMP Echo",
	"ICMP Other",
	"TCP Other",
	"UDP Other",
	"Unknown",
	"TOTAL",
}

func main() {
	// Determinar interfaz
	ifaceName := "lo"
	if len(os.Args) > 1 {
		ifaceName = os.Args[1]
	}

	// Remover límite de memlock
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// =========================================================================
	// Cargar el objeto BPF
	// =========================================================================
	objs := classifierObjects{}
	if err := loadClassifierObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando objetos BPF: %v", err)
	}
	defer objs.Close()

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Capítulo 14 — Ejercicio Ninja: Classifier Multi-Protocolo")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// =========================================================================
	// Poblar prog_array con handlers
	// =========================================================================
	fmt.Println("  📦 Instalando handlers en prog_array:")

	type handlerEntry struct {
		index uint32
		prog  *ebpf.Program
		name  string
	}

	handlers := []handlerEntry{
		{handlerTCP, objs.ClassifyTcp, "TCP (clasifica por puerto)"},
		{handlerUDP, objs.ClassifyUdp, "UDP (DNS vs otros)"},
		{handlerICMP, objs.ClassifyIcmp, "ICMP (echo vs otros)"},
		{handlerOther, objs.ClassifyOther, "Other (catch-all)"},
	}

	for _, h := range handlers {
		if err := objs.HandlerProgs.Put(h.index, uint32(h.prog.FD())); err != nil {
			log.Fatalf("Error instalando handler[%d]: %v", h.index, err)
		}
		fmt.Printf("     [%d] → %s ✓\n", h.index, h.name)
	}
	fmt.Println()

	// =========================================================================
	// Adjuntar XDP
	// =========================================================================
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Interfaz '%s' no encontrada: %v", ifaceName, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpClassifier,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Error adjuntando XDP: %v", err)
	}
	defer xdpLink.Close()

	fmt.Printf("  ✅ Classifier XDP activo en '%s'\n", ifaceName)
	fmt.Println()

	// =========================================================================
	// Demostración de Hot-Swap
	//
	// Después de 10 segundos, "removemos" el handler TCP del prog_array.
	// Los paquetes TCP caerán en el fallback del dispatcher (CLASS_UNKNOWN).
	// A los 20 segundos, lo restauramos. Zero downtime.
	// =========================================================================
	fmt.Println("  🔥 HOT-SWAP DEMO:")
	fmt.Println("     • T+10s: Se remueve handler TCP (paquetes TCP → Unknown)")
	fmt.Println("     • T+20s: Se restaura handler TCP (clasificación normal)")
	fmt.Println()
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("  📡 Mostrando clasificación cada 2s. Ctrl+C para salir.")
	fmt.Println("  💡 Genera tráfico: ping, curl, dig para ver clasificación")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println()

	// =========================================================================
	// Loop principal
	// =========================================================================
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	tcpRemoved := false
	tcpRestored := false

	for {
		select {
		case <-sig:
			fmt.Println("\n  👋 Classifier removido. Adiós.")
			return

		case <-ticker.C:
			elapsed := time.Since(startTime)

			// Hot-swap demo: remover handler TCP a los 10s
			if !tcpRemoved && elapsed > 10*time.Second {
				if err := objs.HandlerProgs.Delete(uint32(handlerTCP)); err != nil {
					log.Printf("  ⚠️  Error removiendo handler TCP: %v", err)
				} else {
					fmt.Println("  ⚡ HOT-SWAP: Handler TCP REMOVIDO — paquetes TCP ahora → Unknown")
					tcpRemoved = true
				}
			}

			// Hot-swap demo: restaurar handler TCP a los 20s
			if tcpRemoved && !tcpRestored && elapsed > 20*time.Second {
				if err := objs.HandlerProgs.Put(uint32(handlerTCP), uint32(objs.ClassifyTcp.FD())); err != nil {
					log.Printf("  ⚠️  Error restaurando handler TCP: %v", err)
				} else {
					fmt.Println("  ⚡ HOT-SWAP: Handler TCP RESTAURADO — clasificación normal")
					tcpRestored = true
				}
			}

			printClassification(objs)
		}
	}
}

// printClassification lee las estadísticas per-CPU y muestra la clasificación.
func printClassification(objs classifierObjects) {
	fmt.Println("  ┌─────────────────────────────────────────────┐")

	for i := uint32(0); i < numClasses; i++ {
		var values []uint64
		if err := objs.ClassStats.Lookup(i, &values); err != nil {
			continue
		}

		// Sumar todas las CPUs
		var total uint64
		for _, v := range values {
			total += v
		}

		if total == 0 && i != classTotal {
			continue
		}

		prefix := "  │  "
		if i == classTotal {
			prefix = "  │  📊 "
		}
		fmt.Printf("%s%-14s %d\n", prefix, classLabels[i], total)
	}
	fmt.Println("  └─────────────────────────────────────────────┘")
}
