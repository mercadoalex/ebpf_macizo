// Capítulo 11 — Frameworks en acción: cilium/ebpf (Go)
//
// Programa de referencia: contador XDP de paquetes por protocolo.
// Demuestra el flujo completo con cilium/ebpf:
//
// 1. go:generate → bpf2go compila el C y genera structs Go
// 2. Cargar programa y maps con loadXdpprotocounterObjects()
// 3. Adjuntar XDP a una interfaz de red
// 4. Leer stats del array map periódicamente
//
// Este es el workflow principal del libro: C para BPF + Go para user space.
// Compara con la implementación en Rust/Aya en ../rust/.
//
// Uso:
//   go generate ./...
//   go build -o proto-counter .
//   sudo ./proto-counter [interfaz]
//
// Si no se especifica interfaz, usa "lo" (loopback) para testing seguro.

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 xdpprotocounter xdp_proto_counter.bpf.c

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Nombres legibles de los protocolos (coinciden con los índices del map)
var protoNames = [4]string{"TCP", "UDP", "ICMP", "Otro"}

func main() {
	// Determinar interfaz de red
	ifaceName := "lo"
	if len(os.Args) > 1 {
		ifaceName = os.Args[1]
	}

	// Remover memlock (necesario para cargar programas BPF)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Capítulo 11 — Contador XDP por Protocolo (cilium/ebpf)")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// Cargar objetos BPF (programa + map generados por bpf2go)
	objs := xdpprotocounterObjects{}
	if err := loadXdpprotocounterObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando objetos BPF: %v", err)
	}
	defer objs.Close()

	fmt.Println("  ✅ Programa BPF cargado y verificado por el kernel")

	// Buscar la interfaz de red
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Interfaz '%s' no encontrada: %v", ifaceName, err)
	}

	// Adjuntar XDP (modo generic para compatibilidad)
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProtoCounter,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Error adjuntando XDP a '%s': %v", ifaceName, err)
	}
	defer l.Close()

	fmt.Printf("  ✅ XDP adjuntado a '%s' (ifindex %d, modo generic)\n",
		ifaceName, iface.Index)
	fmt.Println()
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("  📡 Contando paquetes por protocolo. Ctrl+C para salir.")
	fmt.Println("     Genera tráfico: ping localhost, curl, etc.")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println()

	// Loop principal: mostrar estadísticas cada 2 segundos
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sig:
			fmt.Println("\n  👋 Programa XDP removido. Adiós.")
			return

		case <-ticker.C:
			printStats(objs)
		}
	}
}

// printStats lee el array map y muestra los contadores por protocolo.
func printStats(objs xdpprotocounterObjects) {
	fmt.Print("  📊 ")
	for i := uint32(0); i < 4; i++ {
		var count uint64
		if err := objs.ProtoStats.Lookup(i, &count); err != nil {
			count = 0
		}
		fmt.Printf("%s=%d", protoNames[i], count)
		if i < 3 {
			fmt.Print(" | ")
		}
	}
	fmt.Println()
}
