// Capítulo 11 — Ejercicio SOLUCIÓN: Contador XDP por IP Destino
//
// Programa completo que cuenta paquetes por protocolo Y por IP destino.
// Muestra stats por protocolo (array map) y top IPs (hash map).
//
// Uso:
//   go generate ./...
//   go build -o ip-counter .
//   sudo ./ip-counter [interfaz]

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 ipcounter xdp_ip_counter.bpf.c

import (
	"encoding/binary"
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

// Nombres legibles de los protocolos
var protoNames = [4]string{"TCP", "UDP", "ICMP", "Otro"}

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

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Capítulo 11 — Ejercicio: Contador XDP por IP Destino")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// Cargar objetos BPF
	objs := ipcounterObjects{}
	if err := loadIpcounterObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando objetos BPF: %v", err)
	}
	defer objs.Close()

	fmt.Println("  ✅ Programa BPF cargado exitosamente")

	// Adjuntar XDP a la interfaz
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Interfaz '%s' no encontrada: %v", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpIpCounter,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Error adjuntando XDP: %v", err)
	}
	defer l.Close()

	fmt.Printf("  ✅ XDP adjuntado a '%s' (modo generic)\n", ifaceName)
	fmt.Println()
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("  📡 Contando paquetes. Ctrl+C para salir.")
	fmt.Println("     Genera tráfico: ping localhost, curl localhost, etc.")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println()

	// Loop de estadísticas
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

func printStats(objs ipcounterObjects) {
	// ─── Stats por protocolo ─────────────────────────────────────
	fmt.Print("  📊 Proto: ")
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

	// ─── Stats por IP destino ────────────────────────────────────
	fmt.Println("  📊 Top IPs destino:")

	var key uint32
	var value uint64
	iter := objs.IpStats.Iterate()

	count := 0
	for iter.Next(&key, &value) {
		// Convertir uint32 (network byte order) a IP legible
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, key)
		fmt.Printf("     %s → %d paquetes\n", ip.String(), value)

		count++
		if count >= 10 {
			fmt.Println("     ... (mostrando top 10)")
			break
		}
	}

	if count == 0 {
		fmt.Println("     (sin tráfico IPv4 aún)")
	}
	fmt.Println()
}
