// Capítulo 7 — Solución: Verifier Challenge (Loader en Go)
//
// Loader que carga la versión corregida del programa XDP.
// Los 3 errores del verifier han sido resueltos:
//   1. Bounds check en header Ethernet
//   2. Null check en map lookup
//   3. Struct completamente inicializada con = {}
//
// Uso:
//   go generate
//   go build -o verifier-challenge
//   sudo ./verifier-challenge [interfaz]
//
// Ejemplo:
//   sudo ./verifier-challenge lo
//   sudo ./verifier-challenge eth0

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 challenge verifier_challenge.bpf.c

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// packetCount refleja struct packet_count del programa BPF
type packetCount struct {
	Count       uint64
	Bytes       uint64
	LastPayload [256]byte
}

func main() {
	fmt.Println("=== Capítulo 7: Desafío del Verifier (SOLUCIÓN) ===")
	fmt.Println("")

	// Cargar los objetos BPF
	objs := challengeObjects{}
	if err := loadChallengeObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando programa BPF: %v", err)
	}
	defer objs.Close()

	fmt.Println("✅ Programa cargado — pasó el verifier")

	// Adjuntar XDP a interfaz
	iface := "lo"
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}

	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		log.Fatalf("Interfaz %s no encontrada: %v", iface, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CountTcpPackets,
		Interface: ifaceObj.Index,
	})
	if err != nil {
		log.Fatalf("Error adjuntando XDP a %s: %v", iface, err)
	}
	defer xdpLink.Close()

	fmt.Printf("🔗 XDP adjuntado a interfaz: %s\n", iface)
	fmt.Println("")
	fmt.Println("Contando paquetes TCP por IP de origen...")
	fmt.Println("Genera tráfico: curl http://localhost/ (otra terminal)")
	fmt.Println("")

	// Goroutine para imprimir estadísticas cada 2 segundos
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				printStats(objs.Stats)
			case <-done:
				return
			}
		}
	}()

	// Esperar señal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	close(done)
	fmt.Println("\n--- Estadísticas finales ---")
	printStats(objs.Stats)
	fmt.Println("\n👋 XDP removido. Adiós.")
}

func printStats(m *ebpf.Map) {
	var key uint32
	var stats packetCount

	iter := m.Iterate()
	found := false
	for iter.Next(&key, &stats) {
		found = true
		ip := intToIP(key)
		fmt.Printf("  %s → %d paquetes, %d bytes\n",
			ip, stats.Count, stats.Bytes)
	}
	if !found {
		fmt.Println("  (sin tráfico TCP todavía)")
	}
}

func intToIP(n uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip.String()
}
