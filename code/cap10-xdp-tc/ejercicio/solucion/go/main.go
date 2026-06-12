// Capítulo 10 — Solución: Firewall XDP con Blocklist Dinámica
//
// Este programa carga el firewall XDP, puebla la blocklist con IPs
// de ejemplo, adjunta el programa a la interfaz de red, y muestra
// estadísticas de paquetes cada 2 segundos.
//
// Uso:
//   go generate ./...
//   go build -o firewall .
//   sudo ./firewall [interfaz]
//
// Si no se especifica interfaz, usa "lo" (loopback) para testing.

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 firewall xdp_firewall.bpf.c

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

// ipToU32 convierte una IP a uint32 en network byte order (big-endian).
func ipToU32(ip net.IP) uint32 {
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip)
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

	// Cargar los objetos BPF
	objs := firewallObjects{}
	if err := loadFirewallObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando objetos BPF: %v", err)
	}
	defer objs.Close()

	// ─── Poblar la blocklist ─────────────────────────────────────
	blockedIPs := []string{
		"192.168.1.100",
		"10.0.0.50",
		"172.16.0.99",
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Capítulo 10 — Solución: Firewall XDP con Blocklist")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println("  📋 IPs bloqueadas:")

	for _, ipStr := range blockedIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			log.Printf("  ⚠️  IP inválida: %s", ipStr)
			continue
		}
		key := ipToU32(ip)
		var value uint64 = 0
		if err := objs.Blocklist.Put(key, value); err != nil {
			log.Printf("  ⚠️  Error agregando %s: %v", ipStr, err)
		} else {
			fmt.Printf("     ✗ %s\n", ipStr)
		}
	}
	fmt.Println()

	// ─── Adjuntar XDP ────────────────────────────────────────────
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Interfaz '%s' no encontrada: %v", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFirewall,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Error adjuntando XDP: %v", err)
	}
	defer l.Close()

	fmt.Printf("  ✅ Firewall XDP activo en '%s' (modo generic)\n", ifaceName)
	fmt.Println()
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("  📡 Mostrando stats cada 2 segundos. Ctrl+C para salir.")
	fmt.Println("  💡 Prueba: ping desde una IP bloqueada → 100% packet loss")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println()

	// ─── Loop de estadísticas ────────────────────────────────────
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sig:
			fmt.Println("\n  👋 Firewall removido. Adiós.")
			return
		case <-ticker.C:
			printStats(objs)
		}
	}
}

// printStats muestra las estadísticas globales y por IP bloqueada.
func printStats(objs firewallObjects) {
	var passed, dropped uint64
	keyPass := uint32(0)
	keyDrop := uint32(1)

	objs.Stats.Lookup(keyPass, &passed)
	objs.Stats.Lookup(keyDrop, &dropped)

	fmt.Printf("  📊 Stats: passed=%d | dropped=%d\n", passed, dropped)
}
