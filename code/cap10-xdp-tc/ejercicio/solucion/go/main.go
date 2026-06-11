package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 firewall xdp_firewall.bpf.c

func ipToU32(ip net.IP) uint32 {
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip)
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := firewallObjects{}
	if err := loadFirewallObjects(&objs, nil); err != nil {
		log.Fatalf("cargando objetos: %v", err)
	}
	defer objs.Close()

	// IPs a bloquear (configurable)
	blockedIPs := []string{
		"192.168.1.100",
		"10.0.0.50",
	}

	// Poblar la blocklist
	for _, ipStr := range blockedIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			log.Printf("IP inválida: %s", ipStr)
			continue
		}
		key := ipToU32(ip)
		var value uint64 = 0
		if err := objs.Blocklist.Put(key, value); err != nil {
			log.Printf("error agregando %s: %v", ipStr, err)
		} else {
			fmt.Printf("Bloqueada: %s\n", ipStr)
		}
	}

	// Adjuntar a la interfaz
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		log.Fatal(err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFirewall,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("adjuntando XDP: %v", err)
	}
	defer l.Close()

	fmt.Printf("Firewall XDP activo en %s. Ctrl+C para salir.\n", iface.Name)

	// Mostrar stats cada 2 segundos
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var passed, dropped uint64
			keyPass := uint32(0)
			keyDrop := uint32(1)
			objs.Stats.Lookup(keyPass, &passed)
			objs.Stats.Lookup(keyDrop, &dropped)
			fmt.Printf("Stats: passed=%d dropped=%d\n", passed, dropped)

			// Mostrar drops por IP
			var key uint32
			var value uint64
			iter := objs.Blocklist.Iterate()
			for iter.Next(&key, &value) {
				if value > 0 {
					ip := make(net.IP, 4)
					binary.BigEndian.PutUint32(ip, key)
					fmt.Printf("  IP %s: %d paquetes dropeados\n", ip, value)
				}
			}
		case <-sig:
			fmt.Println("\nSaliendo...")
			return
		}
	}
}
