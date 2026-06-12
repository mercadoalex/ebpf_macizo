// Capítulo 10 — XDP y TC: Networking a velocidad del kernel
//
// Este programa Go demuestra cómo cargar y adjuntar programas XDP y TC:
//
// 1. XDP pass: el programa XDP más simple (dejar pasar todo)
// 2. XDP drop counter: firewall que bloquea ICMP y cuenta paquetes
// 3. TC filter: filtro de Traffic Control que bloquea puerto 8080
//
// El programa carga los ejemplos XDP y TC, los adjunta a la interfaz
// de red especificada, y muestra estadísticas de paquetes.
//
// Uso:
//   go generate ./...
//   go build -o xdp-tc-demo .
//   sudo ./xdp-tc-demo [interfaz]
//
// Si no se especifica interfaz, usa "lo" (loopback) para testing seguro.

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 xdppass xdp_pass.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 xdpdrop xdp_drop_counter.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 tcfilter tc_filter.bpf.c

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
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

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

	// =========================================================================
	// Ejemplo 1: XDP Drop Counter (bloquea ICMP, cuenta paquetes)
	// =========================================================================
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Capítulo 10 — XDP y TC Demo")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// Cargar programa XDP drop counter
	xdpObjs := xdpdropObjects{}
	if err := loadXdpdropObjects(&xdpObjs, nil); err != nil {
		log.Fatalf("Error cargando XDP drop counter: %v", err)
	}
	defer xdpObjs.Close()

	// Buscar la interfaz
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Interfaz '%s' no encontrada: %v", ifaceName, err)
	}

	// Adjuntar XDP (modo generic para compatibilidad en cualquier interfaz)
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   xdpObjs.XdpFirewall,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Error adjuntando XDP: %v", err)
	}
	defer xdpLink.Close()

	fmt.Printf("  ✅ XDP drop counter adjuntado a '%s' (ifindex %d)\n",
		ifaceName, iface.Index)
	fmt.Println("     → Bloqueando paquetes ICMP (ping)")
	fmt.Println()

	// =========================================================================
	// Ejemplo 2: TC Filter (bloquea puerto 8080)
	// =========================================================================

	// Cargar programa TC
	tcObjs := tcfilterObjects{}
	if err := loadTcfilterObjects(&tcObjs, nil); err != nil {
		log.Fatalf("Error cargando TC filter: %v", err)
	}
	defer tcObjs.Close()

	// Crear qdisc clsact (requerido para TC eBPF)
	netlinkIface, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		log.Fatalf("Error obteniendo link: %v", err)
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: netlinkIface.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		log.Printf("  ⚠️  qdisc clsact: %v (puede que ya exista)", err)
	}

	// Adjuntar filtro TC en ingress
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: netlinkIface.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           tcObjs.TcFilter.FD(),
		Name:         "tc_filter",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		log.Fatalf("Error adjuntando filtro TC: %v", err)
	}

	fmt.Printf("  ✅ TC filter adjuntado a '%s' (ingress)\n", ifaceName)
	fmt.Println("     → Bloqueando tráfico TCP a puerto 8080")
	fmt.Println()
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("  📡 Programa activo. Ctrl+C para salir.")
	fmt.Println("     Prueba: ping localhost (bloqueado por XDP)")
	fmt.Println("     Prueba: curl localhost:8080 (bloqueado por TC)")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println()

	// =========================================================================
	// Loop principal: mostrar estadísticas
	// =========================================================================

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sig:
			fmt.Println("\n  🧹 Limpiando...")
			netlink.FilterDel(filter)
			netlink.QdiscDel(qdisc)
			fmt.Println("  👋 Programa BPF removido. Adiós.")
			return

		case <-ticker.C:
			printXDPStats(xdpObjs)
		}
	}
}

// printXDPStats lee el array map del XDP drop counter y muestra estadísticas.
func printXDPStats(objs xdpdropObjects) {
	var passed, dropped uint64
	keyPass := uint32(0)
	keyDrop := uint32(1)

	objs.PktCount.Lookup(keyPass, &passed)
	objs.PktCount.Lookup(keyDrop, &dropped)

	fmt.Printf("  📊 XDP Stats: passed=%d | dropped=%d (ICMP)\n", passed, dropped)
}
