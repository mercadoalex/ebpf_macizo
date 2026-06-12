// Capítulo 14 — Tail Calls, Function Calls y Composición
//
// Este programa Go demuestra cómo:
//
// 1. Cargar un programa BPF con múltiples funciones (dispatcher + handlers)
// 2. Poblar un PROG_ARRAY (jmp_table) con los handlers
// 3. Adjuntar el dispatcher como punto de entrada XDP
// 4. Leer estadísticas per-CPU de los handlers
//
// El dispatcher parsea paquetes y usa bpf_tail_call() para saltar
// al handler del protocolo correspondiente (TCP, UDP, ICMP).
// Los handlers son programas BPF independientes dentro del mismo objeto ELF.
//
// Uso:
//   go generate ./...
//   go build -o tailcall-demo .
//   sudo ./tailcall-demo [interfaz]
//
// Si no se especifica interfaz, usa "lo" (loopback) para testing seguro.

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 dispatcher tailcall_dispatcher.bpf.c

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
	progTCP  = 0
	progUDP  = 1
	progICMP = 2
)

// Labels para las estadísticas
var statsLabels = [5]string{
	"TCP",
	"UDP",
	"ICMP",
	"Other",
	"Dropped",
}

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
	// Cargar el objeto BPF (contiene dispatcher + handlers)
	// =========================================================================
	objs := dispatcherObjects{}
	if err := loadDispatcherObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando objetos BPF: %v", err)
	}
	defer objs.Close()

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Capítulo 14 — Tail Calls: XDP Protocol Dispatcher")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// =========================================================================
	// Poblar el prog_array (jmp_table) con los handlers
	//
	// Esto es la clave de los tail calls desde user space:
	// metemos los FDs de los programas handler en el prog_array,
	// y el dispatcher puede saltar a ellos con bpf_tail_call().
	// =========================================================================
	fmt.Println("  📦 Poblando prog_array (jmp_table):")

	handlers := map[uint32]*ebpf.Program{
		progTCP:  objs.HandleTcp,
		progUDP:  objs.HandleUdp,
		progICMP: objs.HandleIcmp,
	}

	for idx, prog := range handlers {
		if err := objs.JmpTable.Put(idx, uint32(prog.FD())); err != nil {
			log.Fatalf("Error insertando handler[%d] en prog_array: %v", idx, err)
		}
		fmt.Printf("     [%d] → %s handler ✓\n", idx, statsLabels[idx])
	}
	fmt.Println()

	// =========================================================================
	// Adjuntar el dispatcher como programa XDP
	// =========================================================================
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Interfaz '%s' no encontrada: %v", ifaceName, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDispatcher,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Error adjuntando XDP dispatcher: %v", err)
	}
	defer xdpLink.Close()

	fmt.Printf("  ✅ XDP dispatcher adjuntado a '%s' (ifindex %d)\n",
		ifaceName, iface.Index)
	fmt.Println()
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("  📡 Programa activo. Ctrl+C para salir.")
	fmt.Println("     El dispatcher clasifica paquetes por protocolo y salta")
	fmt.Println("     al handler correspondiente via tail call.")
	fmt.Println()
	fmt.Println("  Pruebas sugeridas:")
	fmt.Println("     • ping localhost          → ICMP handler (DROP echo)")
	fmt.Println("     • curl localhost           → TCP handler (PASS)")
	fmt.Println("     • dig @127.0.0.1 google.com → UDP handler (PASS)")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println()

	// =========================================================================
	// Loop principal: mostrar estadísticas per-CPU
	// =========================================================================
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sig:
			fmt.Println("\n  👋 Dispatcher removido. Adiós.")
			return
		case <-ticker.C:
			printStats(objs)
		}
	}
}

// printStats lee el per-CPU array map y muestra totales por protocolo.
func printStats(objs dispatcherObjects) {
	fmt.Print("  📊 Stats: ")

	for i := uint32(0); i < 5; i++ {
		var values []uint64
		if err := objs.PktStats.Lookup(i, &values); err != nil {
			continue
		}

		// Sumar todas las CPUs
		var total uint64
		for _, v := range values {
			total += v
		}

		if i > 0 {
			fmt.Print(" | ")
		}
		fmt.Printf("%s=%d", statsLabels[i], total)
	}
	fmt.Println()
}
