// Capítulo 7 — Ejercicio: Verifier Challenge (Loader en Go)
//
// Este loader intenta cargar el programa BPF del desafío.
// Si el programa tiene errores del verifier, verás los mensajes
// de error detallados que te ayudarán a diagnosticar el problema.
//
// Uso:
//   go generate
//   go build -o verifier-challenge
//   sudo ./verifier-challenge [interfaz]
//
// El programa fallará hasta que corrijas los 3 errores en
// verifier_challenge.bpf.c

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 challenge verifier_challenge.bpf.c

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
)

func main() {
	fmt.Println("=== Capítulo 7: Desafío del Verifier ===")
	fmt.Println("Cargando verifier_challenge.bpf.o...")
	fmt.Println("")

	// Intentar cargar los objetos BPF.
	// Si hay errores del verifier, se imprimirán aquí.
	objs := challengeObjects{}
	if err := loadChallengeObjects(&objs, nil); err != nil {
		fmt.Println("❌ ERROR: El verifier rechazó el programa")
		fmt.Println("")
		fmt.Println("Mensaje del verifier:")
		fmt.Printf("  %v\n", err)
		fmt.Println("")
		fmt.Println("📋 Tu misión: corregir verifier_challenge.bpf.c")
		fmt.Println("   y volver a intentar (go generate && go build).")
		os.Exit(1)
	}
	defer objs.Close()

	fmt.Println("✅ Programa cargado — pasó el verifier")
	fmt.Println("")

	// Adjuntar a la interfaz de red especificada (default: lo)
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
	fmt.Println("El programa está contando paquetes TCP por IP de origen.")
	fmt.Println("Genera tráfico TCP para verlo en acción:")
	fmt.Printf("  curl http://localhost/  (en otra terminal)\n")
	fmt.Println("")
	fmt.Println("Presiona Ctrl+C para salir...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\n👋 XDP removido. Adiós.")
}
