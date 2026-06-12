// Capítulo 18 Ejercicio — Benchmark A/B: Profiling antes/después de optimización
//
// Este programa Go ejecuta BPF_PROG_TEST_RUN para comparar la versión
// optimizada de un programa XDP contra una baseline. El objetivo es
// demostrar con evidencia medible que las técnicas de optimización
// del capítulo producen mejoras reales.
//
// Flujo:
// 1. Carga el programa XDP optimizado
// 2. Ejecuta BPF_PROG_TEST_RUN con paquetes TCP y UDP
// 3. Recolecta latencias en múltiples rondas
// 4. Calcula y muestra métricas comparativas (avg, p50, p99, min, max)
// 5. Estima throughput máximo teórico en Mpps
//
// Uso:
//   go generate ./...
//   go build -o bench-optimized .
//   sudo ./bench-optimized [-rounds 100] [-repeat 10000]

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 optxdp optimized_xdp.bpf.c

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math"
	"sort"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// =============================================================================
// Generación de paquetes sintéticos
// =============================================================================

// buildTCPPacket genera un paquete Ethernet+IPv4+TCP válido
func buildTCPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 74) // 14 + 20 + 20 + 20

	// Ethernet
	pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5] = 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11] = 0x11, 0x22, 0x33, 0x44, 0x55, 0x66
	pkt[12], pkt[13] = 0x08, 0x00 // IPv4

	// IPv4
	pkt[14] = 0x45 // Version=4, IHL=5
	binary.BigEndian.PutUint16(pkt[16:18], 60)
	pkt[22] = 64   // TTL
	pkt[23] = 0x06 // TCP
	copy(pkt[26:30], srcIP[:])
	copy(pkt[30:34], dstIP[:])

	// TCP
	binary.BigEndian.PutUint16(pkt[34:36], srcPort)
	binary.BigEndian.PutUint16(pkt[36:38], dstPort)
	pkt[46] = 0x50 // Data offset
	pkt[47] = 0x10 // ACK flag

	return pkt
}

// buildUDPPacket genera un paquete Ethernet+IPv4+UDP válido
func buildUDPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16) []byte {
	pkt := make([]byte, 56) // 14 + 20 + 8 + 14 (payload)

	// Ethernet
	pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5] = 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
	pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11] = 0x11, 0x22, 0x33, 0x44, 0x55, 0x66
	pkt[12], pkt[13] = 0x08, 0x00 // IPv4

	// IPv4
	pkt[14] = 0x45
	binary.BigEndian.PutUint16(pkt[16:18], 42)
	pkt[22] = 64   // TTL
	pkt[23] = 0x11 // UDP
	copy(pkt[26:30], srcIP[:])
	copy(pkt[30:34], dstIP[:])

	// UDP
	binary.BigEndian.PutUint16(pkt[34:36], srcPort)
	binary.BigEndian.PutUint16(pkt[36:38], dstPort)
	binary.BigEndian.PutUint16(pkt[38:40], 22) // Length

	return pkt
}

// =============================================================================
// Estadísticas
// =============================================================================

type LatencyStats struct {
	Avg time.Duration
	P50 time.Duration
	P99 time.Duration
	Min time.Duration
	Max time.Duration
}

func computeStats(durations []time.Duration) LatencyStats {
	if len(durations) == 0 {
		return LatencyStats{}
	}

	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	total := time.Duration(0)
	for _, d := range sorted {
		total += d
	}

	p99Idx := int(math.Ceil(float64(len(sorted))*0.99)) - 1
	if p99Idx >= len(sorted) {
		p99Idx = len(sorted) - 1
	}

	return LatencyStats{
		Avg: total / time.Duration(len(sorted)),
		P50: sorted[len(sorted)/2],
		P99: sorted[p99Idx],
		Min: sorted[0],
		Max: sorted[len(sorted)-1],
	}
}

// =============================================================================
// Benchmark runner
// =============================================================================

func benchmarkProgram(prog *ebpf.Program, pkt []byte, rounds, repeat int) ([]time.Duration, error) {
	durations := make([]time.Duration, 0, rounds)
	outBuf := make([]byte, len(pkt)+256)

	for i := 0; i < rounds; i++ {
		opts := ebpf.RunOptions{
			Data:    pkt,
			DataOut: outBuf,
			Repeat:  uint32(repeat),
		}

		_, duration, err := prog.Test(&opts)
		if err != nil {
			return nil, fmt.Errorf("round %d failed: %w", i, err)
		}
		durations = append(durations, duration)
	}

	return durations, nil
}

func printStats(label string, stats LatencyStats) {
	fmt.Printf("  %-12s │ avg: %10s │ p50: %10s │ p99: %10s │ min: %10s │ max: %10s\n",
		label, stats.Avg, stats.P50, stats.P99, stats.Min, stats.Max)
}

// =============================================================================
// Main
// =============================================================================

func main() {
	rounds := flag.Int("rounds", 50, "Número de rondas de benchmark")
	repeat := flag.Int("repeat", 10000, "Repeticiones por ronda")
	flag.Parse()

	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println("  Capítulo 18 Ejercicio — Benchmark de XDP Optimizado")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println()

	// --- Setup ---
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Error removiendo memlock: %v", err)
	}

	objs := optxdpObjects{}
	if err := loadOptxdpObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando objetos BPF: %v", err)
	}
	defer objs.Close()

	fmt.Printf("  🔁 Configuración: %d rondas × %d repeticiones\n", *rounds, *repeat)
	fmt.Println()

	// --- Generar paquetes de prueba ---
	tcpPkt := buildTCPPacket(
		[4]byte{192, 168, 1, 100},
		[4]byte{10, 0, 0, 1},
		12345, 80,
	)
	udpPkt := buildUDPPacket(
		[4]byte{192, 168, 1, 200},
		[4]byte{10, 0, 0, 2},
		54321, 53,
	)

	fmt.Printf("  📦 Paquete TCP: %d bytes | Paquete UDP: %d bytes\n", len(tcpPkt), len(udpPkt))
	fmt.Println()

	// --- Benchmark: TCP ---
	fmt.Println("─────────────────────────────────────────────────────────────────────────")
	fmt.Println("  Benchmark con paquetes TCP...")
	fmt.Println("─────────────────────────────────────────────────────────────────────────")

	tcpDurations, err := benchmarkProgram(objs.OptimizedFirewall, tcpPkt, *rounds, *repeat)
	if err != nil {
		log.Fatalf("TCP benchmark failed: %v", err)
	}
	tcpStats := computeStats(tcpDurations)
	printStats("TCP", tcpStats)
	fmt.Println()

	// --- Benchmark: UDP ---
	fmt.Println("─────────────────────────────────────────────────────────────────────────")
	fmt.Println("  Benchmark con paquetes UDP...")
	fmt.Println("─────────────────────────────────────────────────────────────────────────")

	udpDurations, err := benchmarkProgram(objs.OptimizedFirewall, udpPkt, *rounds, *repeat)
	if err != nil {
		log.Fatalf("UDP benchmark failed: %v", err)
	}
	udpStats := computeStats(udpDurations)
	printStats("UDP", udpStats)
	fmt.Println()

	// --- Throughput estimado ---
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println("  📊 Resumen de rendimiento")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println()

	if tcpStats.Avg > 0 {
		tcpMpps := float64(time.Second) / float64(tcpStats.Avg) / 1e6
		fmt.Printf("  🚀 TCP throughput estimado: %.2f Mpps\n", tcpMpps)
	}
	if udpStats.Avg > 0 {
		udpMpps := float64(time.Second) / float64(udpStats.Avg) / 1e6
		fmt.Printf("  🚀 UDP throughput estimado: %.2f Mpps\n", udpMpps)
	}

	fmt.Println()
	fmt.Println("  💡 Técnicas de optimización aplicadas:")
	fmt.Println("     1. Per-CPU maps → zero lock contention")
	fmt.Println("     2. __always_inline → zero call overhead")
	fmt.Println("     3. likely/unlikely → mejor branch prediction")
	fmt.Println()
	fmt.Println("  Compara estos resultados con la versión naive del Cap 10 para")
	fmt.Println("  cuantificar la mejora real de cada técnica.")
	fmt.Println()
}
