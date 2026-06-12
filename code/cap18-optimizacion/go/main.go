// Capítulo 18 — BPF_PROG_TEST_RUN: Benchmarking de programas XDP
//
// Este programa Go demuestra cómo usar BPF_PROG_TEST_RUN para medir el
// rendimiento de un programa XDP sin necesidad de una interfaz de red real.
//
// BPF_PROG_TEST_RUN permite:
// - Ejecutar un programa BPF con datos de entrada sintéticos
// - Repetir la ejecución N veces en un solo syscall
// - Obtener la duración en nanosegundos por ejecución
// - Verificar el código de retorno (XDP_PASS, XDP_DROP, etc.)
//
// El benchmark ejecuta múltiples rondas para calcular estadísticas:
// - Average (promedio aritmético)
// - P50 (mediana)
// - P99 (percentil 99 — peor caso típico)
// - Min / Max
//
// Uso:
//   go generate ./...
//   go build -o bench-xdp .
//   sudo ./bench-xdp [-rounds 100] [-repeat 10000]

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bench prog_test_run.bpf.c

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
// Paquete sintético para benchmark
// =============================================================================

// buildTCPPacket construye un paquete Ethernet+IPv4+TCP válido para testing.
// El paquete simula tráfico HTTP (puerto 80) de 10.0.0.1 → 10.0.0.2.
func buildTCPPacket() []byte {
	pkt := make([]byte, 74) // 14 (eth) + 20 (ip) + 20 (tcp) + 20 (payload)

	// --- Ethernet header (14 bytes) ---
	// dst MAC: 00:00:00:00:00:02
	pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5] = 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
	// src MAC: 00:00:00:00:00:01
	pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11] = 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
	// EtherType: IPv4 (0x0800)
	pkt[12], pkt[13] = 0x08, 0x00

	// --- IPv4 header (20 bytes) ---
	pkt[14] = 0x45 // Version=4, IHL=5
	pkt[15] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[16:18], 60) // Total length
	binary.BigEndian.PutUint16(pkt[18:20], 0x1234) // ID
	pkt[20], pkt[21] = 0x00, 0x00 // Flags/Fragment
	pkt[22] = 64   // TTL
	pkt[23] = 0x06 // Protocol: TCP
	pkt[24], pkt[25] = 0x00, 0x00 // Checksum (skipped for test)
	// Src IP: 10.0.0.1
	pkt[26], pkt[27], pkt[28], pkt[29] = 10, 0, 0, 1
	// Dst IP: 10.0.0.2
	pkt[30], pkt[31], pkt[32], pkt[33] = 10, 0, 0, 2

	// --- TCP header (20 bytes) ---
	binary.BigEndian.PutUint16(pkt[34:36], 12345) // Src port
	binary.BigEndian.PutUint16(pkt[36:38], 80)    // Dst port
	binary.BigEndian.PutUint32(pkt[38:42], 1)     // Seq number
	binary.BigEndian.PutUint32(pkt[42:46], 0)     // Ack number
	pkt[46] = 0x50 // Data offset (5 words = 20 bytes)
	pkt[47] = 0x02 // Flags: SYN
	binary.BigEndian.PutUint16(pkt[48:50], 65535) // Window
	pkt[50], pkt[51] = 0x00, 0x00 // Checksum
	pkt[52], pkt[53] = 0x00, 0x00 // Urgent pointer

	return pkt
}

// =============================================================================
// Estadísticas
// =============================================================================

// BenchResult contiene las métricas de una sesión de benchmark
type BenchResult struct {
	Rounds      int
	RepeatPerRd int
	Durations   []time.Duration // Duración por ronda (promedio de repeat ejecuciones)
	TotalTime   time.Duration
}

// Stats calcula las estadísticas del benchmark
func (r *BenchResult) Stats() (avg, p50, p99, min, max time.Duration) {
	if len(r.Durations) == 0 {
		return
	}

	// Ordenar para percentiles
	sorted := make([]time.Duration, len(r.Durations))
	copy(sorted, r.Durations)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	// Min / Max
	min = sorted[0]
	max = sorted[len(sorted)-1]

	// Promedio
	total := time.Duration(0)
	for _, d := range sorted {
		total += d
	}
	avg = total / time.Duration(len(sorted))

	// P50 (mediana)
	p50Idx := len(sorted) / 2
	p50 = sorted[p50Idx]

	// P99
	p99Idx := int(math.Ceil(float64(len(sorted))*0.99)) - 1
	if p99Idx >= len(sorted) {
		p99Idx = len(sorted) - 1
	}
	p99 = sorted[p99Idx]

	return
}

// =============================================================================
// Benchmark con BPF_PROG_TEST_RUN
// =============================================================================

// runBenchmark ejecuta el programa BPF `rounds` veces, cada vez con `repeat`
// repeticiones internas. Retorna las métricas recolectadas.
func runBenchmark(prog *ebpf.Program, pkt []byte, rounds, repeat int) (*BenchResult, error) {
	result := &BenchResult{
		Rounds:      rounds,
		RepeatPerRd: repeat,
		Durations:   make([]time.Duration, 0, rounds),
	}

	outBuf := make([]byte, len(pkt)+256) // Buffer de salida (puede crecer con encapsulación)

	start := time.Now()

	for i := 0; i < rounds; i++ {
		opts := ebpf.RunOptions{
			Data:       pkt,
			DataOut:    outBuf,
			Repeat:     uint32(repeat),
		}

		ret, duration, err := prog.Test(&opts)
		if err != nil {
			return nil, fmt.Errorf("round %d: prog_test_run failed: %w", i, err)
		}

		// duration es el tiempo total dividido por repeat (ns por ejecución)
		_ = ret
		result.Durations = append(result.Durations, duration)
	}

	result.TotalTime = time.Since(start)
	return result, nil
}

// =============================================================================
// Main
// =============================================================================

func main() {
	rounds := flag.Int("rounds", 50, "Número de rondas de benchmark")
	repeat := flag.Int("repeat", 10000, "Repeticiones por ronda (BPF_PROG_TEST_RUN repeat)")
	flag.Parse()

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Capítulo 18 — BPF_PROG_TEST_RUN: Benchmark de XDP")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// --- Remover memlock ---
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Error removiendo memlock: %v", err)
	}

	// --- Cargar objetos BPF ---
	objs := benchObjects{}
	if err := loadBenchObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando objetos BPF: %v", err)
	}
	defer objs.Close()

	// --- Construir paquete de prueba ---
	pkt := buildTCPPacket()
	fmt.Printf("  📦 Paquete de prueba: %d bytes (Ethernet+IPv4+TCP)\n", len(pkt))
	fmt.Printf("  🔁 Configuración: %d rondas × %d repeticiones/ronda\n", *rounds, *repeat)
	fmt.Println()

	// --- Ejecutar benchmark ---
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("  Ejecutando benchmark...")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println()

	result, err := runBenchmark(objs.XdpBench, pkt, *rounds, *repeat)
	if err != nil {
		log.Fatalf("Error en benchmark: %v", err)
	}

	// --- Calcular y mostrar resultados ---
	avg, p50, p99, min, max := result.Stats()

	fmt.Println("  📊 Resultados de latencia por ejecución:")
	fmt.Println()
	fmt.Printf("     ┌─────────────┬────────────────────┐\n")
	fmt.Printf("     │ Métrica     │ Valor              │\n")
	fmt.Printf("     ├─────────────┼────────────────────┤\n")
	fmt.Printf("     │ Average     │ %18s │\n", avg)
	fmt.Printf("     │ P50         │ %18s │\n", p50)
	fmt.Printf("     │ P99         │ %18s │\n", p99)
	fmt.Printf("     │ Min         │ %18s │\n", min)
	fmt.Printf("     │ Max         │ %18s │\n", max)
	fmt.Printf("     └─────────────┴────────────────────┘\n")
	fmt.Println()
	fmt.Printf("  ⏱️  Tiempo total del benchmark: %s\n", result.TotalTime)
	fmt.Printf("  📈 Ejecuciones totales: %d\n", *rounds**repeat)
	fmt.Println()

	// --- Throughput estimado ---
	if avg > 0 {
		pps := float64(time.Second) / float64(avg)
		fmt.Printf("  🚀 Throughput estimado: %.2f Mpps (millones de paquetes/seg)\n", pps/1e6)
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Benchmark completado.")
	fmt.Println("═══════════════════════════════════════════════════════════════")
}
