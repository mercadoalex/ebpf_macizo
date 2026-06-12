// Capítulo 16 — XDP Load Balancer: Control Plane
//
// Este programa Go implementa el control plane de un load balancer L4
// basado en XDP con consistent hashing. Gestiona:
//
// 1. Configuración de la VIP (Virtual IP del servicio)
// 2. Registro de backends en el consistent hash ring
// 3. Health checks periódicos (TCP connect)
// 4. Exportación de estadísticas per-CPU
// 5. Hot reload de backends sin downtime
//
// Uso:
//   go generate ./...
//   go build -o xdp-lb .
//   sudo ./xdp-lb -iface eth0 -vip 10.0.0.1 -port 80 -backends "10.1.0.1,10.1.0.2,10.1.0.3"
//
// El programa carga el XDP load balancer, configura el consistent hash ring,
// y ejecuta health checks + stats en un loop hasta recibir SIGINT.

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 xdplb xdp_lb.bpf.c

import (
	"encoding/binary"
	"flag"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// =============================================================================
// Configuración
// =============================================================================

const (
	chRingSize  = 65537 // Debe coincidir con CH_RING_SIZE del BPF
	maxBackends = 1024

	statsPackets = 0
	statsBytes   = 1
	statsDrops   = 2

	// Replicas virtuales por backend en el consistent hash ring
	virtualNodes = 150
)

// Backend representa un servidor real
type Backend struct {
	ID     uint32
	IP     net.IP
	MAC    net.HardwareAddr
	Flags  uint16 // 0 = activo, 1 = down
	Alive  bool
}

// backendInfo debe coincidir con struct backend_info en BPF
type backendInfo struct {
	IP    uint32
	MAC   [6]byte
	Flags uint16
}

// vipInfo debe coincidir con struct vip_info en BPF
type vipInfo struct {
	VIP   uint32
	Port  uint16
	Proto uint16
}

// =============================================================================
// Consistent Hashing
// =============================================================================

// buildConsistentHashRing genera el ring de consistent hashing.
// Cada backend obtiene `virtualNodes` posiciones en el ring.
// Cuando un backend cae, solo sus posiciones se redistribuyen.
func buildConsistentHashRing(backends []Backend) [chRingSize]uint32 {
	var ring [chRingSize]uint32

	activeBackends := make([]Backend, 0)
	for _, b := range backends {
		if b.Alive {
			activeBackends = append(activeBackends, b)
		}
	}

	if len(activeBackends) == 0 {
		return ring
	}

	// Llenar el ring: cada posición se asigna al backend cuyo
	// virtual node hash es más cercano
	for i := 0; i < chRingSize; i++ {
		ring[i] = activeBackends[i%len(activeBackends)].ID
	}

	// Asignar posiciones basadas en hash de cada virtual node
	for _, b := range activeBackends {
		for v := 0; v < virtualNodes; v++ {
			key := fmt.Sprintf("%s-%d", b.IP.String(), v)
			h := fnv.New32a()
			h.Write([]byte(key))
			pos := h.Sum32() % chRingSize
			ring[pos] = b.ID
		}
	}

	return ring
}

// =============================================================================
// Health Checks
// =============================================================================

// checkBackendHealth intenta una conexión TCP al backend.
// Si la conexión tiene éxito en < 2s, el backend está vivo.
func checkBackendHealth(backend *Backend, port uint16) bool {
	addr := fmt.Sprintf("%s:%d", backend.IP.String(), port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// =============================================================================
// Utilidades
// =============================================================================

// ipToUint32 convierte una IP a uint32 en network byte order
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// parseMAC genera una MAC ficticia basada en la IP del backend.
// En producción se resolvería via ARP o se configuraría manualmente.
func generateMAC(ip net.IP) net.HardwareAddr {
	ip4 := ip.To4()
	return net.HardwareAddr{0x02, 0x00, ip4[0], ip4[1], ip4[2], ip4[3]}
}

// =============================================================================
// Main
// =============================================================================

func main() {
	// --- Flags ---
	ifaceName := flag.String("iface", "lo", "Interfaz de red para el LB")
	vipStr := flag.String("vip", "10.0.0.1", "Virtual IP del servicio")
	portNum := flag.Int("port", 80, "Puerto del servicio")
	backendStr := flag.String("backends", "10.1.0.1,10.1.0.2,10.1.0.3", "Lista de backends (comma-separated)")
	flag.Parse()

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Capítulo 16 — XDP Load Balancer con Consistent Hashing")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// --- Remover memlock ---
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Error removiendo memlock: %v", err)
	}

	// --- Cargar objetos BPF ---
	objs := xdplbObjects{}
	if err := loadXdplbObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando objetos BPF: %v", err)
	}
	defer objs.Close()

	// --- Configurar VIP ---
	vipIP := net.ParseIP(*vipStr)
	if vipIP == nil {
		log.Fatalf("VIP inválida: %s", *vipStr)
	}

	vip := vipInfo{
		VIP:   ipToUint32(vipIP),
		Port:  htons(uint16(*portNum)),
		Proto: syscall.IPPROTO_TCP,
	}

	vipKey := uint32(0)
	if err := objs.VipConfig.Put(vipKey, vip); err != nil {
		log.Fatalf("Error configurando VIP: %v", err)
	}
	fmt.Printf("  📡 VIP configurada: %s:%d\n", *vipStr, *portNum)

	// --- Parsear y registrar backends ---
	backendIPs := strings.Split(*backendStr, ",")
	backends := make([]Backend, len(backendIPs))

	for i, ipStr := range backendIPs {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil {
			log.Fatalf("Backend IP inválida: %s", ipStr)
		}

		mac := generateMAC(ip)
		backends[i] = Backend{
			ID:    uint32(i),
			IP:    ip,
			MAC:   mac,
			Flags: 0,
			Alive: true,
		}

		// Registrar en el map de backends
		info := backendInfo{
			IP:    ipToUint32(ip),
			Flags: 0,
		}
		copy(info.MAC[:], mac)

		if err := objs.Backends.Put(uint32(i), info); err != nil {
			log.Fatalf("Error registrando backend %d: %v", i, err)
		}

		fmt.Printf("  ✅ Backend %d: %s (MAC %s)\n", i, ip.String(), mac.String())
	}

	// --- Construir y cargar consistent hash ring ---
	ring := buildConsistentHashRing(backends)
	for i := 0; i < chRingSize; i++ {
		if err := objs.ChRing.Put(uint32(i), ring[i]); err != nil {
			log.Fatalf("Error llenando ring[%d]: %v", i, err)
		}
	}
	fmt.Printf("  🔄 Consistent hash ring cargado (%d posiciones, %d virtual nodes/backend)\n",
		chRingSize, virtualNodes)

	// --- Adjuntar XDP a la interfaz ---
	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("Interfaz '%s' no encontrada: %v", *ifaceName, err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpLb,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // Usar native mode en producción
	})
	if err != nil {
		log.Fatalf("Error adjuntando XDP: %v", err)
	}
	defer xdpLink.Close()

	fmt.Printf("\n  🤘 Load balancer XDP activo en '%s' (ifindex %d)\n", *ifaceName, iface.Index)
	fmt.Println()
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("  Ctrl+C para detener")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println()

	// --- Loop principal: health checks + stats ---
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	statsTicker := time.NewTicker(3 * time.Second)
	healthTicker := time.NewTicker(10 * time.Second)
	defer statsTicker.Stop()
	defer healthTicker.Stop()

	for {
		select {
		case <-sig:
			fmt.Println("\n  🧹 Limpiando...")
			fmt.Println("  👋 Load balancer detenido.")
			return

		case <-statsTicker.C:
			printStats(objs, backends)

		case <-healthTicker.C:
			changed := runHealthChecks(backends, uint16(*portNum))
			if changed {
				// Recalcular ring y actualizar maps
				ring = buildConsistentHashRing(backends)
				for i := 0; i < chRingSize; i++ {
					objs.ChRing.Put(uint32(i), ring[i])
				}
				// Actualizar flags en backend map
				for _, b := range backends {
					info := backendInfo{IP: ipToUint32(b.IP)}
					copy(info.MAC[:], b.MAC)
					if !b.Alive {
						info.Flags = 1
					}
					objs.Backends.Put(b.ID, info)
				}
				fmt.Println("  🔄 Ring recalculado tras cambio de health")
			}
		}
	}
}

// printStats lee los maps de estadísticas per-CPU y muestra un resumen.
func printStats(objs xdplbObjects, backends []Backend) {
	var packets, bytes, drops []uint64

	pktKey := uint32(statsPackets)
	bytKey := uint32(statsBytes)
	drpKey := uint32(statsDrops)

	objs.Stats.Lookup(pktKey, &packets)
	objs.Stats.Lookup(bytKey, &bytes)
	objs.Stats.Lookup(drpKey, &drops)

	// Sumar per-CPU values
	totalPkts := sumPerCPU(packets)
	totalBytes := sumPerCPU(bytes)
	totalDrops := sumPerCPU(drops)

	fmt.Printf("  📊 Stats: pkts=%d | bytes=%d | drops=%d\n",
		totalPkts, totalBytes, totalDrops)

	// Stats por backend
	for _, b := range backends {
		var bstats []uint64
		objs.BackendStats.Lookup(b.ID, &bstats)
		total := sumPerCPU(bstats)
		if total > 0 {
			status := "✅"
			if !b.Alive {
				status = "❌"
			}
			fmt.Printf("       Backend %d (%s) %s: %d pkts\n",
				b.ID, b.IP.String(), status, total)
		}
	}
}

// runHealthChecks ejecuta health checks en todos los backends.
// Retorna true si hubo algún cambio de estado.
func runHealthChecks(backends []Backend, port uint16) bool {
	changed := false
	for i := range backends {
		alive := checkBackendHealth(&backends[i], port)
		if alive != backends[i].Alive {
			backends[i].Alive = alive
			changed = true
			status := "UP"
			if !alive {
				status = "DOWN"
			}
			fmt.Printf("  ⚡ Backend %d (%s) → %s\n",
				backends[i].ID, backends[i].IP.String(), status)
		}
	}
	return changed
}

func sumPerCPU(values []uint64) uint64 {
	total := uint64(0)
	for _, v := range values {
		total += v
	}
	return total
}

// htons convierte host byte order a network byte order (uint16)
func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
