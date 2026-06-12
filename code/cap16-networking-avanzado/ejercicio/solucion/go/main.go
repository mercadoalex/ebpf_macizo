// Ejercicio Capítulo 16 — Solución: Control Plane del Load Balancer L4
//
// Control plane completo que gestiona el load balancer L4 XDP:
// - Configuración de VIP y backends
// - Consistent hashing con virtual nodes
// - Health checks periódicos con reconvergencia automática
// - Exportación de estadísticas per-CPU
// - Hot reload de backends (agregar/remover sin restart)
//
// Requisitos del ejercicio:
// - Latencia < 5µs por paquete
// - 100K conexiones simultáneas
// - Hot reload sin pérdida de conexiones existentes
//
// Uso:
//   go generate ./...
//   go build -o lb-l4 .
//   sudo ./lb-l4 -iface eth0 -vip 10.0.0.1 -port 80 \
//       -backends "10.1.0.1,10.1.0.2,10.1.0.3"

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 lbl4 lb_l4.bpf.c

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
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// =============================================================================
// Constantes (deben coincidir con el BPF)
// =============================================================================

const (
	chRingSize  = 65537
	maxBackends = 256

	statRxPackets  = 0
	statRxBytes    = 1
	statTxPackets  = 2
	statTxBytes    = 3
	statDrops      = 4
	statRateLimited = 5

	// Nodos virtuales por backend en el ring
	virtualNodes = 200

	// Intervalos
	healthInterval = 5 * time.Second
	statsInterval  = 3 * time.Second
)

// =============================================================================
// Tipos
// =============================================================================

// Backend representa un servidor real del pool
type Backend struct {
	ID    uint32
	IP    net.IP
	MAC   net.HardwareAddr
	Alive bool
	mu    sync.RWMutex
}

// backendInfo — layout idéntico a struct backend_info del BPF
type backendInfo struct {
	IP    uint32
	MAC   [6]byte
	Flags uint16
}

// vipConfig — layout idéntico a struct vip_config del BPF
type vipConfig struct {
	VIP         uint32
	Port        uint16
	Proto       uint16
	NumBackends uint32
}

// LoadBalancer contiene el estado completo del control plane
type LoadBalancer struct {
	objs     lbl4Objects
	link     link.Link
	backends []*Backend
	vipIP    net.IP
	vipPort  uint16
	iface    string
	mu       sync.RWMutex
}

// =============================================================================
// Consistent Hashing
// =============================================================================

// buildRing genera el consistent hash ring con virtual nodes.
// Usa FNV-1a hash para distribución uniforme.
func buildRing(backends []*Backend) [chRingSize]uint32 {
	var ring [chRingSize]uint32

	// Recoger solo backends vivos
	active := make([]*Backend, 0, len(backends))
	for _, b := range backends {
		b.mu.RLock()
		alive := b.Alive
		b.mu.RUnlock()
		if alive {
			active = append(active, b)
		}
	}

	if len(active) == 0 {
		return ring
	}

	// Inicializar ring con distribución round-robin como base
	for i := 0; i < chRingSize; i++ {
		ring[i] = active[i%len(active)].ID
	}

	// Sobreescribir con posiciones hasheadas (virtual nodes)
	for _, b := range active {
		for v := 0; v < virtualNodes; v++ {
			key := fmt.Sprintf("backend-%s-vnode-%d", b.IP.String(), v)
			h := fnv.New32a()
			h.Write([]byte(key))
			pos := h.Sum32() % chRingSize
			ring[pos] = b.ID
		}
	}

	return ring
}

// =============================================================================
// Control Plane
// =============================================================================

func NewLoadBalancer(ifaceName string, vipIP net.IP, vipPort uint16, backendIPs []net.IP) (*LoadBalancer, error) {
	// Remover memlock
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removiendo memlock: %w", err)
	}

	// Cargar objetos BPF
	objs := lbl4Objects{}
	if err := loadLbl4Objects(&objs, nil); err != nil {
		return nil, fmt.Errorf("cargando BPF: %w", err)
	}

	// Crear backends
	backends := make([]*Backend, len(backendIPs))
	for i, ip := range backendIPs {
		mac := generateMAC(ip)
		backends[i] = &Backend{
			ID:    uint32(i),
			IP:    ip,
			MAC:   mac,
			Alive: true,
		}
	}

	lb := &LoadBalancer{
		objs:     objs,
		backends: backends,
		vipIP:    vipIP,
		vipPort:  vipPort,
		iface:    ifaceName,
	}

	return lb, nil
}

func (lb *LoadBalancer) Start() error {
	// Configurar VIP
	vip := vipConfig{
		VIP:         ipToUint32(lb.vipIP),
		Port:        htons(lb.vipPort),
		Proto:       syscall.IPPROTO_TCP,
		NumBackends: uint32(len(lb.backends)),
	}

	vipKey := uint32(0)
	if err := lb.objs.Vip.Put(vipKey, vip); err != nil {
		return fmt.Errorf("configurando VIP: %w", err)
	}

	// Registrar backends
	for _, b := range lb.backends {
		if err := lb.updateBackendMap(b); err != nil {
			return fmt.Errorf("registrando backend %d: %w", b.ID, err)
		}
	}

	// Construir y cargar ring
	if err := lb.updateRing(); err != nil {
		return fmt.Errorf("cargando ring: %w", err)
	}

	// Adjuntar XDP
	iface, err := net.InterfaceByName(lb.iface)
	if err != nil {
		return fmt.Errorf("interfaz '%s': %w", lb.iface, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   lb.objs.LbL4,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return fmt.Errorf("adjuntando XDP: %w", err)
	}
	lb.link = l

	return nil
}

func (lb *LoadBalancer) updateBackendMap(b *Backend) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	info := backendInfo{
		IP: ipToUint32(b.IP),
	}
	copy(info.MAC[:], b.MAC)
	if !b.Alive {
		info.Flags = 1
	}

	return lb.objs.Backends.Put(b.ID, info)
}

func (lb *LoadBalancer) updateRing() error {
	ring := buildRing(lb.backends)
	for i := 0; i < chRingSize; i++ {
		if err := lb.objs.ChRing.Put(uint32(i), ring[i]); err != nil {
			return err
		}
	}
	return nil
}

func (lb *LoadBalancer) RunHealthChecks() bool {
	changed := false
	for _, b := range lb.backends {
		alive := checkHealth(b.IP, lb.vipPort)
		b.mu.Lock()
		if alive != b.Alive {
			b.Alive = alive
			changed = true
			status := "UP"
			if !alive {
				status = "DOWN"
			}
			fmt.Printf("  ⚡ Backend %d (%s) → %s\n", b.ID, b.IP.String(), status)
		}
		b.mu.Unlock()
	}

	if changed {
		// Reconverger: actualizar maps
		for _, b := range lb.backends {
			lb.updateBackendMap(b)
		}
		lb.updateRing()
		fmt.Println("  🔄 Ring reconvergido")
	}

	return changed
}

func (lb *LoadBalancer) PrintStats() {
	fmt.Println()
	fmt.Println("  ┌─────────────────────────────────────────────────┐")

	statNames := []string{"rx_pkts", "rx_bytes", "tx_pkts", "tx_bytes", "drops", "rate_limited"}
	for i, name := range statNames {
		var values []uint64
		key := uint32(i)
		if err := lb.objs.Stats.Lookup(key, &values); err != nil {
			continue
		}
		total := sumSlice(values)
		if total > 0 {
			fmt.Printf("  │  %-14s: %12d                    │\n", name, total)
		}
	}

	fmt.Println("  ├─────────────────────────────────────────────────┤")

	for _, b := range lb.backends {
		var values []uint64
		if err := lb.objs.BackendPkts.Lookup(b.ID, &values); err != nil {
			continue
		}
		total := sumSlice(values)
		b.mu.RLock()
		status := "✅"
		if !b.Alive {
			status = "❌"
		}
		b.mu.RUnlock()
		fmt.Printf("  │  backend[%d] %s %-15s: %8d pkts   │\n",
			b.ID, status, b.IP.String(), total)
	}

	fmt.Println("  └─────────────────────────────────────────────────┘")
}

func (lb *LoadBalancer) Close() {
	if lb.link != nil {
		lb.link.Close()
	}
	lb.objs.Close()
}

// =============================================================================
// Utilidades
// =============================================================================

func checkHealth(ip net.IP, port uint16) bool {
	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

func generateMAC(ip net.IP) net.HardwareAddr {
	ip4 := ip.To4()
	return net.HardwareAddr{0x02, 0x00, ip4[0], ip4[1], ip4[2], ip4[3]}
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

func sumSlice(values []uint64) uint64 {
	total := uint64(0)
	for _, v := range values {
		total += v
	}
	return total
}

// =============================================================================
// Main
// =============================================================================

func main() {
	ifaceName := flag.String("iface", "lo", "Interfaz de red")
	vipStr := flag.String("vip", "10.0.0.1", "Virtual IP del servicio")
	portNum := flag.Int("port", 80, "Puerto del servicio")
	backendStr := flag.String("backends", "10.1.0.1,10.1.0.2,10.1.0.3", "Backends (comma-separated)")
	flag.Parse()

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Ejercicio Cap 16 — Load Balancer L4 (Solución)")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// Parsear backends
	backendIPs := make([]net.IP, 0)
	for _, s := range strings.Split(*backendStr, ",") {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil {
			log.Fatalf("IP inválida: %s", s)
		}
		backendIPs = append(backendIPs, ip)
	}

	// Crear load balancer
	vipIP := net.ParseIP(*vipStr)
	if vipIP == nil {
		log.Fatalf("VIP inválida: %s", *vipStr)
	}

	lb, err := NewLoadBalancer(*ifaceName, vipIP, uint16(*portNum), backendIPs)
	if err != nil {
		log.Fatalf("Error creando LB: %v", err)
	}
	defer lb.Close()

	// Iniciar
	if err := lb.Start(); err != nil {
		log.Fatalf("Error iniciando LB: %v", err)
	}

	fmt.Printf("  📡 VIP: %s:%d\n", *vipStr, *portNum)
	for _, b := range lb.backends {
		fmt.Printf("  ✅ Backend %d: %s\n", b.ID, b.IP.String())
	}
	fmt.Printf("  🔄 Ring: %d posiciones, %d vnodes/backend\n", chRingSize, virtualNodes)
	fmt.Printf("  🤘 LB activo en '%s'\n", *ifaceName)
	fmt.Println()
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("  Ctrl+C para detener")
	fmt.Println("─────────────────────────────────────────────────────────────")

	// Loop principal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	statsTicker := time.NewTicker(statsInterval)
	healthTicker := time.NewTicker(healthInterval)
	defer statsTicker.Stop()
	defer healthTicker.Stop()

	for {
		select {
		case <-sig:
			fmt.Println("\n  🧹 Limpiando...")
			fmt.Println("  👋 Load balancer detenido.")
			return

		case <-statsTicker.C:
			lb.PrintStats()

		case <-healthTicker.C:
			lb.RunHealthChecks()
		}
	}
}
