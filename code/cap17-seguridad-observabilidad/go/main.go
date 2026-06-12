// Capítulo 17 — Seguridad y Observabilidad: Runtime Security Monitor
//
// Este programa Go carga dos programas BPF complementarios:
//
// 1. LSM file_open — Deniega acceso a archivos sensibles (enforcement)
// 2. Syscall monitor — Detecta patrones sospechosos (execve, setns, unshare)
//
// Ambos programas emiten eventos via ring buffer que este control plane
// consume y presenta como alertas de seguridad clasificadas por severidad.
//
// Esto demuestra cómo combinar enforcement (LSM) con detección (tracepoints)
// para construir un runtime security system — el patrón que usan Falco y Tetragon.
//
// Uso:
//   go generate ./...
//   go build -o security-monitor .
//   sudo ./security-monitor
//
// El programa carga ambos programas BPF, configura las políticas de
// seguridad, y consume eventos en un loop hasta SIGINT.
//
// Requisitos:
// - Kernel >= 5.7 con CONFIG_BPF_LSM=y y lsm=bpf en boot cmdline
// - BTF habilitado (CONFIG_DEBUG_INFO_BTF=y)
// - Ejecutar como root (CAP_BPF + CAP_MAC_ADMIN)

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 lsmFileOpen lsm_file_open.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 syscallMonitor syscall_monitor.bpf.c

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// =============================================================================
// Constantes (deben coincidir con los programas BPF)
// =============================================================================

const (
	maxFileNameLen = 64
	maxBinLen      = 64

	// Severity levels
	severityInfo     = 0
	severityWarning  = 1
	severityCritical = 2

	// Event types (syscall monitor)
	eventExecveContainer = 1
	eventSetns           = 2
	eventUnshare         = 3
	eventSuspiciousExec  = 4
)

// =============================================================================
// Estructuras (deben coincidir con los programas BPF)
// =============================================================================

// securityEvent corresponde a struct security_event en lsm_file_open.bpf.c
type securityEvent struct {
	TimestampNs uint64
	PID         uint32
	UID         uint32
	Action      uint32 // 0 = denied, 1 = allowed (audit)
	Comm        [16]byte
	Filename    [maxFileNameLen]byte
}

// syscallAlert corresponde a struct syscall_alert en syscall_monitor.bpf.c
type syscallAlert struct {
	TimestampNs uint64
	PID         uint32
	TGID        uint32
	UID         uint32
	EventType   uint32
	Severity    uint32
	NamespaceID uint32
	Comm        [16]byte
	Filename    [maxBinLen]byte
}

// protectedPath corresponde a struct protected_path en BPF
type protectedPath struct {
	Filename [maxFileNameLen]byte
	Enforce  uint32
	Pad      uint32
}

// =============================================================================
// Utilidades
// =============================================================================

func nullTermStr(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		return string(b)
	}
	return string(b[:n])
}

func severityStr(s uint32) string {
	switch s {
	case severityInfo:
		return "INFO"
	case severityWarning:
		return "⚠️  WARNING"
	case severityCritical:
		return "🚨 CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func eventTypeStr(t uint32) string {
	switch t {
	case eventExecveContainer:
		return "EXECVE_CONTAINER"
	case eventSetns:
		return "SETNS"
	case eventUnshare:
		return "UNSHARE"
	case eventSuspiciousExec:
		return "SUSPICIOUS_EXEC"
	default:
		return "UNKNOWN"
	}
}

func actionStr(a uint32) string {
	if a == 0 {
		return "🚫 DENIED"
	}
	return "👁️  AUDIT"
}

// =============================================================================
// Main
// =============================================================================

func main() {
	// --- Flags ---
	protectedFilesStr := flag.String("protect", "/etc/shadow,/etc/sudoers",
		"Archivos a proteger (comma-separated)")
	enforceMode := flag.Bool("enforce", false,
		"Modo enforce: deniega acceso (requiere LSM BPF). Sin flag = audit only")
	suspiciousBinsStr := flag.String("suspicious", "nsenter,mount,unshare,chroot,pivot_root",
		"Binarios sospechosos a monitorear (comma-separated)")
	flag.Parse()

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Capítulo 17 — Runtime Security Monitor")
	fmt.Println("  LSM File Protection + Syscall Monitoring")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// --- Remover memlock ---
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Error removiendo memlock: %v", err)
	}

	// --- Cargar programa LSM ---
	lsmObjs := lsmFileOpenObjects{}
	if err := loadLsmFileOpenObjects(&lsmObjs, nil); err != nil {
		log.Fatalf("Error cargando LSM objects: %v\n"+
			"  Nota: LSM BPF requiere kernel con CONFIG_BPF_LSM=y y 'lsm=bpf' en cmdline", err)
	}
	defer lsmObjs.Close()

	// --- Cargar programa syscall monitor ---
	monObjs := syscallMonitorObjects{}
	if err := loadSyscallMonitorObjects(&monObjs, nil); err != nil {
		log.Fatalf("Error cargando syscall monitor objects: %v", err)
	}
	defer monObjs.Close()

	// --- Configurar archivos protegidos ---
	protectedFiles := strings.Split(*protectedFilesStr, ",")
	fmt.Println("  📁 Archivos protegidos:")
	for _, f := range protectedFiles {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}

		// Usar solo el nombre base del archivo como key
		parts := strings.Split(f, "/")
		basename := parts[len(parts)-1]

		var key [maxFileNameLen]byte
		copy(key[:], basename)

		enforce := uint32(0)
		if *enforceMode {
			enforce = 1
		}

		val := protectedPath{
			Enforce: enforce,
		}
		copy(val.Filename[:], basename)

		if err := lsmObjs.ProtectedFiles.Put(key, val); err != nil {
			log.Printf("  ⚠️  Error protegiendo '%s': %v", f, err)
			continue
		}

		mode := "audit"
		if *enforceMode {
			mode = "enforce"
		}
		fmt.Printf("    ✅ %s → %s\n", f, mode)
	}

	// --- Configurar binarios sospechosos ---
	suspiciousBins := strings.Split(*suspiciousBinsStr, ",")
	fmt.Println("\n  🔍 Binarios sospechosos monitoreados:")
	for _, b := range suspiciousBins {
		b = strings.TrimSpace(b)
		if b == "" {
			continue
		}

		var key [maxBinLen]byte
		copy(key[:], b)

		// Severidad: nsenter y mount son CRITICAL, otros WARNING
		severity := uint32(severityWarning)
		if b == "nsenter" || b == "mount" || b == "pivot_root" {
			severity = severityCritical
		}

		if err := monObjs.SuspiciousBins.Put(key, severity); err != nil {
			log.Printf("  ⚠️  Error configurando '%s': %v", b, err)
			continue
		}
		fmt.Printf("    ✅ %s → %s\n", b, severityStr(severity))
	}

	// --- Adjuntar LSM hook ---
	lsmLink, err := link.AttachLSM(link.LSMOptions{
		Program: lsmObjs.LsmFileOpen,
	})
	if err != nil {
		log.Fatalf("Error adjuntando LSM hook: %v\n"+
			"  Verificar: cat /sys/kernel/security/lsm (debe incluir 'bpf')", err)
	}
	defer lsmLink.Close()
	fmt.Println("\n  🔒 LSM file_open hook adjuntado")

	// --- Adjuntar tracepoints ---
	tpExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", monObjs.TraceExecve, nil)
	if err != nil {
		log.Fatalf("Error adjuntando tracepoint execve: %v", err)
	}
	defer tpExecve.Close()

	tpSetns, err := link.Tracepoint("syscalls", "sys_enter_setns", monObjs.TraceSetns, nil)
	if err != nil {
		log.Fatalf("Error adjuntando tracepoint setns: %v", err)
	}
	defer tpSetns.Close()

	tpUnshare, err := link.Tracepoint("syscalls", "sys_enter_unshare", monObjs.TraceUnshare, nil)
	if err != nil {
		log.Fatalf("Error adjuntando tracepoint unshare: %v", err)
	}
	defer tpUnshare.Close()

	fmt.Println("  👁️  Syscall monitors adjuntados (execve, setns, unshare)")

	// --- Abrir ring buffers ---
	lsmReader, err := ringbuf.NewReader(lsmObjs.SecurityEvents)
	if err != nil {
		log.Fatalf("Error abriendo ring buffer LSM: %v", err)
	}
	defer lsmReader.Close()

	monReader, err := ringbuf.NewReader(monObjs.Alerts)
	if err != nil {
		log.Fatalf("Error abriendo ring buffer monitor: %v", err)
	}
	defer monReader.Close()

	fmt.Println("\n─────────────────────────────────────────────────────────────")
	fmt.Println("  Monitoreando... Ctrl+C para detener")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println()

	// --- Signal handling ---
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// --- Consumer goroutines ---
	go consumeLSMEvents(lsmReader)
	go consumeSyscallAlerts(monReader)

	// --- Esperar señal ---
	<-sig
	fmt.Println("\n  🧹 Limpiando...")
	fmt.Println("  👋 Security monitor detenido.")
}

// consumeLSMEvents lee eventos del ring buffer de LSM (file access)
func consumeLSMEvents(reader *ringbuf.Reader) {
	for {
		record, err := reader.Read()
		if err != nil {
			return
		}

		var evt securityEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &evt); err != nil {
			continue
		}

		ts := time.Duration(evt.TimestampNs) * time.Nanosecond
		comm := nullTermStr(evt.Comm[:])
		filename := nullTermStr(evt.Filename[:])

		fmt.Printf("  [%s] %s │ LSM file_open │ pid=%d uid=%d comm=%s file=%s\n",
			ts.Truncate(time.Millisecond), actionStr(evt.Action),
			evt.PID, evt.UID, comm, filename)
	}
}

// consumeSyscallAlerts lee alertas del ring buffer del syscall monitor
func consumeSyscallAlerts(reader *ringbuf.Reader) {
	for {
		record, err := reader.Read()
		if err != nil {
			return
		}

		var alert syscallAlert
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &alert); err != nil {
			continue
		}

		ts := time.Duration(alert.TimestampNs) * time.Nanosecond
		comm := nullTermStr(alert.Comm[:])
		filename := nullTermStr(alert.Filename[:])

		evtStr := eventTypeStr(alert.EventType)
		sevStr := severityStr(alert.Severity)

		extra := ""
		if filename != "" {
			extra = fmt.Sprintf(" bin=%s", filename)
		}
		if alert.NamespaceID != 0 {
			extra += fmt.Sprintf(" ns=%d", alert.NamespaceID)
		}

		fmt.Printf("  [%s] %s │ %s │ pid=%d uid=%d comm=%s%s\n",
			ts.Truncate(time.Millisecond), sevStr, evtStr,
			alert.PID, alert.UID, comm, extra)
	}
}
