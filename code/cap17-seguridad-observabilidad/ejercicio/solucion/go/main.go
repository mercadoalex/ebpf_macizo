// Ejercicio Capítulo 17 (Solución) — Container Escape Detector
//
// Sistema de alerting que detecta intentos de escape de contenedores
// usando una combinación de:
//
// 1. LSM hooks — Bloquea mounts sospechosos desde containers
// 2. Syscall monitoring — Detecta execve, setns, unshare, mount
// 3. Clasificación — Alertas por severidad (INFO → ESCAPE)
//
// El programa carga el BPF escape_detector, configura las herramientas
// de escape conocidas, y consume eventos via ring buffer mostrando
// alertas clasificadas en tiempo real.
//
// Uso:
//   go generate ./...
//   go build -o escape-detector .
//   sudo ./escape-detector [-enforce]
//
// Luego desde un container ejecutar:
//   nsenter --target 1 --mount --pid  (debería generar alerta ESCAPE)
//   mount -t proc proc /mnt           (debería ser bloqueado en enforce mode)

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 escapeDetector escape_detector.bpf.c

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// =============================================================================
// Constantes
// =============================================================================

const (
	maxPathLen = 128
	maxBinLen  = 64

	// Severidad
	sevInfo     = 0
	sevWarning  = 1
	sevCritical = 2
	sevEscape   = 3

	// Tipos de evento
	evtMountSuspicious   = 1
	evtSetnsEscape       = 2
	evtUnsharePrivileged = 3
	evtExecEscapeTool    = 4
	evtProcNsAccess      = 5
	evtLSMMountBlocked   = 6
)

// =============================================================================
// Estructuras
// =============================================================================

// escapeAlert debe coincidir con struct escape_alert en BPF
type escapeAlert struct {
	TimestampNs uint64
	PID         uint32
	TGID        uint32
	UID         uint32
	EventType   uint32
	Severity    uint32
	NamespaceID uint32
	Flags       uint32
	Pad         uint32
	Comm        [16]byte
	Detail      [maxPathLen]byte
}

// =============================================================================
// Utilidades de display
// =============================================================================

func nullTermStr(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		return string(b)
	}
	return string(b[:n])
}

func severityIcon(s uint32) string {
	switch s {
	case sevInfo:
		return "ℹ️ "
	case sevWarning:
		return "⚠️ "
	case sevCritical:
		return "🚨"
	case sevEscape:
		return "💀"
	default:
		return "? "
	}
}

func severityStr(s uint32) string {
	switch s {
	case sevInfo:
		return "INFO"
	case sevWarning:
		return "WARNING"
	case sevCritical:
		return "CRITICAL"
	case sevEscape:
		return "ESCAPE"
	default:
		return "UNKNOWN"
	}
}

func eventTypeStr(t uint32) string {
	switch t {
	case evtMountSuspicious:
		return "MOUNT_SUSPICIOUS"
	case evtSetnsEscape:
		return "SETNS_ESCAPE"
	case evtUnsharePrivileged:
		return "UNSHARE_PRIVILEGED"
	case evtExecEscapeTool:
		return "EXEC_ESCAPE_TOOL"
	case evtProcNsAccess:
		return "PROC_NS_ACCESS"
	case evtLSMMountBlocked:
		return "LSM_MOUNT_BLOCKED"
	default:
		return "UNKNOWN"
	}
}

// =============================================================================
// Estadísticas
// =============================================================================

type stats struct {
	total    uint64
	mounts   uint64
	setns    uint64
	unshare  uint64
	execve   uint64
	blocked  uint64
	alerts   uint64
}

func (s *stats) print() {
	fmt.Printf("  📊 Stats: total=%d mount=%d setns=%d unshare=%d exec=%d blocked=%d alerts=%d\n",
		s.total, s.mounts, s.setns, s.unshare, s.execve, s.blocked, s.alerts)
}

// =============================================================================
// Main
// =============================================================================

func main() {
	enforce := flag.Bool("enforce", false, "Modo enforce: bloquea mounts desde containers")
	flag.Parse()

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  Ejercicio Cap 17 — Container Escape Detector")
	fmt.Println("  LSM + Syscall Monitoring + Ring Buffer Alerting")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// --- Setup ---
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Error removiendo memlock: %v", err)
	}

	// --- Cargar BPF ---
	objs := escapeDetectorObjects{}
	if err := loadEscapeDetectorObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando BPF: %v\n"+
			"  Requiere: CONFIG_BPF_LSM=y, lsm=bpf en cmdline, BTF habilitado", err)
	}
	defer objs.Close()

	// --- Configurar enforce mode ---
	enforceVal := uint32(0)
	if *enforce {
		enforceVal = 1
	}
	configKey := uint32(0)
	if err := objs.Config.Put(configKey, enforceVal); err != nil {
		log.Printf("⚠️  Error configurando enforce mode: %v", err)
	}

	mode := "detect-only"
	if *enforce {
		mode = "ENFORCE (mounts bloqueados)"
	}
	fmt.Printf("  🔧 Modo: %s\n", mode)

	// --- Configurar herramientas de escape ---
	escapeToolsList := []struct {
		name     string
		severity uint32
	}{
		{"nsenter", sevEscape},
		{"mount", sevCritical},
		{"unshare", sevCritical},
		{"chroot", sevCritical},
		{"pivot_root", sevEscape},
		{"runc", sevWarning},
		{"ctr", sevWarning},
		{"crictl", sevWarning},
	}

	fmt.Println("\n  🔍 Herramientas de escape monitoreadas:")
	for _, tool := range escapeToolsList {
		var key [maxBinLen]byte
		copy(key[:], tool.name)
		if err := objs.EscapeTools.Put(key, tool.severity); err != nil {
			log.Printf("  ⚠️  Error configurando '%s': %v", tool.name, err)
			continue
		}
		fmt.Printf("    ✅ %s → %s\n", tool.name, severityStr(tool.severity))
	}

	// --- Adjuntar LSM hook ---
	lsmLink, err := link.AttachLSM(link.LSMOptions{
		Program: objs.LsmSbMount,
	})
	if err != nil {
		log.Fatalf("Error adjuntando LSM sb_mount: %v", err)
	}
	defer lsmLink.Close()
	fmt.Println("\n  🔒 LSM sb_mount hook adjuntado")

	// --- Adjuntar tracepoints ---
	tpExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceEscapeExecve, nil)
	if err != nil {
		log.Fatalf("Error adjuntando tracepoint execve: %v", err)
	}
	defer tpExecve.Close()

	tpSetns, err := link.Tracepoint("syscalls", "sys_enter_setns", objs.TraceEscapeSetns, nil)
	if err != nil {
		log.Fatalf("Error adjuntando tracepoint setns: %v", err)
	}
	defer tpSetns.Close()

	tpUnshare, err := link.Tracepoint("syscalls", "sys_enter_unshare", objs.TraceEscapeUnshare, nil)
	if err != nil {
		log.Fatalf("Error adjuntando tracepoint unshare: %v", err)
	}
	defer tpUnshare.Close()

	tpMount, err := link.Tracepoint("syscalls", "sys_enter_mount", objs.TraceEscapeMount, nil)
	if err != nil {
		log.Fatalf("Error adjuntando tracepoint mount: %v", err)
	}
	defer tpMount.Close()

	fmt.Println("  👁️  Tracepoints adjuntados (execve, setns, unshare, mount)")

	// --- Abrir ring buffer ---
	reader, err := ringbuf.NewReader(objs.EscapeAlerts)
	if err != nil {
		log.Fatalf("Error abriendo ring buffer: %v", err)
	}
	defer reader.Close()

	fmt.Println("\n─────────────────────────────────────────────────────────────")
	fmt.Println("  🛡️  Escape Detector activo — Ctrl+C para detener")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  Para probar, ejecutar desde un container:")
	fmt.Println("    nsenter --target 1 --mount --pid")
	fmt.Println("    mount -t proc proc /mnt")
	fmt.Println()

	// --- Signal handling ---
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// --- Consumer loop ---
	alertChan := make(chan escapeAlert, 256)
	go consumeAlerts(reader, alertChan)

	var s stats
	statsTicker := time.NewTicker(5 * time.Second)
	defer statsTicker.Stop()

	for {
		select {
		case <-sig:
			fmt.Println("\n  🧹 Limpiando...")
			s.print()
			fmt.Println("  👋 Escape detector detenido.")
			return

		case alert := <-alertChan:
			s.alerts++
			s.total++
			switch alert.EventType {
			case evtMountSuspicious, evtLSMMountBlocked:
				s.mounts++
			case evtSetnsEscape:
				s.setns++
			case evtUnsharePrivileged:
				s.unshare++
			case evtExecEscapeTool:
				s.execve++
			}
			if alert.EventType == evtLSMMountBlocked {
				s.blocked++
			}

			printAlert(alert)

		case <-statsTicker.C:
			if s.total > 0 {
				s.print()
			}
		}
	}
}

// consumeAlerts lee del ring buffer y envía alertas al canal
func consumeAlerts(reader *ringbuf.Reader, ch chan<- escapeAlert) {
	for {
		record, err := reader.Read()
		if err != nil {
			close(ch)
			return
		}

		var alert escapeAlert
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &alert); err != nil {
			continue
		}

		ch <- alert
	}
}

// printAlert muestra una alerta formateada
func printAlert(alert escapeAlert) {
	ts := time.Duration(alert.TimestampNs) * time.Nanosecond
	comm := nullTermStr(alert.Comm[:])
	detail := nullTermStr(alert.Detail[:])

	icon := severityIcon(alert.Severity)
	sev := severityStr(alert.Severity)
	evt := eventTypeStr(alert.EventType)

	fmt.Printf("  %s [%s] %s │ %s │ pid=%d uid=%d comm=%s ns=%d",
		icon, ts.Truncate(time.Millisecond), sev, evt,
		alert.PID, alert.UID, comm, alert.NamespaceID)

	if detail != "" {
		fmt.Printf(" detail=%s", detail)
	}
	if alert.Flags != 0 {
		fmt.Printf(" flags=0x%x", alert.Flags)
	}
	fmt.Println()

	// Mensaje especial para escapes confirmados
	if alert.Severity >= sevEscape {
		fmt.Println("  ╰── 💀 ¡ESCAPE DETECTADO! Acción inmediata requerida")
	}
}
