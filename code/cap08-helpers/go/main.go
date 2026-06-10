// Capítulo 8 — Helper Functions: Demo de helpers de contexto
//
// Este loader en Go demuestra cómo consumir eventos desde un ring buffer.
// El programa BPF (context_helpers.bpf.c) se adjunta al tracepoint openat
// y envía un struct event con información obtenida de helper functions:
//   - PID/TID  (bpf_get_current_pid_tgid)
//   - UID/GID  (bpf_get_current_uid_gid)
//   - comm     (bpf_get_current_comm)
//   - timestamp (bpf_ktime_get_ns)
//
// El consumer en Go lee estos eventos del ring buffer y los imprime
// de forma legible en la terminal.

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 helpers ../bpf/context_helpers.bpf.c

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// event debe coincidir EXACTAMENTE con el struct event del programa BPF.
// El orden, tamaño y alineación de los campos importan.
// Si los structs no coinciden, leerás basura.
type event struct {
	PID         uint32
	TID         uint32
	UID         uint32
	GID         uint32
	TimestampNs uint64
	Comm        [16]byte
}

func main() {
	// Cargar objetos BPF generados por bpf2go.
	objs := helpersObjects{}
	if err := loadHelpersObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando objetos BPF: %v", err)
	}
	defer objs.Close()

	// Adjuntar al tracepoint syscalls/sys_enter_openat.
	// Se dispara cada vez que cualquier proceso llama a openat() —
	// que es la syscall detrás de open(), fopen(), etc.
	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenat, nil)
	if err != nil {
		log.Fatalf("Error adjuntando tracepoint: %v", err)
	}
	defer tp.Close()

	// Crear reader del ring buffer.
	// El ring buffer "events" está definido en el programa BPF.
	rd, err := ringbuf.NewReader(objs.Events, nil)
	if err != nil {
		log.Fatalf("Error creando reader del ring buffer: %v", err)
	}
	defer rd.Close()

	fmt.Println("✅ Programa BPF cargado — escuchando eventos openat()")
	fmt.Println("   Helpers demostrados: pid_tgid, uid_gid, comm, ktime_get_ns")
	fmt.Println("")
	fmt.Printf("%-8s %-8s %-6s %-6s %-16s %s\n",
		"PID", "TID", "UID", "GID", "COMM", "TIMESTAMP")
	fmt.Println("--------------------------------------------------------------")

	// Goroutine para cerrar el reader cuando llegue Ctrl+C.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n👋 Deteniendo...")
		rd.Close()
	}()

	// Leer eventos del ring buffer en un loop.
	for {
		record, err := rd.Read()
		if err != nil {
			// El reader fue cerrado (Ctrl+C) — salimos limpiamente.
			break
		}

		// Deserializar el evento.
		var e event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("Error parseando evento: %v", err)
			continue
		}

		// Extraer el nombre (comm) como string limpio — sin null bytes.
		comm := nullTermStr(e.Comm[:])

		// Convertir timestamp a algo más legible.
		// bpf_ktime_get_ns() da nanosegundos desde boot.
		uptime := time.Duration(e.TimestampNs) * time.Nanosecond

		fmt.Printf("%-8d %-8d %-6d %-6d %-16s %s\n",
			e.PID, e.TID, e.UID, e.GID, comm, uptime.Truncate(time.Microsecond))
	}
}

// nullTermStr convierte un byte slice con null terminator a string Go.
func nullTermStr(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i == -1 {
		return string(b)
	}
	return string(b[:i])
}
