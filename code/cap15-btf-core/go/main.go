// Capítulo 15 — Loader Go con soporte CO-RE (BTF transparente)
//
// Demuestra cómo cilium/ebpf maneja CO-RE de forma transparente:
// 1. Carga el programa BPF compilado con CO-RE
// 2. cilium/ebpf automáticamente lee el BTF del kernel target
// 3. Resuelve relocations (offsets) sin intervención del programador
// 4. Consume eventos del ring buffer
//
// El punto clave: NO necesitas hacer nada especial en Go para que CO-RE
// funcione. cilium/ebpf lo maneja internamente al cargar el programa.
// Si el kernel tiene BTF (/sys/kernel/btf/vmlinux), las relocations
// se resuelven automáticamente.
//
// Uso:
//   go generate ./...
//   go build -o core-exit-tracer .
//   sudo ./core-exit-tracer

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 tracer core_exit_tracer.bpf.c

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// ExitEvent mapea la struct exit_event del lado BPF.
// El layout debe coincidir EXACTAMENTE con la definición en el .bpf.c.
type ExitEvent struct {
	PID  uint32
	PPID uint32
	Comm [16]byte
}

func main() {
	// Verificar BTF del kernel (informativo, no bloqueante).
	// cilium/ebpf intentará cargar de todas formas — pero si no hay BTF,
	// las relocations CO-RE fallarán.
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
		fmt.Println("⚠️  WARNING: /sys/kernel/btf/vmlinux no encontrado")
		fmt.Println("   CO-RE requiere un kernel compilado con CONFIG_DEBUG_INFO_BTF=y")
		fmt.Println("   El programa probablemente fallará al cargar.")
		fmt.Println("")
	}

	// Cargar objetos BPF.
	// Aquí es donde la MAGIA de CO-RE ocurre de forma transparente:
	//   1. bpf2go embebe el .bpf.o (con BTF + relocations) en el binario Go
	//   2. loadTracerObjects() llama a ebpf.NewCollection()
	//   3. cilium/ebpf detecta relocations pendientes en el .bpf.o
	//   4. Lee /sys/kernel/btf/vmlinux del kernel ACTUAL
	//   5. Resuelve cada relocation: encuentra el offset REAL de cada campo
	//   6. Parchea el bytecode BPF con los offsets correctos
	//   7. Carga el programa parcheado en el kernel
	//
	// Todo esto es INVISIBLE para nosotros. Solo llamamos loadTracerObjects().
	objs := tracerObjects{}
	if err := loadTracerObjects(&objs, nil); err != nil {
		log.Fatalf("Error cargando objetos BPF (¿kernel sin BTF?): %v", err)
	}
	defer objs.Close()

	// Adjuntar al kprobe do_exit.
	kp, err := link.Kprobe("do_exit", objs.TraceExitCore, nil)
	if err != nil {
		log.Fatalf("Error adjuntando kprobe: %v", err)
	}
	defer kp.Close()

	// Abrir ring buffer para leer eventos.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Error abriendo ring buffer: %v", err)
	}
	defer rd.Close()

	// Cerrar reader al recibir señal de terminación.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	fmt.Println("✅ Programa CO-RE cargado exitosamente")
	fmt.Println("   Hook: kprobe/do_exit")
	fmt.Println("   BTF: relocations resueltas automáticamente por cilium/ebpf")
	fmt.Println("")
	fmt.Println("📊 Tracing procesos que terminan... (Ctrl+C para salir)")
	fmt.Printf("%-8s %-8s %s\n", "PID", "PPID", "COMM")
	fmt.Println("──────── ──────── ────────────────")

	// Consumir eventos del ring buffer.
	for {
		record, err := rd.Read()
		if err != nil {
			break
		}

		var event ExitEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			continue
		}

		comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
		fmt.Printf("%-8d %-8d %s\n", event.PID, event.PPID, comm)
	}

	fmt.Println("\n👋 Saliendo...")
}
