// Capítulo 7 — El Verifier: Cargando programas corregidos
//
// Este loader demuestra cómo cargar los tres programas BPF que
// pasaron la verificación (las versiones fixed/).
//
// El propósito es educativo: el lector puede ver que las versiones
// corregidas cargan sin errores, mientras que las rotas serían
// rechazadas por el verifier.
//
// Los tres programas demuestran:
// 1. Null check obligatorio en map lookups
// 2. Bounds check obligatorio en acceso a paquetes XDP
// 3. Inicialización completa de structs antes de pasarlas a helpers
//
// Para ejecutar:
//   cd bpf/ && make
//   cd ../go/ && go generate && go build && sudo ./verifier-demo

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 nullcheck ../bpf/fixed/01_null_deref.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bounds ../bpf/fixed/02_no_bounds.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 uninit ../bpf/fixed/03_uninitialized.bpf.c

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
)

func main() {
	fmt.Println("=== Capítulo 7: Cargando programas que pasan el verifier ===")
	fmt.Println("")

	// --- Programa 1: Null check en map lookup ---
	fmt.Print("1. Cargando 01_null_deref (fixed)... ")
	nullObjs := nullcheckObjects{}
	if err := loadNullcheckObjects(&nullObjs, nil); err != nil {
		log.Fatalf("FALLO: %v", err)
	}
	defer nullObjs.Close()

	tp1, err := link.Tracepoint("syscalls", "sys_enter_execve", nullObjs.CountExecve, nil)
	if err != nil {
		log.Fatalf("Error adjuntando tracepoint (01): %v", err)
	}
	defer tp1.Close()
	fmt.Println("✅ Cargado y adjuntado (tracepoint/syscalls/sys_enter_execve)")

	// --- Programa 2: Bounds check en XDP ---
	fmt.Print("2. Cargando 02_no_bounds (fixed)... ")
	boundsObjs := boundsObjects{}
	if err := loadBoundsObjects(&boundsObjs, nil); err != nil {
		log.Fatalf("FALLO: %v", err)
	}
	defer boundsObjs.Close()
	// XDP requiere una interfaz de red — solo verificamos carga exitosa
	fmt.Println("✅ Cargado (XDP — listo para adjuntar a interfaz)")

	// --- Programa 3: Struct inicializada ---
	fmt.Print("3. Cargando 03_uninitialized (fixed)... ")
	uninitObjs := uninitObjects{}
	if err := loadUninitObjects(&uninitObjs, nil); err != nil {
		log.Fatalf("FALLO: %v", err)
	}
	defer uninitObjs.Close()

	tp3, err := link.Tracepoint("syscalls", "sys_enter_execve", uninitObjs.TraceExecve, nil)
	if err != nil {
		log.Fatalf("Error adjuntando tracepoint (03): %v", err)
	}
	defer tp3.Close()
	fmt.Println("✅ Cargado y adjuntado (tracepoint/syscalls/sys_enter_execve)")

	fmt.Println("")
	fmt.Println("─────────────────────────────────────────────────────────────")
	fmt.Println("Todos los programas pasaron el verifier y están ejecutándose.")
	fmt.Println("")
	fmt.Println("Esto confirma que las correcciones funcionan:")
	fmt.Println("  1. Null check antes de dereferenciar map lookup")
	fmt.Println("  2. Bounds check antes de acceder a headers del paquete")
	fmt.Println("  3. Inicialización completa de structs antes de helpers")
	fmt.Println("")
	fmt.Println("El programa 1 cuenta execve() por PID en un hash map.")
	fmt.Println("Presiona Ctrl+C para salir...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\n👋 Programas BPF removidos. Adiós.")
}
