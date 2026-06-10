//go:build ignore

// minimal.bpf.c — Programa BPF mínimo del Capítulo 3
//
// Este programa no hace absolutamente nada. Su propósito es validar que
// el toolchain completo funciona: clang compila, el verifier acepta,
// y el loader en Go puede cargarlo al kernel.
//
// Attach point: tracepoint/syscalls/sys_enter_execve
// Se dispara cada vez que se ejecuta un nuevo programa (execve).

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// SEC() define la sección ELF que indica al loader dónde adjuntar este programa.
// "tracepoint/syscalls/sys_enter_execve" = tracepoint estático del kernel
// que se dispara en cada llamada a execve().
SEC("tracepoint/syscalls/sys_enter_execve")
int minimal_prog(void *ctx) {
    // No hace nada. Solo existe para demostrar que el toolchain funciona.
    return 0;
}

// Todos los programas BPF necesitan declarar su licencia.
// Sin esto, el verifier rechaza el programa.
char LICENSE[] SEC("license") = "GPL";
