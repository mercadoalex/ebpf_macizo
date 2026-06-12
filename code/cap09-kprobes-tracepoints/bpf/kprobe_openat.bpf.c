// Capítulo 9 — Kprobes: Interceptando do_sys_openat2
//
// Este programa demuestra el uso básico de un kprobe para interceptar
// la función do_sys_openat2 del kernel y registrar qué archivos abre
// cada proceso.
//
// Conceptos:
//   - SEC("kprobe/...") para adjuntar a funciones del kernel
//   - struct pt_regs como contexto con registros del procesador
//   - PT_REGS_PARM2() para acceder al segundo argumento (filename)
//   - bpf_probe_read_user_str() para leer strings de user space
//
// Compilar:
//   make kprobe_openat.bpf.o

//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("kprobe/do_sys_openat2")
int trace_openat(struct pt_regs *ctx) {
    // do_sys_openat2(int dfd, const char __user *filename, struct open_how *how)
    // Argumento 2 = filename (en rsi en x86_64)
    const char *filename = (const char *)PT_REGS_PARM2(ctx);

    char buf[64];
    bpf_probe_read_user_str(buf, sizeof(buf), filename);

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("pid=%d open: %s", pid, buf);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
