// vmlinux.h — Stub minimalista para compilación de ejemplos (Capítulo 15)
//
// En un proyecto real, este archivo se genera con:
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//
// El vmlinux.h completo tiene 180,000-250,000 líneas con TODAS las
// definiciones de tipos del kernel. Este stub contiene solo las
// estructuras que nuestros ejemplos necesitan.
//
// IMPORTANTE: Los offsets reales no importan aquí. CO-RE los resuelve
// en tiempo de carga usando el BTF del kernel target. Lo que importa
// son los NOMBRES de las structs y sus campos.
//
// El atributo __attribute__((preserve_access_index)) es CRUCIAL:
// instruye a clang a emitir relocations en vez de calcular offsets
// estáticamente.

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;
typedef long long __s64;
typedef __u32 u32;
typedef __u64 u64;
typedef __s64 s64;

typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;

// ============================================================================
// Estructuras del kernel usadas en los ejemplos CO-RE
// ============================================================================

// Namespace info — para acceder al PID namespace
struct ns_common {
    unsigned int inum;
} __attribute__((preserve_access_index));

struct pid_namespace {
    struct ns_common ns;
} __attribute__((preserve_access_index));

// Namespace proxy — accede a los namespaces de un proceso
struct nsproxy {
    struct pid_namespace *pid_ns_for_children;
} __attribute__((preserve_access_index));

// Credenciales del proceso
struct cred {
    uid_t uid;
    gid_t gid;
    uid_t euid;
    gid_t egid;
} __attribute__((preserve_access_index));

// task_struct — la estructura central del scheduler.
// En un vmlinux.h real tiene 200+ campos. Aquí solo los que usamos.
//
// Nota: el campo 'state' se renombró a '__state' en kernel 5.14+.
// Incluimos ambos para demostrar el patrón de fallback con
// bpf_core_field_exists().
struct task_struct {
    long state;                          // < 5.14
    long __state;                        // >= 5.14 (renombrado)
    int pid;
    int tgid;
    struct task_struct *real_parent;
    struct task_struct *parent;
    char comm[16];
    struct nsproxy *nsproxy;
    const struct cred *real_cred;
    u64 start_time;                      // tiempo de inicio (ns monotónicos)
} __attribute__((preserve_access_index));

// pt_regs — registros del CPU (para kprobes)
struct pt_regs {
    unsigned long di;
    unsigned long si;
    unsigned long dx;
    unsigned long cx;
    unsigned long ax;
    unsigned long sp;
    unsigned long ip;
} __attribute__((preserve_access_index));

// Tracepoint context (para tracepoints raw)
struct trace_event_raw_sched_process_exec {
    int pid;
    int old_pid;
    char filename[256];
} __attribute__((preserve_access_index));

#endif /* __VMLINUX_H__ */
