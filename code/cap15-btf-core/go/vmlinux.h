// vmlinux.h — Stub minimalista para compilación (Capítulo 15)
//
// En un proyecto real, se genera con:
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//
// Este stub contiene solo las estructuras que nuestro ejemplo necesita.
// Los offsets reales se resuelven via CO-RE en tiempo de carga.

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

typedef int pid_t;

struct task_struct {
    int pid;
    int tgid;
    struct task_struct *real_parent;
    char comm[16];
} __attribute__((preserve_access_index));

struct pt_regs {
    unsigned long di;
    unsigned long si;
    unsigned long dx;
    unsigned long cx;
    unsigned long ax;
    unsigned long sp;
    unsigned long ip;
} __attribute__((preserve_access_index));

#endif /* __VMLINUX_H__ */
