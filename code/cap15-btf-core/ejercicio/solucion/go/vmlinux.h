// vmlinux.h — Stub para el ejercicio de portabilidad (Capítulo 15)
//
// En producción, generar con:
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//
// Este stub incluye las estructuras necesarias para el ejercicio portable.

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

struct ns_common {
    unsigned int inum;
} __attribute__((preserve_access_index));

struct pid_namespace {
    struct ns_common ns;
} __attribute__((preserve_access_index));

struct nsproxy {
    struct pid_namespace *pid_ns_for_children;
} __attribute__((preserve_access_index));

struct cred {
    uid_t uid;
    gid_t gid;
    uid_t euid;
    gid_t egid;
} __attribute__((preserve_access_index));

struct task_struct {
    long state;
    long __state;
    int pid;
    int tgid;
    struct task_struct *real_parent;
    struct task_struct *parent;
    char comm[16];
    struct nsproxy *nsproxy;
    const struct cred *real_cred;
    u64 start_time;
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
