//go:build ignore

// lsm_file_open.bpf.c — Capítulo 17: LSM Hook para Control de Acceso a Archivos
//
// Este programa usa BPF LSM (Linux Security Module) para interceptar
// la apertura de archivos y denegar acceso a paths sensibles. Implementa
// una política de seguridad runtime que:
//
// 1. Intercepta file_open via LSM hook
// 2. Compara el path contra una lista de paths protegidos
// 3. Deniega acceso (retorna -EPERM) si el proceso no está autorizado
// 4. Emite eventos de seguridad al user space via ring buffer
//
// Esto es runtime security enforcement — el programa decide si permitir
// o bloquear una operación ANTES de que ocurra. Similar a lo que hacen
// Tetragon o Falco, pero a nivel básico para entender el mecanismo.
//
// Attach point: LSM hook "file_open"
// Requisitos: kernel >= 5.7 con CONFIG_BPF_LSM=y, lsm=bpf en cmdline

#include <linux/bpf.h>
#include <linux/lsm_hooks.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// =============================================================================
// Configuración
// =============================================================================

// Máximo de paths protegidos que podemos monitorear
#define MAX_PROTECTED_PATHS 64

// Largo máximo de un path o componente
#define MAX_PATH_LEN 256

// Largo del nombre del archivo (componente final del path)
#define MAX_FILENAME_LEN 64

// =============================================================================
// Estructuras
// =============================================================================

// Evento de seguridad emitido al user space
struct security_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u32 action;       // 0 = denied, 1 = allowed (monitored)
    char  comm[16];     // Nombre del proceso
    char  filename[MAX_FILENAME_LEN]; // Nombre del archivo
};

// Entrada en la tabla de paths protegidos
struct protected_path {
    char filename[MAX_FILENAME_LEN]; // Nombre del archivo a proteger
    __u32 enforce;                   // 1 = deny, 0 = audit-only
    __u32 _pad;
};

// =============================================================================
// Maps
// =============================================================================

// Ring buffer para emitir eventos de seguridad al user space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB
} security_events SEC(".maps");

// Hash map: filename → protected_path config
// El control plane (Go) llena este map con los archivos a proteger.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROTECTED_PATHS);
    __type(key, char[MAX_FILENAME_LEN]);
    __type(value, struct protected_path);
} protected_files SEC(".maps");

// Estadísticas: index 0 = total checks, 1 = denials, 2 = audit hits
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} lsm_stats SEC(".maps");

// =============================================================================
// Funciones auxiliares
// =============================================================================

static __always_inline void stats_inc(__u32 idx) {
    __u64 *counter = bpf_map_lookup_elem(&lsm_stats, &idx);
    if (counter)
        *counter += 1;
}

// =============================================================================
// Programa LSM: file_open
// =============================================================================

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
    // Incrementar contador de checks totales
    stats_inc(0);

    // Obtener info del proceso actual
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Leer el nombre del archivo (componente final del path)
    // Usamos dentry->d_name.name que es el nombre del archivo sin el path completo
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return 0; // Permitir si no podemos leer

    // Leer nombre del archivo desde dentry
    char filename[MAX_FILENAME_LEN] = {};
    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    if (!name)
        return 0;

    bpf_probe_read_kernel_str(filename, sizeof(filename), name);

    // Buscar en la tabla de paths protegidos
    struct protected_path *policy = bpf_map_lookup_elem(&protected_files, filename);
    if (!policy)
        return 0; // No está en la lista — permitir

    // ¡Hit! El archivo está protegido
    // Emitir evento al user space
    struct security_event *evt;
    evt = bpf_ringbuf_reserve(&security_events, sizeof(*evt), 0);
    if (evt) {
        evt->timestamp_ns = bpf_ktime_get_ns();
        evt->pid = pid;
        evt->uid = uid;
        bpf_get_current_comm(evt->comm, sizeof(evt->comm));
        __builtin_memcpy(evt->filename, filename, MAX_FILENAME_LEN);

        if (policy->enforce) {
            evt->action = 0; // denied
            stats_inc(1);    // denial counter
        } else {
            evt->action = 1; // audit only
            stats_inc(2);    // audit counter
        }

        bpf_ringbuf_submit(evt, 0);
    }

    // Enforce: denegar acceso si la política es enforce
    if (policy->enforce)
        return -EPERM;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
