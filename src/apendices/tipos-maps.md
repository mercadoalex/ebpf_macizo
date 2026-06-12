# Apéndice C: Cheatsheet de tipos de maps

> Referencia rápida de todos los tipos de maps BPF: cuándo usar cada uno, características y definición en C.
> Consulta rápida — no tutorial. Si necesitas contexto, ve al Capítulo 6.

---

## Tabla de referencia rápida

| Tipo | Per-CPU | User-accessible | Key size | Value size | Max entries | Caso de uso principal |
|------|---------|-----------------|----------|------------|-------------|----------------------|
| `BPF_MAP_TYPE_HASH` | No | Sí | Arbitrario | Arbitrario | Configurable | Diccionario general key→value |
| `BPF_MAP_TYPE_ARRAY` | No | Sí | `u32` (índice) | Arbitrario | Fijo | Acceso O(1) por índice |
| `BPF_MAP_TYPE_PERCPU_HASH` | Sí | Sí | Arbitrario | Arbitrario | Configurable | Contadores sin lock por CPU |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | Sí | Sí | `u32` (índice) | Arbitrario | Fijo | Stats por CPU sin contención |
| `BPF_MAP_TYPE_LRU_HASH` | No | Sí | Arbitrario | Arbitrario | Configurable | Cache con eviction automática |
| `BPF_MAP_TYPE_PROG_ARRAY` | No | No* | `u32` (índice) | fd de programa | Configurable | Tail calls entre programas |
| `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | Sí (implícito) | Sí (lectura) | `u32` (CPU) | fd de perf event | Nº CPUs | Streaming eventos→user space |
| `BPF_MAP_TYPE_RINGBUF` | No (shared) | Sí (lectura) | N/A | Variable | 1 (buffer size) | Streaming moderno kernel→user |
| `BPF_MAP_TYPE_DEVMAP` | No | Sí | `u32` (índice) | ifindex | Configurable | XDP redirect entre interfaces |
| `BPF_MAP_TYPE_XSKMAP` | No | Sí | `u32` (índice) | fd de AF_XDP socket | Configurable | Zero-copy packet forwarding |
| `BPF_MAP_TYPE_LPM_TRIE` | No | Sí | Prefijo + datos | Arbitrario | Configurable | Longest prefix match (routing) |
| `BPF_MAP_TYPE_STACK_TRACE` | No | Sí (lectura) | `u32` (stack ID) | Array de IPs | Configurable | Captura de stack traces |

\* `PROG_ARRAY`: user space lo crea y lo llena con fds, pero no lo "lee" como datos.

---

## Guía de decisión: ¿Cuál map usar?

```text
¿Necesitas enviar eventos al user space?
├── Sí → ¿Orden garantizado y multi-producer?
│         ├── Sí → RINGBUF
│         └── No (legacy) → PERF_EVENT_ARRAY
│
¿Necesitas almacenar datos key→value?
├── Sí → ¿Las keys son índices numéricos secuenciales (0, 1, 2...)?
│         ├── Sí → ¿Necesitas evitar contención entre CPUs?
│         │         ├── Sí → PERCPU_ARRAY
│         │         └── No → ARRAY
│         └── No → ¿El tamaño es impredecible / keys dinámicas?
│                   ├── Sí → ¿Puede llenarse y necesitas eviction?
│                   │         ├── Sí → LRU_HASH
│                   │         └── No → ¿Contadores high-freq?
│                   │                   ├── Sí → PERCPU_HASH
│                   │                   └── No → HASH
│                   └── ¿Las keys son prefijos IP/CIDR?
│                             └── Sí → LPM_TRIE
│
¿Necesitas tail calls (saltar a otro programa BPF)?
└── Sí → PROG_ARRAY

¿Necesitas redirigir paquetes XDP a otra interfaz?
└── Sí → DEVMAP

¿Necesitas zero-copy con AF_XDP sockets?
└── Sí → XSKMAP

¿Necesitas capturar call stacks del kernel/user?
└── Sí → STACK_TRACE
```

---

## Definiciones en C

### HASH

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);    // ej: PID
    __type(value, __u64);  // ej: contador
} my_hash SEC(".maps");
```

### ARRAY

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);    // índice 0..max_entries-1
    __type(value, struct stats);
} my_array SEC(".maps");
```

### PERCPU_HASH

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} per_cpu_hash SEC(".maps");
```

> ⚙️ **Nota técnica**: Cada CPU tiene su propia copia del value. Desde user space, lees un array de values (uno por CPU) y los sumas tú.

### PERCPU_ARRAY

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} per_cpu_array SEC(".maps");
```

### LRU_HASH

```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 50000);
    __type(key, struct flow_key);
    __type(value, struct flow_info);
} lru_cache SEC(".maps");
```

> 🔥 **Advertencia**: Cuando el map se llena, las entradas menos usadas se descartan silenciosamente. No asumas que un `lookup` siempre encuentra lo que pusiste antes.

### PROG_ARRAY

```c
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);  // fd del programa destino
} jump_table SEC(".maps");
```

Uso en BPF (tail call):

```c
bpf_tail_call(ctx, &jump_table, index);
// Si el tail call falla, la ejecución continúa aquí
```

### PERF_EVENT_ARRAY

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");
```

Envío desde BPF:

```c
bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
```

### RINGBUF

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // tamaño del buffer en bytes
} rb SEC(".maps");
```

Envío desde BPF:

```c
struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
if (!e) return 0;
e->pid = bpf_get_current_pid_tgid() >> 32;
bpf_ringbuf_submit(e, 0);
```

> 💡 **Tip**: `RINGBUF` es superior a `PERF_EVENT_ARRAY` en casi todo: un solo buffer compartido, ordering garantizado, y menos overhead. Usa ringbuf salvo que necesites compatibilidad con kernels < 5.8.

### DEVMAP

```c
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 64);
    __type(key, __u32);    // índice lógico
    __type(value, __u32);  // ifindex de la interfaz destino
} tx_port SEC(".maps");
```

Uso en XDP:

```c
return bpf_redirect_map(&tx_port, dst_index, 0);
```

### XSKMAP

```c
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);  // fd del AF_XDP socket
} xsks_map SEC(".maps");
```

Uso en XDP:

```c
return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
```

### LPM_TRIE

```c
struct lpm_key {
    __u32 prefixlen;  // longitud del prefijo en bits
    __u32 addr;       // dirección IPv4
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u32);  // ej: acción (DROP/PASS)
} lpm_map SEC(".maps");
```

> ⚙️ **Nota técnica**: `LPM_TRIE` requiere `BPF_F_NO_PREALLOC`. La key siempre empieza con `prefixlen` (`__u32`). Útil para routing tables y ACLs basadas en CIDR.

### STACK_TRACE

```c
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 10000);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64)); // max depth
} stack_map SEC(".maps");
```

Captura desde BPF:

```c
__u32 stack_id = bpf_get_stackid(ctx, &stack_map, BPF_F_USER_STACK);
```

---

## Resumen de kernels mínimos

| Tipo | Kernel mínimo |
|------|--------------|
| HASH, ARRAY | 3.19 |
| PERCPU_HASH, PERCPU_ARRAY | 4.6 |
| LRU_HASH | 4.10 |
| PROG_ARRAY | 4.2 |
| PERF_EVENT_ARRAY | 4.3 |
| STACK_TRACE | 4.6 |
| LPM_TRIE | 4.11 |
| DEVMAP | 4.14 |
| XSKMAP | 4.18 |
| RINGBUF | 5.8 |

---

## Tips rápidos

- **Siempre limpia tus maps**: El kernel no tiene garbage collector. Si tu programa BPF termina, los maps persisten (pinned o no). Limpia desde user space.
- **Per-CPU = sin locks, pero más memoria**: Cada CPU tiene su copia. Ideal para contadores hot-path. Desde user space sumas los valores de todas las CPUs.
- **RINGBUF > PERF_EVENT_ARRAY**: Salvo que necesites kernel < 5.8, ringbuf gana en todo.
- **LRU_HASH para caches**: Si no puedes predecir cuántas entries tendrás, LRU evicta automáticamente. No confíes en que tus datos persistan.
- **PROG_ARRAY para pipelines**: Máximo 33 tail calls encadenados. Planifica tu pipeline con ese límite.

---

## Para saber más

- 📖 [Kernel docs: BPF maps](https://docs.kernel.org/bpf/maps.html)
- 📖 [libbpf map types reference](https://libbpf.readthedocs.io/en/latest/api.html)
- 💻 [Ejemplos de maps en el kernel](https://github.com/torvalds/linux/tree/master/samples/bpf)
