# Apéndice D: Troubleshooting del Verifier

> "El verifier no es tu enemigo. Es el último bastión entre tu código y un kernel panic."

Este apéndice documenta los 20 errores más comunes que escupe el verifier de eBPF. Cada entrada tiene el mensaje exacto (en inglés, como lo produce el kernel), su significado, cómo arreglarlo con código antes/después, y los errores típicos que lo provocan.

Úsalo como referencia rápida cuando el verifier te rechace un programa. Si necesitas entender la lógica del verifier en profundidad, vuelve al **Capítulo 7**.

---

## 1. `invalid mem access 'scalar'`

**Significado:** Estás intentando leer memoria usando un valor que el verifier no puede garantizar que sea un puntero válido. Típicamente ocurre al hacer dereference de un resultado de `bpf_map_lookup_elem()` sin verificar si es NULL.

**Errores comunes que lo provocan:**
- No verificar el retorno de `bpf_map_lookup_elem()`
- Usar un puntero después de que podría haberse invalidado
- Castear un scalar a puntero sin validación

**Antes (falla):**

```c
struct event *e;
e = bpf_map_lookup_elem(&my_map, &key);
e->counter++;  // ERROR: e podría ser NULL
```

**Después (correcto):**

```c
struct event *e;
e = bpf_map_lookup_elem(&my_map, &key);
if (!e)
    return 0;
e->counter++;  // OK: el verifier sabe que e != NULL
```

---

## 2. `back-edge from insn X to insn Y`

**Significado:** El verifier detectó un loop (salto hacia atrás en el flujo de instrucciones). En kernels < 5.3, los loops están completamente prohibidos. En kernels >= 5.3, los loops deben tener un bound explícito verificable.

**Errores comunes que lo provocan:**
- Usar `while` o `for` sin un límite estático conocido en tiempo de compilación
- Loops cuyo bound depende de datos de runtime
- Recursión accidental en la lógica del programa

**Antes (falla):**

```c
int i = 0;
while (i < len) {  // ERROR: len es variable, el verifier no puede probar terminación
    process(data[i]);
    i++;
}
```

**Después (correcto):**

```c
#define MAX_LEN 256

#pragma unroll
for (int i = 0; i < MAX_LEN; i++) {
    if (i >= len)
        break;
    process(data[i]);
}
```

**Alternativa (kernel >= 5.3 con bounded loops):**

```c
for (int i = 0; i < len && i < MAX_LEN; i++) {
    process(data[i]);
}
```

---

## 3. `R0 !read_ok`

**Significado:** El registro R0 (que contiene el valor de retorno) no tiene un valor válido al final del programa. El verifier requiere que todo programa eBPF retorne un valor escalar definido.

**Errores comunes que lo provocan:**
- Olvidar un `return` en alguna rama del código
- Control flow donde algún path no asigna un valor de retorno
- Funciones helper que dejan R0 en estado indeterminado

**Antes (falla):**

```c
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    if (some_condition) {
        return XDP_DROP;
    }
    // ERROR: si some_condition es false, no hay return
}
```

**Después (correcto):**

```c
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    if (some_condition) {
        return XDP_DROP;
    }
    return XDP_PASS;  // siempre retornar un valor
}
```

---

## 4. `the program is too large. processed X insns`

**Significado:** Tu programa excede el límite de complejidad del verifier. El verifier analiza cada path posible y tiene un presupuesto máximo de instrucciones que puede procesar (1 millón en kernels modernos, 4096 en kernels viejos).

**Errores comunes que lo provocan:**
- Código con muchas ramas condicionales (explosión combinatoria de paths)
- Loops desenrollados demasiado grandes
- Lógica compleja que debería estar en user space o dividirse con tail calls

**Antes (falla):**

```c
SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    // Parseo completo de L2/L3/L4 + 50 reglas inline
    // + logging + stats + rate limiting
    // ... 2000 líneas de código ...
    return XDP_PASS;
}
```

**Después (correcto):**

```c
// Dividir en programas más pequeños con tail calls
SEC("xdp")
int xdp_entry(struct xdp_md *ctx) {
    __u32 protocol = parse_protocol(ctx);
    bpf_tail_call(ctx, &jmp_table, protocol);
    return XDP_PASS;  // fallback si tail call falla
}

SEC("xdp")
int xdp_handle_tcp(struct xdp_md *ctx) {
    // Solo lógica de TCP
    return apply_tcp_rules(ctx);
}
```

---

## 5. `invalid access to packet, off=X size=Y, R6(id=Z,off=W,r=0)`

**Significado:** Estás leyendo datos de un paquete de red sin verificar que el puntero esté dentro de los límites del paquete. El verifier exige que siempre compruebes `data + offset <= data_end` antes de leer.

**Errores comunes que lo provocan:**
- Olvidar la verificación de bounds al parsear headers
- Hacer casts a structs sin validar que el paquete es suficientemente largo
- Acceder a payload variable sin recalcular bounds

**Antes (falla):**

```c
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    // ERROR: no verificaste que ip cabe en el paquete
    if (ip->protocol == IPPROTO_TCP)
        return XDP_DROP;

    return XDP_PASS;
}
```

**Después (correcto):**

```c
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP)
        return XDP_DROP;

    return XDP_PASS;
}
```

---

## 6. `unreachable insn X`

**Significado:** El verifier encontró instrucciones que nunca se pueden ejecutar. Código muerto no está permitido en programas eBPF porque podría ocultar comportamiento malicioso.

**Errores comunes que lo provocan:**
- Código después de un `return` incondicional
- Ramas que el compilador no eliminó pero que son lógicamente imposibles
- Funciones auxiliares que nunca se llaman

**Antes (falla):**

```c
SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("write called");
    return 0;
    bpf_printk("never reached");  // ERROR: unreachable
    return 1;
}
```

**Después (correcto):**

```c
SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("write called");
    return 0;
}
```

---

## 7. `R1 type=scalar expected=fp`

**Significado:** El verifier esperaba un puntero al stack frame (frame pointer) pero recibió un valor escalar. Esto ocurre cuando pasas un valor por valor donde se espera un puntero, típicamente en helpers que requieren un puntero a una variable local.

**Errores comunes que lo provocan:**
- Pasar `key` en vez de `&key` a `bpf_map_lookup_elem()`
- Confundir punteros con valores escalares en argumentos de helpers
- Usar el operador incorrecto al pasar struct members

**Antes (falla):**

```c
__u32 key = 0;
// ERROR: bpf_map_lookup_elem espera un puntero, no un escalar
void *value = bpf_map_lookup_elem(&my_map, key);
```

**Después (correcto):**

```c
__u32 key = 0;
void *value = bpf_map_lookup_elem(&my_map, &key);  // &key = puntero al stack
```

---

## 8. `variable stack access var_off=(0x0; 0xffffffff) off=-X size=Y`

**Significado:** Estás accediendo al stack con un offset variable que el verifier no puede resolver estáticamente. El acceso al stack debe ser a posiciones fijas conocidas en tiempo de compilación.

**Errores comunes que lo provocan:**
- Usar un índice variable para acceder a un array local
- Pasar offsets dinámicos a `bpf_probe_read()` sobre el stack
- Aritmética de punteros sobre variables locales con offsets no constantes

**Antes (falla):**

```c
SEC("kprobe/do_sys_open")
int trace_open(struct pt_regs *ctx) {
    char buf[256];
    int offset = get_dynamic_offset();  // valor no constante
    // ERROR: acceso al stack con offset variable
    char c = buf[offset];
    return 0;
}
```

**Después (correcto):**

```c
SEC("kprobe/do_sys_open")
int trace_open(struct pt_regs *ctx) {
    char buf[256];
    int offset = get_dynamic_offset();

    // Asegurar que offset está en rango
    if (offset < 0 || offset >= 256)
        return 0;

    // Usar bpf_probe_read para acceso con offset dinámico
    char c;
    bpf_probe_read(&c, 1, &buf[offset & 0xFF]);
    return 0;
}
```

---

## 9. `func#X not referenced`

**Significado:** Definiste una función BPF-to-BPF (subprograma) que nunca se invoca. El verifier rechaza funciones no utilizadas porque representan código muerto.

**Errores comunes que lo provocan:**
- Funciones helper definidas "por si acaso" pero nunca llamadas
- Refactoring incompleto donde se eliminó la llamada pero no la función
- Funciones condicionalmente compiladas con `#ifdef` mal configurados

**Antes (falla):**

```c
static __always_inline int helper_unused(void *ctx) {
    return 0;
}

// Esta función no la llama nadie — el compilador podría no eliminarla
static int __attribute__((noinline)) process_data(int val) {
    return val * 2;
}

SEC("kprobe/vfs_read")
int trace_read(struct pt_regs *ctx) {
    return 0;  // process_data nunca se llama
}
```

**Después (correcto):**

```c
static int __attribute__((noinline)) process_data(int val) {
    return val * 2;
}

SEC("kprobe/vfs_read")
int trace_read(struct pt_regs *ctx) {
    int result = process_data(42);  // ahora sí se referencia
    bpf_printk("result: %d", result);
    return 0;
}
```

---

## 10. `invalid indirect read from stack R2 off -X+Y size Z`

**Significado:** Estás pasando a un helper un puntero al stack que apunta a memoria no inicializada. El verifier exige que toda la memoria que pases a helpers esté inicializada para prevenir data leaks del kernel.

**Errores comunes que lo provocan:**
- Declarar un buffer en el stack sin inicializarlo antes de pasarlo a un helper
- Inicializar parcialmente una estructura y luego pasarla completa
- Usar `__builtin_memset` con tamaño incorrecto

**Antes (falla):**

```c
SEC("kprobe/do_sys_open")
int trace_open(struct pt_regs *ctx) {
    char filename[256];
    // ERROR: filename no está inicializado
    bpf_probe_read_user_str(filename, sizeof(filename), (void *)PT_REGS_PARM2(ctx));
    // ^ Algunos kernels lo rechazan si el buffer no está limpio
    return 0;
}
```

**Después (correcto):**

```c
SEC("kprobe/do_sys_open")
int trace_open(struct pt_regs *ctx) {
    char filename[256] = {};  // inicializar a ceros
    bpf_probe_read_user_str(filename, sizeof(filename), (void *)PT_REGS_PARM2(ctx));
    return 0;
}
```

---

## 11. `math between pkt pointer and register with unbounded min value`

**Significado:** Estás haciendo aritmética de punteros sobre datos de paquete usando un valor cuyo rango mínimo el verifier no puede determinar. El verifier necesita saber que el resultado de la aritmética no producirá un puntero fuera del paquete.

**Errores comunes que lo provocan:**
- Usar un campo del paquete (ej: `ihl`) como offset sin acotar su valor
- Aritmética con valores leídos del paquete sin máscara ni bounds check
- Sumar un registro variable a un puntero de paquete sin validación

**Antes (falla):**

```c
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // ERROR: ip->ihl es unbounded (podría ser 0-15)
    void *transport = (void *)ip + (ip->ihl * 4);
    // El verifier no puede garantizar que transport < data_end
}
```

**Después (correcto):**

```c
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u8 ihl = ip->ihl;
    if (ihl < 5 || ihl > 15)  // acotar el valor de IHL
        return XDP_PASS;

    void *transport = (void *)ip + (ihl * 4);
    if (transport + 1 > data_end)  // re-validar bounds
        return XDP_PASS;

    // Ahora sí es seguro acceder a transport
}
```

---

## 12. `bpf_spin_lock without BTF`

**Significado:** Estás usando `bpf_spin_lock` en un map pero el programa no tiene información BTF (BPF Type Format) asociada. Los spin locks requieren BTF para que el verifier pueda verificar el uso correcto del lock.

**Errores comunes que lo provocan:**
- Compilar sin `-g` (flag de debug info que genera BTF)
- Usar un toolchain viejo que no genera BTF
- Definir el map con spin lock en un kernel que no soporta BTF maps

**Antes (falla):**

Compilación sin BTF:
```bash
clang -O2 -target bpf -c prog.bpf.c -o prog.bpf.o
```

**Después (correcto):**

```bash
clang -O2 -g -target bpf -c prog.bpf.c -o prog.bpf.o
#         ^^ genera BTF
```

Y asegurarte de que la estructura del map incluya el lock correctamente:

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct my_value);  // my_value contiene bpf_spin_lock
} my_map SEC(".maps");

struct my_value {
    struct bpf_spin_lock lock;
    __u64 counter;
};
```

---

## 13. `helper call is not allowed in probe`

**Significado:** Estás intentando usar una helper function que no está disponible para el tipo de programa eBPF que estás escribiendo. No todas las helpers funcionan en todos los contextos.

**Errores comunes que lo provocan:**
- Usar `bpf_skb_load_bytes()` en un programa kprobe (es solo para TC/socket)
- Usar `bpf_redirect()` en un tracepoint
- Usar `bpf_get_socket_cookie()` en un programa que no tiene acceso a sockets
- Confundir helpers de XDP con helpers de TC

**Antes (falla):**

```c
SEC("kprobe/tcp_sendmsg")
int trace_tcp(struct pt_regs *ctx) {
    // ERROR: bpf_redirect no está disponible en kprobes
    return bpf_redirect(2, 0);
}
```

**Después (correcto):**

```c
SEC("kprobe/tcp_sendmsg")
int trace_tcp(struct pt_regs *ctx) {
    __u64 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("tcp_sendmsg pid=%d", pid);
    return 0;
}
```

**Referencia:** Consulta el **Apéndice B** para ver la matriz de compatibilidad helpers × tipos de programa.

---

## 14. `stack depth X exceeds max allowed 512`

**Significado:** Tu programa usa más de 512 bytes de stack. El stack de eBPF está limitado a 512 bytes por frame (por subprograma). Esto incluye variables locales, buffers, y espacio para llamadas a helpers.

**Errores comunes que lo provocan:**
- Declarar buffers grandes en el stack (`char buf[256]` ya ocupa la mitad)
- Múltiples estructuras locales que suman más de 512 bytes
- Funciones inline que acumulan stack de las funciones que llaman

**Antes (falla):**

```c
SEC("kprobe/vfs_write")
int trace_write(struct pt_regs *ctx) {
    char path[256];           // 256 bytes
    char comm[256];           // 256 bytes
    struct event evt = {};    // + N bytes
    // ERROR: total > 512 bytes de stack
    return 0;
}
```

**Después (correcto):**

```c
// Opción 1: Usar un map per-CPU como "stack extendido"
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event_buffer);
} heap SEC(".maps");

struct event_buffer {
    char path[256];
    char comm[256];
};

SEC("kprobe/vfs_write")
int trace_write(struct pt_regs *ctx) {
    __u32 zero = 0;
    struct event_buffer *buf = bpf_map_lookup_elem(&heap, &zero);
    if (!buf)
        return 0;

    bpf_get_current_comm(buf->comm, sizeof(buf->comm));
    // Ahora buf vive en el map, no en el stack
    return 0;
}
```

---

## 15. `cannot pass map_type X into func bpf_YYY`

**Significado:** Estás pasando un tipo de map que no es compatible con el helper que estás llamando. Cada helper que opera sobre maps solo acepta tipos específicos.

**Errores comunes que lo provocan:**
- Usar `bpf_ringbuf_reserve()` con un map que no es `BPF_MAP_TYPE_RINGBUF`
- Pasar un array map a `bpf_map_delete_elem()` (los arrays no soportan delete)
- Usar `bpf_perf_event_output()` con un map que no es `BPF_MAP_TYPE_PERF_EVENT_ARRAY`

**Antes (falla):**

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct event);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(void *ctx) {
    // ERROR: bpf_ringbuf_reserve solo funciona con RINGBUF maps
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    return 0;
}
```

**Después (correcto):**

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(void *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;
    // ... llenar el evento ...
    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

---

## 16. `arg#X expected pointer to ctx, but got PTR`

**Significado:** Un helper espera recibir el puntero al contexto del programa (ctx) directamente, pero le estás pasando otro tipo de puntero. Algunos helpers como `bpf_perf_event_output()` requieren `ctx` como primer argumento.

**Errores comunes que lo provocan:**
- Pasar una variable local en lugar de `ctx`
- Modificar el puntero ctx antes de pasarlo
- Confundir el orden de argumentos de un helper

**Antes (falla):**

```c
SEC("kprobe/do_sys_open")
int trace_open(struct pt_regs *ctx) {
    struct event e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;

    // ERROR: primer arg debe ser ctx, no &e
    bpf_perf_event_output(&e, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}
```

**Después (correcto):**

```c
SEC("kprobe/do_sys_open")
int trace_open(struct pt_regs *ctx) {
    struct event e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;

    // ctx va como primer argumento
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}
```

---

## 17. `invalid size of register fill`

**Significado:** El verifier detectó una inconsistencia en el tamaño de una operación de lectura/escritura en el stack. Ocurre cuando escribes un valor de un tamaño y luego lees del mismo offset con un tamaño diferente.

**Errores comunes que lo provocan:**
- Unions o casts que reinterpretan el mismo espacio de stack con tamaños diferentes
- Escribir un `__u32` y luego leer un `__u64` de la misma posición
- Código generado por el compilador con optimizaciones agresivas

**Antes (falla):**

```c
SEC("kprobe/vfs_read")
int trace_read(struct pt_regs *ctx) {
    __u32 val32 = 42;
    // Guardar 4 bytes en el stack...
    __u64 *ptr = (__u64 *)&val32;
    // ... e intentar leer 8 bytes del mismo lugar: ERROR
    __u64 val64 = *ptr;
    return 0;
}
```

**Después (correcto):**

```c
SEC("kprobe/vfs_read")
int trace_read(struct pt_regs *ctx) {
    __u64 val64 = 42;  // usar el tamaño correcto desde el inicio
    // O si necesitas convertir:
    __u32 val32 = 42;
    __u64 extended = (__u64)val32;  // cast explícito, no reinterpret
    return 0;
}
```

---

## 18. `R0 is not a known value (R0=scalar(...))`

**Significado:** El programa eBPF termina con un valor de retorno que el verifier no puede clasificar como un retorno válido para el tipo de programa. En programas XDP, por ejemplo, el return value debe ser una de las acciones válidas (XDP_PASS, XDP_DROP, etc.).

**Errores comunes que lo provocan:**
- Retornar un valor calculado dinámicamente en un programa XDP/TC
- Retornar el resultado de un helper sin constrained range
- No acotar el valor de retorno a las acciones válidas del programa

**Antes (falla):**

```c
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u32 action;
    __u32 key = 0;
    __u32 *val = bpf_map_lookup_elem(&config_map, &key);
    if (!val)
        return XDP_PASS;
    action = *val;
    return action;  // ERROR: action podría ser cualquier valor
}
```

**Después (correcto):**

```c
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    __u32 action;
    __u32 key = 0;
    __u32 *val = bpf_map_lookup_elem(&config_map, &key);
    if (!val)
        return XDP_PASS;
    action = *val;
    // Acotar a valores válidos de XDP
    if (action > XDP_REDIRECT)
        action = XDP_PASS;
    return action;
}
```

---

## 19. `pointer arithmetic on pkt_end prohibited`

**Significado:** Estás haciendo aritmética sobre el puntero `data_end` del paquete. El verifier no permite operaciones aritméticas sobre `data_end` — solo puedes compararlo contra otro puntero para verificar bounds.

**Errores comunes que lo provocan:**
- Intentar calcular el tamaño del paquete como `data_end - data` y usarlo para indexar
- Restar un offset de `data_end`
- Usar `data_end` como base para acceder datos "desde el final"

**Antes (falla):**

```c
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // ERROR: aritmética sobre data_end
    int pkt_len = data_end - data;
    void *last_byte = data_end - 1;
}
```

**Después (correcto):**

```c
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Calcular tamaño desde data (es puntero aritmético válido)
    // Usar ctx->data_end - ctx->data para el tamaño
    __u32 pkt_len = (__u32)(data_end - data);

    // Para bounds check, comparar punteros directamente
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
}
```

---

## 20. `Unreleased reference id=X alloc_insn=Y`

**Significado:** Reservaste un recurso (como un slot en un ring buffer con `bpf_ringbuf_reserve()`) y existe un path de ejecución donde no lo liberas. El verifier exige que todo recurso reservado se libere (submit o discard) en todos los paths posibles.

**Errores comunes que lo provocan:**
- Reservar ring buffer y retornar antes de hacer submit/discard
- Olvidar el `bpf_ringbuf_discard()` en paths de error
- Branches complejos donde alguna rama no libera el recurso

**Antes (falla):**

```c
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(void *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;

    if (e->pid == 0)
        return 0;  // ERROR: e fue reservado pero nunca se hizo submit/discard

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

**Después (correcto):**

```c
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(void *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;

    if (e->pid == 0) {
        bpf_ringbuf_discard(e, 0);  // liberar en TODOS los paths
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
```

---

## Consejos generales para sobrevivir al verifier

1. **Siempre verifica NULL** después de `bpf_map_lookup_elem()`. Siempre.

2. **Bounds check antes de leer paquetes.** El patrón `if ((void *)(ptr + 1) > data_end)` es tu mejor amigo en XDP/TC.

3. **Inicializa todo.** Variables locales a cero, buffers con `= {}`. El verifier odia la memoria sin inicializar.

4. **Divide y vencerás.** Si el programa es demasiado complejo, usa tail calls o BPF-to-BPF function calls.

5. **Compila con `-g`** para generar BTF. Muchas features modernas lo requieren.

6. **Usa `__always_inline`** en funciones helper locales. Reduce la complejidad que ve el verifier.

7. **Acota los valores.** Si lees un campo del paquete y lo usas como offset, ponle un `& MASK` o un `if (val > MAX)`.

8. **Revisa el log del verifier.** Usa `bpftool prog load prog.o /sys/fs/bpf/prog -d` para ver el log detallado cuando falles.

9. **Actualiza tu kernel.** Cada versión nueva relaja restricciones del verifier y soporta más patterns.

10. **Lee el error completo.** El verifier suele decirte exactamente en qué instrucción y registro falla — usa esa info para ubicar el problema en tu código fuente.

---

> **Referencia cruzada:** Para entender *por qué* el verifier tiene estas reglas, vuelve al **Capítulo 7: El Verifier — Tu enemigo favorito**. Para la lista de helpers válidos por tipo de programa, consulta el **Apéndice B**.
