# Apéndice A: Glosario bilingüe

> Todos los términos técnicos en inglés que aparecen en el libro, con su explicación en español y el capítulo donde se introducen por primera vez.

---

## Cómo usar este glosario

Cada entrada sigue el formato:

**término** (pronunciación) — explicación en español. Introducido en: Capítulo N.

Los términos están organizados alfabéticamente por el término en inglés. Si necesitas buscar un concepto en español, usa el índice temático al final de este apéndice.

---

## A

**AF_XDP** (ei-ef eks-di-pi) — familia de sockets que permite desviar paquetes desde XDP directamente al user space sin pasar por el network stack del kernel. Ideal para procesamiento custom de paquetes a alta velocidad. Introducido en: Capítulo 16.

**attach point** (atach point) — lugar específico del kernel (función, tracepoint, hook de red) donde un programa eBPF se conecta para ejecutarse. También llamado "punto de enganche". Introducido en: Capítulo 2.

**Aya** (áia) — framework en Rust para escribir programas BPF completos (kernel + user space) con safety garantizado por el type system de Rust. Introducido en: Capítulo 3.

## B

**batching** (baching) — técnica de agrupar múltiples operaciones de map en una sola llamada al kernel para reducir el overhead de transición user/kernel. Introducido en: Capítulo 18.

**BPF** (bi-pi-ef) — Berkeley Packet Filter. El filtro de paquetes original de 1992, ancestro de eBPF. Todo empezó aquí. Introducido en: Capítulo 2.

**BPF_CORE_READ** (bi-pi-éf kor ríd) — macro que realiza lecturas de campos de estructuras del kernel con soporte de relocations CO-RE, permitiendo portabilidad entre versiones de kernel. Introducido en: Capítulo 15.

**BPF_MAP_TYPE_PROG_ARRAY** (prog aréi) — tipo especial de map que almacena file descriptors de programas BPF. Es la tabla de saltos que las tail calls usan para transferir control entre programas. Introducido en: Capítulo 14.

**BPF_PROG_TEST_RUN** (bi-pi-ef prog test ran) — comando del syscall `bpf()` que permite ejecutar un programa BPF contra datos sintéticos sin hooks activos ni tráfico real. El unit test de programas BPF. Introducido en: Capítulo 18.

**BPF profiling** (bi-pi-ef profáiling) — técnicas para medir el rendimiento de programas BPF: instrucciones ejecutadas, tiempo de ejecución, frecuencia de invocación. Introducido en: Capítulo 18.

**BPF-to-BPF function call** (bi-pi-ef tu bi-pi-ef) — llamada a función normal dentro del ecosistema BPF donde la función llamada retorna al punto de llamada. Es el `call` + `return` tradicional, a diferencia de una tail call. Introducido en: Capítulo 14.

**bpf2go** (bi-pi-ef-tu-gou) — herramienta del proyecto cilium/ebpf que compila programas BPF en C y genera código Go para cargarlos y manejarlos automáticamente. Introducido en: Capítulo 3.

**bpf_get_current_comm** (bi-pi-ef get current com) — helper function que copia el nombre del proceso actual (campo `comm` del `task_struct`) a un buffer. Máximo 16 caracteres. Introducido en: Capítulo 4.

**bpf_get_current_pid_tgid** (bi-pi-ef get current pid ti-yi-ai-di) — helper que retorna PID y TGID del proceso actual empaquetados en 64 bits. Los 32 bits altos son el TGID, los bajos son el TID. Introducido en: Capítulo 4.

**bpf_ktime_get_ns** (bi-pi-ef k-táim get nano-ése) — helper que retorna el tiempo monotónico del kernel en nanosegundos. Tu cronómetro dentro del kernel. Introducido en: Capítulo 8.

**bpf_map_delete_elem** (bi-pi-ef map delít élem) — helper para eliminar una entrada de un map por clave. Introducido en: Capítulo 8.

**bpf_map_lookup_elem** (bi-pi-ef map lúkap élem) — helper para buscar un valor en un map por clave. Retorna un puntero al valor o NULL si no existe. Introducido en: Capítulo 8.

**bpf_map_update_elem** (bi-pi-ef map ápdeit élem) — helper para insertar o actualizar un par clave-valor en un map. Introducido en: Capítulo 8.

**bpf_perf_event_output** (bi-pi-ef perf ivént áutput) — helper para enviar datos a un perf event buffer en user space. La forma clásica de comunicar eventos kernel→user. Introducido en: Capítulo 8.

**bpf_redirect** (bi-pi-ef ri-dáirekt) — helper para redirigir un paquete a otra interfaz de red o a un socket. Introducido en: Capítulo 8.

**bpf_ringbuf_output** (bi-pi-ef ring-baf áutput) — helper para escribir datos en un ring buffer. La forma moderna y eficiente de comunicar eventos kernel→user. Introducido en: Capítulo 8.

**bpf_skb_load_bytes** (bi-pi-ef es-ká-bi lóud báits) — helper para leer bytes de un socket buffer (paquete de red) de forma segura, respetando los bounds. Introducido en: Capítulo 8.

**bpf_tail_call** (bi-pi-ef teil col) — helper function que ejecuta una tail call. Recibe el contexto, el prog_array map, y un índice. Si falla, la ejecución continúa normalmente. Introducido en: Capítulo 14.

**bpf_trace_printk** (bi-pi-ef tréis príntk) — helper que imprime mensajes de debug al trace buffer del kernel. Es el `printf` de eBPF, pero con limitaciones severas y no apto para producción. Introducido en: Capítulo 4.

**bpf_xdp_adjust_head** (bi-pi-ef ex-di-pi adyást jed) — helper para mover el puntero de inicio del paquete en programas XDP, útil para encapsular o desencapsular paquetes. Introducido en: Capítulo 8.

**bpftool** (bi-pi-ef-tul) — utilidad de línea de comandos para inspeccionar, cargar y gestionar programas BPF y maps en el kernel. La navaja suiza del administrador BPF. Introducido en: Capítulo 3.

**BTF** (bi-ti-éf) — BPF Type Format. Formato compacto de metadata que describe todos los tipos del kernel (structs, enums, typedefs). Viaja embebido en el binario del kernel y en objetos BPF. Introducido en: Capítulo 3 (mención), Capítulo 15 (profundidad).

**bounded loop** (báunded lup) — loop con un número máximo de iteraciones conocido en tiempo de compilación. El verifier solo acepta loops que puede demostrar que terminan. Introducido en: Capítulo 7.

**bounds checking** (báunds chéking) — verificación de que un puntero no excede los límites del paquete. Obligatorio en XDP/TC antes de leer cualquier byte. Introducido en: Capítulo 10.

**bytecode** (báit-cod) — instrucciones intermedias que ejecuta la máquina virtual eBPF. Como el assembly de Java pero para el kernel. Introducido en: Capítulo 2.

## C

**cilium/ebpf** (sílium i-bi-pi-ef) — biblioteca en Go para interactuar con programas eBPF: cargar, adjuntar, leer maps, y manejar el ciclo de vida completo. El framework principal de este libro. Introducido en: Capítulo 3.

**clang** (clang) — compilador del proyecto LLVM capaz de generar bytecode BPF desde código C. Tu puerta de entrada para escribir programas que corren en el kernel. Introducido en: Capítulo 3.

**CO-RE** (kór) — Compile Once, Run Everywhere. Mecanismo que permite compilar un programa BPF una sola vez y ejecutarlo en kernels con diferentes layouts de estructuras. Introducido en: Capítulo 15.

**complexity limit** (compléxiti límit) — número máximo de instrucciones que el verifier analiza antes de rechazar un programa (1 millón en kernels modernos). Introducido en: Capítulo 7.

**consistent hashing** (consístent jáshing) — algoritmo de distribución de carga que minimiza la redistribución cuando se agregan o eliminan backends. Solo el ~10% del tráfico se redistribuye por cada cambio. Introducido en: Capítulo 16.

**context switch** (cóntext suích) — cuando el kernel pausa un proceso y le da el CPU a otro. Cuesta tiempo y es una de las razones por las que eBPF es preferible a user space para tareas críticas. Introducido en: Capítulo 1.

**contributor** (contribiútor) — persona que envía parches al subsistema BPF del kernel Linux vía mailing lists, con revisión de código y tags como `Acked-by`. Introducido en: Capítulo 18.

## D

**dead code** (ded coud) — instrucciones que el verifier determina que nunca se ejecutarán. En kernels modernos se toleran, pero es mejor no tenerlas. Introducido en: Capítulo 7.

**devmap** (dév-map) — map de tipo `BPF_MAP_TYPE_DEVMAP` que almacena interfaces de red indexadas por ifindex. Permite redirigir paquetes entre interfaces a velocidad wire-speed. Introducido en: Capítulo 16.

**dynamic tracing** (dainámik tréising) — instrumentación que se instala en runtime sin recompilar ni reiniciar el kernel. Los kprobes son el ejemplo canónico. Introducido en: Capítulo 9.

## E

**eBPF** (i-bi-pi-ef) — extended BPF. La evolución de BPF en una máquina virtual completa dentro del kernel que permite ejecutar programas seguros y verificados en contexto privilegiado. El protagonista de este libro. Introducido en: Capítulo 2.

**egress** (ígrés) — tráfico que sale por una interfaz de red. La dirección "paquete que se va". Introducido en: Capítulo 10.

**ELF** (elf) — Executable and Linkable Format. Formato de archivo binario estándar en Linux. Los programas BPF compilados se empaquetan como objetos ELF con secciones especiales. Introducido en: Capítulo 3.

## F

**fentry** (ef-éntri) — mecanismo moderno de instrumentación de entrada a funciones del kernel basado en BTF. Más eficiente que kprobes y con acceso type-safe a los argumentos. Introducido en: Capítulo 9.

**fexit** (ef-éxit) — mecanismo moderno de instrumentación de retorno de funciones del kernel basado en BTF. Da acceso tanto a los argumentos originales como al valor de retorno. Introducido en: Capítulo 9.

**field offset** (fíld ófset) — posición en bytes de un campo dentro de una estructura del kernel. Puede cambiar entre versiones, y CO-RE existe para resolver este problema. Introducido en: Capítulo 15.

## G

**go generate** (gou yéneret) — comando de Go que ejecuta directivas `//go:generate` para automatizar generación de código. Usado por cilium/ebpf para generar bindings desde programas BPF. Introducido en: Capítulo 3.

## H

**hash map** (jash map) — tipo de map BPF que implementa una tabla hash genérica con claves y valores de tamaño arbitrario. El map más versátil y usado del ecosistema. Introducido en: Capítulo 6.

**helper function** (jélper fánkshon) — función proporcionada por el kernel que un programa eBPF puede invocar. Es la única forma que tiene un programa BPF de interactuar con el mundo exterior. Introducido en: Capítulo 2 (concepto), Capítulo 8 (profundidad).

**helper function signature** (jélper fánkshon sígnacher) — tipo de retorno y tipos de argumentos que el verifier conoce para cada helper. Pasar un tipo incorrecto resulta en rechazo. Introducido en: Capítulo 7.

**hook** (juk) — punto en el código del kernel donde puedes enganchar un programa eBPF para interceptar eventos. Cada tipo de programa tiene sus hooks disponibles. Introducido en: Capítulo 2.

## I

**ingress** (íngrés) — tráfico que entra a una interfaz de red. La dirección "paquete que llega". Introducido en: Capítulo 10.

**inlining** (in-láining) — directiva del compilador que copia el cuerpo de una función en cada punto de llamada, eliminando el overhead de la llamada. En BPF, `__always_inline` es casi obligatorio para funciones hot. Introducido en: Capítulo 18.

**IPVS** (ai-pi-ví-es) — IP Virtual Server. Load balancer L4 del kernel Linux implementado como módulo de netfilter. La alternativa sin eBPF para balanceo de carga. Introducido en: Capítulo 16.

## J

**JIT** (yit) — Just-In-Time compiler. Traduce bytecode eBPF a instrucciones nativas de tu CPU para ejecutar a velocidad máxima, sin overhead de interpretación. Introducido en: Capítulo 2.

## K

**kernel** (kérnel) — núcleo del sistema operativo que controla todo el hardware y los recursos. El jefe invisible de tu máquina. Introducido en: Capítulo 1.

**kernel space** (kérnel spéis) — zona privilegiada de memoria donde corre el kernel y sus módulos. Aquí se toman las decisiones de verdad sobre hardware y recursos. Introducido en: Capítulo 1.

**kprobe** (kéi-proub) — mecanismo de instrumentación dinámica que permite interceptar la entrada a cualquier función del kernel en runtime sin modificar código fuente. Introducido en: Capítulo 9.

**kretprobe** (kéi-ret-proub) — variante de kprobe que intercepta el punto de retorno de una función del kernel, permitiendo capturar el valor de retorno. Introducido en: Capítulo 9.

## L

**libbpf** (lib-bi-pi-ef) — biblioteca en C que simplifica la carga y gestión de programas BPF. Es la referencia de bajo nivel del ecosistema y la base sobre la que se construyen otros frameworks. Introducido en: Capítulo 3.

**LLVM** (el-el-vi-em) — infraestructura de compiladores que incluye el backend capaz de emitir instrucciones BPF. clang es su frontend para C. Introducido en: Capítulo 3.

**LSM** (el-es-em) — Linux Security Modules. Framework del kernel para implementar políticas de seguridad. eBPF puede adjuntarse a LSM hooks para tomar decisiones de seguridad en tiempo real. Introducido en: Capítulo 17.

## M

**map** (map) — estructura de datos en kernel space que sirve para almacenar datos y comunicar programas eBPF con user space. El mecanismo principal de persistencia y comunicación del ecosistema BPF. Introducido en: Capítulo 2 (concepto), Capítulo 6 (profundidad).

## N

**network stack** (nétuork stak) — conjunto de capas del kernel que procesan paquetes de red (driver → XDP → TC → IP → TCP/UDP → socket). XDP opera antes de que el paquete entre al stack completo. Introducido en: Capítulo 10.

## O

**object file** (óbject fail) — archivo `.o` resultado de compilar código C con clang. Contiene bytecode BPF empaquetado en formato ELF listo para ser cargado en el kernel. Introducido en: Capítulo 3.

## P

**per-CPU map** (per si-pi-iu map) — variante de map donde cada CPU tiene su propia copia de los valores. Elimina contención entre cores pero requiere sumar todas las copias al leer desde user space. Introducido en: Capítulo 6 (concepto), Capítulo 18 (optimización).

**perf event** (perf ivént) — mecanismo del kernel para enviar eventos desde kernel space a user space. Precursor del ring buffer, todavía útil para ciertos patrones de comunicación. Introducido en: Capítulo 12.

**pointer validity** (póinter valíditi) — propiedad que el verifier verifica para cada puntero: que no sea NULL, que no apunte fuera de bounds, y que se haya verificado antes de usarse. Introducido en: Capítulo 7.

**prog_array** (prog aréi) — nombre coloquial del map de tipo `BPF_MAP_TYPE_PROG_ARRAY`. La tabla de saltos para tail calls. Introducido en: Capítulo 14.

**program type** (prógram taip) — categoría de programa eBPF que define qué puede hacer, qué helpers puede llamar, y dónde se puede adjuntar. Ejemplos: XDP, TC, kprobe, LSM. Introducido en: Capítulo 2.

**pruning** (prúning) — optimización del verifier que evita re-analizar caminos ya verificados. Si un estado es equivalente a uno previamente visto, corta el análisis. Introducido en: Capítulo 7.

## R

**register state** (réyister stéit) — estado que el verifier mantiene para cada uno de los 11 registros BPF (r0-r10) durante el análisis estático: NOT_INIT, SCALAR, PTR_TO_MAP_VALUE, PTR_TO_CTX, etc. Introducido en: Capítulo 7.

**relocation** (ri-lou-kéi-shon) — ajuste de offsets de campos dentro de estructuras del kernel que CO-RE realiza en tiempo de carga. Permite que un mismo binario funcione en kernels con layouts diferentes. Introducido en: Capítulo 15.

**ring buffer** (ring báfer) — estructura de datos circular en kernel space para comunicación eficiente de eventos kernel→user. Reemplaza a perf events con mejor rendimiento y API más simple. Introducido en: Capítulo 6 (concepto), Capítulo 12 (profundidad).

**ring 0 / ring 3** (ring síro / ring trí) — niveles de privilegio del procesador. Ring 0 = kernel (todo permitido). Ring 3 = user space (permisos restringidos). Introducido en: Capítulo 1.

## S

**scheduler** (skédyuler) — subsistema del kernel que decide qué proceso corre en cada momento y por cuánto tiempo. Introducido en: Capítulo 1.

**SEC** (sec, de "section") — macro de C que coloca una función o variable en una sección específica del ELF. Le dice al loader qué tipo de programa es y dónde adjuntarlo. Introducido en: Capítulo 4.

**sk_buff** (es-ká-baf) — socket buffer. La estructura central del networking en Linux. Los programas TC reciben un `__sk_buff` que es una vista eBPF-safe de esta estructura masiva. Introducido en: Capítulo 10.

**stack depth** (stak depz) — profundidad acumulada del stack entre un programa y sus funciones BPF-to-BPF. El verifier impone un máximo de 512 bytes por programa. Introducido en: Capítulo 14.

**stack limit** (stak límit) — límite de 512 bytes para la pila de un programa BPF. No hay heap, no hay malloc. Lo que cabe en la pila es todo lo que tienes. Introducido en: Capítulo 7.

**static tracing** (státik tréising) — instrumentación predefinida en el código fuente del kernel con interfaces estables entre versiones. Los tracepoints son el ejemplo canónico. Introducido en: Capítulo 9.

**struct pt_regs** (pi-ti-régs) — estructura que contiene los registros del procesador en el punto donde se disparó un kprobe. Es el contexto de ejecución que recibe tu programa BPF al interceptar una función. Introducido en: Capítulo 9.

**system call** (sístem col) — mecanismo por el cual un programa en user space le pide algo al kernel. También llamado "syscall". Es la única forma legítima de cruzar la frontera user/kernel. Introducido en: Capítulo 1.

## T

**tail call** (teil col) — mecanismo que permite a un programa BPF transferir control a otro programa BPF sin volver. El programa llamante termina; el llamado toma su lugar. Límite: 33 encadenadas. Introducido en: Capítulo 14.

**TC** (ti-si) — Traffic Control. Subsistema del kernel para controlar tráfico de red. Permite adjuntar programas eBPF como filtros en ingress o egress, operando después de XDP. Introducido en: Capítulo 10.

**toolchain** (tul-chéin) — conjunto de herramientas que transforman tu código fuente en un programa funcional cargado en el kernel: compilador, linker, y utilidades de gestión. Introducido en: Capítulo 3.

**trace_pipe** (tréis páip) — archivo virtual en `/sys/kernel/debug/tracing/trace_pipe` donde aparecen los mensajes emitidos por `bpf_trace_printk`. Tu ventana de debug al kernel. Introducido en: Capítulo 4.

**tracepoint** (tréis-point) — punto de instrumentación estático definido en el código fuente del kernel. Es estable entre versiones y tiene formato documentado, a diferencia de los kprobes. Introducido en: Capítulo 4 (uso), Capítulo 9 (profundidad).

**trap** (trap) — instrucción que causa una transición de user space a kernel space. Es el mecanismo de hardware detrás de las syscalls y las excepciones. Introducido en: Capítulo 1.

**type encoding** (taip en-kóu-ding) — representación compacta de la información de un tipo (nombre, tamaño, campos, offsets) en formato BTF. Cada tipo tiene un ID único. Introducido en: Capítulo 15.

## U

**uprobe** (iú-proub) — similar a kprobe pero para funciones en user space. Intercepta la entrada a funciones en binarios o bibliotecas compartidas sin modificar su código. Introducido en: Capítulo 9.

**user space** (iúser spéis) — zona de memoria donde corren tus programas normales (navegador, servidor web, scripts). No tiene acceso directo al hardware — necesita syscalls para todo. Introducido en: Capítulo 1.

## V

**verifier** (véri-faier) — componente del kernel que analiza estáticamente cada programa BPF antes de permitir su ejecución. Si no pasa el verifier, no corre. Es la garantía de seguridad del modelo eBPF. Introducido en: Capítulo 2 (concepto), Capítulo 7 (profundidad).

**vmlinux.h** (vi-em-línux punto áche) — header generado automáticamente desde el BTF del kernel que contiene las definiciones de TODAS las estructuras, enums y typedefs del kernel. Reemplaza la necesidad de instalar kernel headers. Introducido en: Capítulo 15.

## X

**XDP** (ex-di-pi) — eXpress Data Path. Hook de procesamiento de paquetes que se ejecuta en el driver de la NIC, antes de que el paquete entre al network stack del kernel. El punto más temprano donde puedes tocar un paquete. Introducido en: Capítulo 10.

**XDP_ABORTED** — acción XDP que indica un error en el programa. El paquete se descarta y se genera un tracepoint para debugging. Introducido en: Capítulo 10.

**XDP_DROP** — acción XDP que descarta el paquete silenciosamente. No llega a ningún lado. Muere ahí. Introducido en: Capítulo 10.

**XDP_PASS** — acción XDP que deja pasar el paquete al network stack normal del kernel. Introducido en: Capítulo 10.

**XDP_REDIRECT** — acción XDP que envía el paquete a otra interfaz de red o a un socket AF_XDP. Introducido en: Capítulo 10 (concepto), Capítulo 16 (producción).

**XDP_TX** — acción XDP que rebota el paquete por la misma interfaz por la que entró. Útil para respuestas rápidas sin procesar en stack. Introducido en: Capítulo 10.

**XDP native mode** (natív moud) — modo de ejecución donde el programa XDP corre directamente en el driver de la NIC, antes de alocar `sk_buff`. El modo más rápido pero requiere soporte del driver. Introducido en: Capítulo 16.

**XDP offload** (ófloud) — modo donde el programa XDP se ejecuta directamente en el hardware de la NIC (SmartNIC). El paquete nunca toca la CPU del host. Introducido en: Capítulo 16.

**xdp_md** (ex-di-pi em-di) — estructura de contexto que recibe un programa XDP. Contiene punteros al inicio y fin del paquete, y metadata como el índice de la interfaz de red. Introducido en: Capítulo 10.

## __

**__builtin_preserve_access_index** — intrínseco del compilador clang que instruye emitir información de relocation para cada acceso a campos de estructuras. Es el mecanismo de bajo nivel que habilita CO-RE. Introducido en: Capítulo 15.

**__u32** (unsigned terty-tu) — tipo de 32 bits sin signo definido en los headers del kernel. Alias de `uint32_t` en el ecosistema BPF/kernel. Introducido en: Capítulo 4.

**__u64** (unsigned sixti-for) — tipo de 64 bits sin signo definido en los headers del kernel. Alias de `uint64_t` en el ecosistema BPF/kernel. Introducido en: Capítulo 4.

---

## Índice temático

Para encontrar términos por área conceptual:

### Fundamentos del kernel (Capítulos 1-2)
kernel, user space, kernel space, system call, scheduler, context switch, ring 0/ring 3, trap, BPF, eBPF, bytecode, JIT, verifier, hook, attach point, program type, helper function, map

### Toolchain y entorno (Capítulo 3)
clang, LLVM, bpftool, ELF, object file, BTF, go generate, bpf2go, toolchain, libbpf, Aya, cilium/ebpf

### Primer programa (Capítulo 4)
bpf_trace_printk, trace_pipe, SEC, __u32, __u64, bpf_get_current_pid_tgid, bpf_get_current_comm, tracepoint

### Maps y datos (Capítulo 6)
hash map, per-CPU map, ring buffer

### Verifier (Capítulo 7)
bounded loop, stack limit, pointer validity, dead code, register state, pruning, complexity limit, helper function signature

### Helper functions (Capítulo 8)
bpf_ktime_get_ns, bpf_map_lookup_elem, bpf_map_update_elem, bpf_map_delete_elem, bpf_perf_event_output, bpf_ringbuf_output, bpf_skb_load_bytes, bpf_redirect, bpf_xdp_adjust_head

### Instrumentación (Capítulo 9)
kprobe, kretprobe, fentry, fexit, uprobe, struct pt_regs, dynamic tracing, static tracing

### Networking (Capítulo 10)
XDP, TC, xdp_md, sk_buff, XDP_PASS, XDP_DROP, XDP_TX, XDP_REDIRECT, XDP_ABORTED, bounds checking, ingress, egress, network stack

### Frameworks (Capítulo 11)
cilium/ebpf, Aya, libbpf

### Comunicación user↔kernel (Capítulo 12)
perf event, ring buffer

### Tail calls y composición (Capítulo 14)
tail call, BPF_MAP_TYPE_PROG_ARRAY, bpf_tail_call, BPF-to-BPF function call, stack depth, prog_array

### BTF y portabilidad (Capítulo 15)
BTF, CO-RE, vmlinux.h, relocation, BPF_CORE_READ, __builtin_preserve_access_index, field offset, type encoding

### Networking avanzado (Capítulo 16)
XDP native mode, XDP offload, consistent hashing, IPVS, devmap, AF_XDP, XDP_REDIRECT

### Seguridad y observabilidad (Capítulo 17)
LSM

### Optimización (Capítulo 18)
BPF_PROG_TEST_RUN, per-CPU map, batching, inlining, BPF profiling, contributor
