# Apéndice B: Referencia rápida de helper functions

> Todas las helper functions organizadas por tipo de programa eBPF, con firma simplificada, descripción y kernel mínimo requerido.

---

## Cómo usar esta referencia

Cada entrada sigue el formato:

```
función(parámetros) → retorno
Descripción breve | Kernel mínimo
```

Las funciones están agrupadas por tipo de programa donde son más relevantes. Muchas helpers están disponibles en múltiples tipos de programa — la sección "Universales" lista las que funcionan en prácticamente todos.

> ⚙️ **Nota técnica**: La disponibilidad exacta depende de la versión del kernel y el tipo de programa. Usa `bpftool feature probe` para verificar qué helpers están disponibles en tu sistema.

---

## Universales (disponibles en todos o casi todos los tipos de programa)

### Operaciones de Maps

| Helper | Firma simplificada | Descripción | Kernel |
|--------|-------------------|-------------|--------|
| `bpf_map_lookup_elem` | `(map, key) → *value` | Busca un elemento en el map por su clave | 3.19 |
| `bpf_map_update_elem` | `(map, key, value, flags) → int` | Inserta o actualiza un elemento en el map | 3.19 |
| `bpf_map_delete_elem` | `(map, key) → int` | Elimina un elemento del map por su clave | 3.19 |
| `bpf_map_lookup_and_delete_elem` | `(map, key) → *value` | Busca y elimina atómicamente un elemento | 4.20 |
| `bpf_map_push_elem` | `(map, value, flags) → int` | Inserta un elemento en un map tipo queue/stack | 4.20 |
| `bpf_map_pop_elem` | `(map, value) → int` | Extrae un elemento de un map tipo queue/stack | 4.20 |
| `bpf_map_peek_elem` | `(map, value) → int` | Lee sin extraer de un map tipo queue/stack | 4.20 |

### Tiempo y aleatoriedad

| Helper | Firma simplificada | Descripción | Kernel |
|--------|-------------------|-------------|--------|
| `bpf_ktime_get_ns` | `() → u64` | Retorna timestamp monotónico en nanosegundos | 4.1 |
| `bpf_ktime_get_boot_ns` | `() → u64` | Timestamp incluyendo tiempo en suspend | 5.7 |
| `bpf_ktime_get_coarse_ns` | `() → u64` | Timestamp de menor precisión pero más rápido | 5.11 |
| `bpf_get_prandom_u32` | `() → u32` | Genera un número pseudo-aleatorio de 32 bits | 4.1 |

### Tail calls y control de flujo

| Helper | Firma simplificada | Descripción | Kernel |
|--------|-------------------|-------------|--------|
| `bpf_tail_call` | `(ctx, prog_array, index) → void` | Salta a otro programa BPF (no retorna si tiene éxito) | 4.2 |
| `bpf_spin_lock` | `(lock) → void` | Adquiere un spin lock en un map value | 5.1 |
| `bpf_spin_unlock` | `(lock) → void` | Libera un spin lock en un map value | 5.1 |

### Ring buffer y perf events

| Helper | Firma simplificada | Descripción | Kernel |
|--------|-------------------|-------------|--------|
| `bpf_ringbuf_reserve` | `(ringbuf, size, flags) → *void` | Reserva espacio en el ring buffer | 5.8 |
| `bpf_ringbuf_submit` | `(data, flags) → void` | Envía datos reservados al ring buffer | 5.8 |
| `bpf_ringbuf_discard` | `(data, flags) → void` | Descarta una reserva sin enviar | 5.8 |
| `bpf_ringbuf_output` | `(ringbuf, data, size, flags) → int` | Copia datos al ring buffer (sin reserva previa) | 5.8 |
| `bpf_perf_event_output` | `(ctx, map, flags, data, size) → int` | Envía un evento al perf buffer en user space | 4.4 |

### Debug y logging

| Helper | Firma simplificada | Descripción | Kernel |
|--------|-------------------|-------------|--------|
| `bpf_trace_printk` | `(fmt, fmt_size, ...) → int` | Imprime al trace log del kernel (solo debug) | 4.1 |
| `bpf_printk` | `(fmt, ...) → int` | Macro wrapper de trace_printk (más cómodo) | 5.2 |

---

## Kprobes, Tracepoints y Tracing

### Información de proceso

| Helper | Firma simplificada | Descripción | Kernel |
|--------|-------------------|-------------|--------|
| `bpf_get_current_pid_tgid` | `() → u64` | Retorna PID (bits 0-31) y TGID (bits 32-63) del proceso actual | 4.2 |
| `bpf_get_current_uid_gid` | `() → u64` | Retorna UID (bits 0-31) y GID (bits 32-63) del proceso actual | 4.2 |
| `bpf_get_current_comm` | `(buf, buf_size) → int` | Copia el nombre del proceso actual (hasta 16 bytes) | 4.2 |
| `bpf_get_current_task` | `() → *task_struct` | Retorna puntero al task_struct del proceso actual | 4.8 |
| `bpf_get_current_task_btf` | `() → *task_struct` | Igual que anterior pero con información BTF | 5.11 |
| `bpf_get_current_cgroup_id` | `() → u64` | Retorna el ID del cgroup del proceso actual | 4.18 |
| `bpf_get_ns_current_pid_tgid` | `(dev, ino, ns_info, size) → int` | Retorna PID/TGID en un namespace específico | 5.7 |

### Lectura de memoria del kernel

| Helper | Firma simplificada | Descripción | Kernel |
|--------|-------------------|-------------|--------|
| `bpf_probe_read_kernel` | `(dst, size, src) → int` | Lee memoria del kernel de forma segura | 5.5 |
| `bpf_probe_read_user` | `(dst, size, src) → int` | Lee memoria de user space de forma segura | 5.5 |
| `bpf_probe_read_kernel_str` | `(dst, size, src) → int` | Lee un string del kernel (null-terminated) | 5.5 |
| `bpf_probe_read_user_str` | `(dst, size, src) → int` | Lee un string de user space (null-terminated) | 5.5 |
| `bpf_probe_read` | `(dst, size, src) → int` | Lee memoria (deprecated, usar las versiones específicas) | 4.1 |

### Stack y llamadas

| Helper | Firma simplificada | Descripción | Kernel |
|--------|-------------------|-------------|--------|
| `bpf_get_stackid` | `(ctx, map, flags) → int` | Captura stack trace y retorna ID en el stack map | 4.6 |
| `bpf_get_stack` | `(ctx, buf, size, flags) → int` | Captura stack trace en un buffer proporcionado | 4.18 |
| `bpf_get_func_ip` | `(ctx) → u64` | Retorna la dirección de la función instrumentada | 5.15 |
| `bpf_send_signal` | `(sig) → int` | Envía una señal al proceso actual | 5.3 |
| `bpf_send_signal_thread` | `(sig) → int` | Envía una señal al thread actual | 5.3 |

---

## XDP (eXpress Data Path)

| Helper | Firma simplificada | Descripción | Kernel |
|--------|-------------------|-------------|--------|
| `bpf_xdp_adjust_head` | `(xdp_md, delta) → int` | Mueve el inicio del paquete (encapsular/decapsular) | 4.10 |
| `bpf_xdp_adjust_tail` | `(xdp_md, delta) → int` | Mueve el final del paquete (truncar/extender) | 4.18 |
| `bpf_xdp_adjust_meta` | `(xdp_md, delta) → int` | Ajusta el área de metadata entre XDP y TC | 4.15 |
| `bpf_redirect` | `(ifindex, flags) → int` | Redirige el paquete a otra interfaz de red | 4.4 |
| `bpf_redirect_map` | `(map, key, flags) → int` | Redirige usando un map (devmap/cpumap) — más eficiente | 4.14 |
| `bpf_fib_lookup` | `(ctx, params, plen, flags) → int` | Consulta la tabla de routing (FIB) del kernel | 4.18 |
| `bpf_csum_diff` | `(from, from_size, to, to_size, seed) → int` | Calcula diferencia incremental de checksum | 4.6 |

---

## TC (Traffic Control)

| Helper | Firma simplificada | Descripción | Kernel |
|--------|-------------------|-------------|--------|
| `bpf_skb_load_bytes` | `(skb, offset, to, len) → int` | Lee bytes del paquete desde un offset | 4.5 |
| `bpf_skb_store_bytes` | `(skb, offset, from, len, flags) → int` | Escribe bytes en el paquete en un offset | 4.1 |
| `bpf_skb_change_head` | `(skb, len, flags) → int` | Agranda el headroom del paquete | 4.10 |
| `bpf_skb_change_tail` | `(skb, len, flags) → int` | Cambia el tamaño total del paquete | 4.9 |
| `bpf_skb_change_proto` | `(skb, proto, flags) → int` | Cambia el protocolo L3 del paquete (ej: IPv4↔IPv6) | 4.8 |
| `bpf_skb_pull_data` | `(skb, len) → int` | Asegura que `len` bytes sean lineales (no paginados) | 4.9 |
| `bpf_l3_csum_replace` | `(skb, offset, from, to, size) → int` | Reemplaza checksum L3 incrementalmente | 4.1 |
| `bpf_l4_csum_replace` | `(skb, offset, from, to, flags) → int` | Reemplaza checksum L4 incrementalmente | 4.1 |
| `bpf_skb_vlan_push` | `(skb, vlan_proto, vlan_tci) → int` | Agrega tag VLAN al paquete | 4.3 |
| `bpf_skb_vlan_pop` | `(skb) → int` | Remueve tag VLAN del paquete | 4.3 |
| `bpf_skb_get_tunnel_key` | `(skb, key, size, flags) → int` | Obtiene metadata del túnel (VXLAN, GRE, etc.) | 4.3 |
| `bpf_skb_set_tunnel_key` | `(skb, key, size, flags) → int` | Establece metadata del túnel para encapsulación | 4.3 |
| `bpf_clone_redirect` | `(skb, ifindex, flags) → int` | Clona el paquete y lo redirige a otra interfaz | 4.2 |
| `bpf_redirect_neigh` | `(ifindex, params, plen, flags) → int` | Redirige con resolución de neighbor (L2) | 5.10 |

---

## LSM (Linux Security Modules)

| Helper | Firma simplificada | Descripción | Kernel |
|--------|-------------------|-------------|--------|
| `bpf_lsm_*` (hooks) | `(args...) → int` | Implementa decisiones de seguridad en hooks LSM | 5.7 |
| `bpf_ima_inode_hash` | `(inode, dst, size) → int` | Obtiene hash IMA de un inodo (integridad de archivos) | 5.11 |
| `bpf_ima_file_hash` | `(file, dst, size) → int` | Obtiene hash IMA de un archivo abierto | 5.11 |
| `bpf_bprm_opts_set` | `(bprm, flags) → int` | Modifica opciones de ejecución de binarios (security) | 5.3 |
| `bpf_task_storage_get` | `(map, task, value, flags) → *void` | Obtiene storage local asociado a un task | 5.11 |
| `bpf_task_storage_delete` | `(map, task) → int` | Elimina storage local de un task | 5.11 |
| `bpf_inode_storage_get` | `(map, inode, value, flags) → *void` | Obtiene storage local asociado a un inodo | 5.10 |
| `bpf_inode_storage_delete` | `(map, inode) → int` | Elimina storage local de un inodo | 5.10 |

---

## CO-RE y BTF (macros y funciones de compilación)

Estas no son helper functions del kernel, sino macros/funciones de libbpf que se resuelven en tiempo de compilación. Se incluyen aquí porque son fundamentales en cualquier programa BPF moderno.

| Macro/Función | Uso | Descripción | Requiere |
|---------------|-----|-------------|----------|
| `BPF_CORE_READ` | `BPF_CORE_READ(ptr, field)` | Lee un campo de una estructura del kernel con relocación CO-RE | libbpf + BTF |
| `BPF_CORE_READ_INTO` | `BPF_CORE_READ_INTO(dst, src, field)` | Lee campo CO-RE directamente en una variable destino | libbpf + BTF |
| `BPF_CORE_READ_STR_INTO` | `BPF_CORE_READ_STR_INTO(dst, src, field)` | Lee string CO-RE en buffer destino | libbpf + BTF |
| `bpf_core_field_exists` | `bpf_core_field_exists(field)` | Verifica si un campo existe en la estructura del kernel actual | libbpf + BTF |
| `bpf_core_field_size` | `bpf_core_field_size(field)` | Retorna el tamaño de un campo en el kernel actual | libbpf + BTF |
| `bpf_core_type_exists` | `bpf_core_type_exists(type)` | Verifica si un tipo existe en el kernel actual | libbpf + BTF |
| `bpf_core_enum_value_exists` | `bpf_core_enum_value_exists(type, val)` | Verifica si un valor de enum existe en el kernel actual | libbpf + BTF |

---

## Notas importantes

### Sobre disponibilidad

- La columna "Kernel" indica la versión **mínima** donde se introdujo la helper.
- Algunas helpers requieren capabilities específicas (`CAP_BPF`, `CAP_NET_ADMIN`, etc.).
- El verifier restringe qué helpers puede usar cada tipo de programa — no todas las combinaciones son válidas.

### Sobre deprecación

- `bpf_probe_read` (sin sufijo) está deprecated desde kernel 5.5. Usar `bpf_probe_read_kernel` o `bpf_probe_read_user` según corresponda.
- `bpf_trace_printk` es solo para debug — nunca usar en producción (impacto de rendimiento severo).

### Verificar en tu sistema

```bash
# Ver helpers disponibles por tipo de programa
bpftool feature probe | grep helper

# Ver helpers de un programa cargado
bpftool prog dump jited id <PROG_ID> | grep call
```

---

## Referencia completa

Para la lista exhaustiva y actualizada de todas las BPF helper functions:

- **Kernel source**: `include/uapi/linux/bpf.h` (documentación en comentarios)
- **man page**: `man 7 bpf-helpers`
- **Online**: [ebpf-docs helpers](https://ebpf-docs.dylanreimerink.nl/linux/helper-function/)
