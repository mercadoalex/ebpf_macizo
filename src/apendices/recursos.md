# Apéndice E: Recursos y comunidad

> Documentación oficial, repositorios clave, conferencias, comunidades y blogs para seguir aprendiendo sobre eBPF.

---

## Documentación oficial

| Recurso | URL | Descripción |
|---------|-----|-------------|
| eBPF.io | [ebpf.io](https://ebpf.io) | Portal oficial del proyecto eBPF — punto de entrada ideal con guías, laboratorios y estado del ecosistema |
| Kernel BPF docs | [docs.kernel.org/bpf](https://docs.kernel.org/bpf/) | Documentación oficial del subsistema BPF en el kernel Linux |
| cilium/ebpf docs | [ebpf-go.dev](https://ebpf-go.dev) | Documentación de la librería Go que usamos en este libro |
| Aya Book | [aya-rs.dev/book](https://aya-rs.dev/book/) | Guía oficial del framework Aya para eBPF en Rust |
| libbpf docs | [libbpf.readthedocs.io](https://libbpf.readthedocs.io) | Documentación de la librería C canonical para eBPF |
| man bpf-helpers | `man 7 bpf-helpers` | Referencia completa de helper functions (local en tu sistema) |
| BPF Design Q&A | [kernel.org/doc/.../bpf_design_QA](https://docs.kernel.org/bpf/bpf_design_QA.html) | Decisiones de diseño del subsistema BPF explicadas por los maintainers |

---

## Repositorios clave

### Frameworks y librerías

| Repo | Lenguaje | Descripción |
|------|----------|-------------|
| [cilium/ebpf](https://github.com/cilium/ebpf) | Go | Librería pura Go para eBPF — la que usamos en el libro |
| [aya-rs/aya](https://github.com/aya-rs/aya) | Rust | Framework eBPF completo en Rust, sin dependencia de libbpf |
| [libbpf/libbpf](https://github.com/libbpf/libbpf) | C | Librería canónica de eBPF, parte del kernel upstream |
| [iovisor/bcc](https://github.com/iovisor/bcc) | C/Python | BPF Compiler Collection — herramientas y framework con bindings Python |
| [libbpf/libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) | C | Templates para empezar proyectos eBPF con libbpf rápidamente |

### Herramientas

| Repo | Descripción |
|------|-------------|
| [bpftool](https://github.com/libbpf/bpftool) | Herramienta CLI para inspeccionar y manipular programas/maps BPF |
| [cilium/cilium](https://github.com/cilium/cilium) | Networking y seguridad para Kubernetes basado en eBPF |
| [falcosecurity/falco](https://github.com/falcosecurity/falco) | Runtime security usando eBPF para detección de amenazas |
| [cilium/tetragon](https://github.com/cilium/tetragon) | Observabilidad de seguridad y enforcement con eBPF |
| [pixie-io/pixie](https://github.com/pixie-io/pixie) | Observabilidad auto-instrumentada para Kubernetes con eBPF |
| [aquasecurity/tracee](https://github.com/aquasecurity/tracee) | Runtime security y forensics con eBPF |
| [iovisor/bpftrace](https://github.com/iovisor/bpftrace) | Lenguaje de tracing de alto nivel para eBPF (estilo AWK/DTrace) |

---

## Conferencias

| Evento | Frecuencia | Descripción |
|--------|-----------|-------------|
| **eBPF Summit** | Anual (virtual) | La conferencia dedicada a eBPF — talks técnicos, lightning talks, y demos del ecosistema. Organizada por Isovalent/Cilium. Grabaciones disponibles gratuitamente. |
| **Linux Plumbers Conference** | Anual | Track dedicado a Networking/BPF donde los kernel developers discuten el futuro del subsistema. Las decisiones de diseño de eBPF se toman aquí. |
| **KubeCon + CloudNativeCon** | 2x año | Track de eBPF creciente — enfocado en uso de eBPF en Kubernetes (Cilium, Tetragon, Pixie). |
| **LSF/MM/BPF** | Anual | Workshop cerrado de kernel developers donde se planifican las features de BPF del próximo ciclo. Notas publicadas después. |
| **FOSDEM** | Anual (Bruselas) | Devroom de networking/kernel con talks regulares sobre eBPF. Entrada gratuita. |
| **Kernel Recipes** | Anual (París) | Conferencia de kernel con talks frecuentes sobre BPF. Excelente nivel técnico. |

---

## Comunidades

| Comunidad | Cómo unirse | Descripción |
|-----------|-------------|-------------|
| **eBPF Slack** | [ebpf.io/slack](https://ebpf.io/slack) | Canal #ebpf-general — la comunidad más activa para preguntas y discusión sobre eBPF |
| **BPF mailing list** | `bpf@vger.kernel.org` | Lista donde se discuten parches, features y cambios al subsistema BPF del kernel |
| **Reddit r/ebpf** | [reddit.com/r/ebpf](https://reddit.com/r/ebpf) | Subreddit para noticias, preguntas y proyectos de eBPF |
| **Stack Overflow** | Tag `[ebpf]` y `[bpf]` | Preguntas técnicas puntuales — buena base de conocimiento buscable |
| **Cilium Slack** | [cilium.io/slack](https://cilium.io/slack) | Canal #ebpf-go para preguntas específicas de la librería cilium/ebpf |
| **Aya Discord** | [discord.gg/aya](https://discord.gg/xHW2cb5jW9) | Comunidad del framework Aya para eBPF en Rust |
| **LKML** | `linux-kernel@vger.kernel.org` | Linux Kernel Mailing List — para seguir el desarrollo general del kernel |

---

## Blogs y newsletters

### Blogs individuales

| Autor | URL | Enfoque |
|-------|-----|---------|
| **Brendan Gregg** | [brendangregg.com/blog](https://www.brendangregg.com/blog/) | El referente en performance y tracing con BPF — sus posts son lectura obligatoria |
| **Andrii Nakryiko** | [nakryiko.com](https://nakryiko.com/) | Maintainer de libbpf — posts profundos sobre CO-RE, BTF, y el futuro de BPF |
| **Quentin Monnet** | [qmonnet.github.io](https://qmonnet.github.io/) | Co-maintainer de bpftool — artículos técnicos sobre herramientas BPF |
| **Arthur Chiao** | [arthurchiao.art](https://arthurchiao.art/) | Traducciones y análisis profundos de papers y código eBPF |

### Blogs de empresas

| Blog | URL | Enfoque |
|------|-----|---------|
| **Isovalent Blog** | [isovalent.com/blog](https://isovalent.com/blog/) | La empresa detrás de Cilium — posts sobre networking, seguridad y observabilidad con eBPF |
| **Cloudflare Blog** | [blog.cloudflare.com](https://blog.cloudflare.com/) (tag: eBPF) | Uso de XDP en producción a escala masiva — DDoS mitigation, load balancing |
| **Meta Engineering** | [engineering.fb.com](https://engineering.fb.com/) | Katran, producción de eBPF a hiperescala |
| **LWN.net** | [lwn.net](https://lwn.net/) | Cobertura profunda de cambios al subsistema BPF en cada release del kernel |
| **Tigera Blog** | [tigera.io/blog](https://www.tigera.io/blog/) | eBPF en el contexto de Calico y networking de Kubernetes |

### Newsletters

| Newsletter | Descripción |
|-----------|-------------|
| **eBPF Updates** | Resumen periódico de novedades en el ecosistema eBPF — publicado en ebpf.io |
| **BPF & XDP Newsletter** | Curado por la comunidad Cilium — parches, releases, y artículos relevantes |
| **LWN Kernel Page** | No es específico de BPF, pero cubre todos los cambios significativos al subsistema |

---

## Libros complementarios

| Título | Autor | Año | Descripción |
|--------|-------|-----|-------------|
| *Learning eBPF* | Liz Rice | 2023 | Introducción accesible con ejemplos en C/Python. Buen complemento para ver otro estilo pedagógico. |
| *BPF Performance Tools* | Brendan Gregg | 2019 | La biblia del performance engineering con BPF. 700+ páginas de herramientas y metodología. Imprescindible. |
| *Linux Observability with BPF* | David Calavera, Lorenzo Fontana | 2019 | Enfocado en observabilidad. Algo datado pero sólido en conceptos fundamentales. |
| *Systems Performance* (2nd ed.) | Brendan Gregg | 2020 | No es sobre BPF específicamente pero el contexto de performance es crucial para entender el *por qué* de eBPF. |
| *Linux Kernel Programming* | Kaiwan N Billimoria | 2021 | Para entender las internals del kernel que eBPF instrumenta — modules, memory, scheduling. |

---

## Recursos de aprendizaje interactivo

| Recurso | URL | Descripción |
|---------|-----|-------------|
| **eBPF Labs** | [ebpf.io/labs](https://ebpf.io/labs) | Laboratorios interactivos del proyecto eBPF oficial |
| **Isovalent Labs** | [isovalent.com/labs](https://isovalent.com/labs/) | Labs gratuitos de Cilium y eBPF con entornos preconfigurados |
| **Lizrice/learning-ebpf** | [github.com/lizrice/learning-ebpf](https://github.com/lizrice/learning-ebpf) | Código fuente del libro Learning eBPF — buenos ejemplos para practicar |
| **xdp-tutorial** | [github.com/xdp-project/xdp-tutorial](https://github.com/xdp-project/xdp-tutorial) | Tutorial hands-on de XDP paso a paso — excelente para networking |

---

## Cómo mantenerse actualizado

El ecosistema eBPF evoluciona rápido. Cada release del kernel (cada ~2 meses) trae nuevas features. Recomendaciones:

1. **Sigue el changelog de BPF**: Cada merge window, LWN publica un resumen de los cambios al subsistema BPF.
2. **Suscríbete al eBPF Slack**: El canal #ebpf-general es donde se anuncian releases y se discuten problemas.
3. **Revisa bpf-next**: El árbol `bpf-next` en git muestra lo que viene en el próximo kernel.
4. **Asiste al eBPF Summit**: Las grabaciones son un excelente resumen anual del estado del arte.

```bash
# Ver la versión de tu kernel y features BPF disponibles
uname -r
bpftool feature probe kernel
```
