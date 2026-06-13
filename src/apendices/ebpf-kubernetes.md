# Apéndice F: eBPF en Kubernetes — Guía de navegación

> "Kubernetes sin eBPF es como un auto sin espejos retrovisores — funciona, pero no ves un carajo de lo que pasa."

---

## Por qué eBPF domina el ecosistema Kubernetes

Si trabajas con Kubernetes en 2024+, ya estás usando eBPF aunque no lo sepas. Los problemas que K8s siempre tuvo — networking lento, observabilidad ciega, seguridad reactiva — son exactamente los que eBPF resuelve:

| Problema K8s | Solución clásica | Solución eBPF |
|--------------|-----------------|---------------|
| Networking (CNI, services) | kube-proxy + iptables (O(N) rules) | Cilium: XDP/TC con maps O(1) |
| Service mesh | Sidecars (Envoy por pod) | Cilium Service Mesh: kernel-level, sin sidecar |
| Observabilidad | SDKs + agents + sidecars | Pixie/Hubble: uprobes sin instrumentación |
| Runtime security | Escaneo de imágenes (estático) | Falco/Tetragon: detección + enforcement en runtime |
| Network policies | CNI plugins con iptables | Cilium: BPF-native policies |

La tendencia es clara: el data plane de Kubernetes se está moviendo al kernel vía eBPF.

---

## El patrón: DaemonSet con acceso al host

Cualquier herramienta eBPF en Kubernetes sigue el mismo patrón de deployment:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ebpf-agent
spec:
  selector:
    matchLabels:
      app: ebpf-agent
  template:
    spec:
      hostPID: true       # Ver procesos del host
      hostNetwork: true   # Ver tráfico del host
      containers:
      - name: agent
        image: tu-agent:latest
        securityContext:
          privileged: true  # O capabilities específicas
        volumeMounts:
        - name: bpf-fs
          mountPath: /sys/fs/bpf
        - name: debug-fs
          mountPath: /sys/kernel/debug
      volumes:
      - name: bpf-fs
        hostPath:
          path: /sys/fs/bpf
      - name: debug-fs
        hostPath:
          path: /sys/kernel/debug
```

**Las piezas clave:**

- **DaemonSet**: un pod por nodo — cada nodo necesita su propio agent eBPF
- **hostPID: true**: permite ver todos los procesos del nodo, no solo los del pod
- **hostNetwork: true**: permite interceptar tráfico de red del nodo
- **privileged** (o caps específicas): necesario para cargar programas BPF en el kernel
- **/sys/fs/bpf**: el filesystem donde se pinean maps y programas BPF
- **/sys/kernel/debug**: acceso a tracepoints y debugfs

### Capabilities mínimas (sin privileged)

En producción, evita `privileged: true`. Usa capabilities específicas:

```yaml
securityContext:
  capabilities:
    add:
    - BPF            # Cargar programas BPF
    - PERFMON        # Tracepoints, kprobes
    - NET_ADMIN      # XDP, TC
    - SYS_RESOURCE   # Memlock (kernels viejos)
```

Si necesitas LSM hooks (enforcement), agrega `MAC_ADMIN`. Si solo haces observabilidad, `BPF` + `PERFMON` suele bastar.

---

## Cilium — Networking eBPF-native para K8s

**Qué reemplaza**: kube-proxy, CNI plugin (Calico/Flannel), y opcionalmente el service mesh (Istio/Linkerd).

**Cómo funciona**:
- Se deploya como DaemonSet con un agent por nodo
- Reemplaza las reglas iptables de kube-proxy con programas XDP/TC
- Implementa Network Policies con BPF maps (lookup O(1) vs O(N) iptables chains)
- Ofrece Hubble: observabilidad de red basada en eBPF

**Impacto medido**:
- Escala a 50,000+ services sin degradación (iptables colapsa a ~10,000)
- Latencia de service routing: ~5µs (vs ~50µs con iptables)
- Network policies sin overhead de CPU adicional

**Relación con el libro**: Lo que aprendiste en el Capítulo 10 (XDP/TC), Capítulo 14 (tail calls), y Capítulo 16 (XDP en producción) es exactamente lo que Cilium implementa internamente.

---

## Tetragon — Runtime security con enforcement

**Qué resuelve**: Detectar y bloquear amenazas en runtime dentro de pods, con contexto de Kubernetes (pod name, namespace, labels).

**Cómo funciona**:
- DaemonSet que carga programas BPF (LSM + kprobes + tracepoints)
- TracingPolicies en CRDs de K8s definen qué monitorear
- Entiende el modelo de pods: sabe qué proceso pertenece a qué pod
- Puede matar procesos (SIGKILL) o denegar operaciones (LSM)

**Ejemplo — bloquear escritura a /etc/passwd desde cualquier pod**:
```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: block-passwd-write
spec:
  kprobes:
  - call: "security_file_open"
    syscall: false
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "/etc/passwd"
      matchActions:
      - action: Sigkill
```

**Relación con el libro**: Es la versión production-grade de lo que construiste en el Capítulo 17 (LSM hooks + syscall monitoring).

---

## Pixie / Hubble — Observabilidad sin instrumentación

**Pixie** (ahora parte de New Relic):
- Captura métricas HTTP, gRPC, SQL, Redis usando uprobes — sin SDKs, sin sidecars
- Almacena datos in-cluster (privacy by design)
- Flamegraphs de CPU, network flows, request latencies — todo automático

**Hubble** (parte de Cilium):
- Observabilidad de red L3/L4/L7 basada en los datos que Cilium ya captura
- Flows entre services, DNS queries, HTTP requests
- Se integra con Grafana para dashboards

**Relación con el libro**: El patrón de observabilidad del Capítulo 17 (ring buffers + maps per-CPU + consumer) es la base. Pixie agrega uprobes (Capítulo 9) para visibilidad a nivel de aplicación.

---

## Falco — Detección de amenazas con reglas declarativas

**Qué resuelve**: Detectar comportamiento anómalo en containers en runtime.

**Cómo funciona en K8s**:
- DaemonSet con driver eBPF (reemplazó el kernel module original)
- Reglas YAML definen qué es sospechoso
- Se integra con alertmanager, Slack, PagerDuty
- Solo detección — no bloquea (para enforcement, usa Tetragon)

**Cuándo usar Falco vs Tetragon**:
- Falco: quieres un motor de reglas maduro con 200+ reglas comunitarias, solo detección
- Tetragon: necesitas enforcement inline + detección, estás en el ecosistema Cilium

---

## Mapa de decisión: ¿qué herramienta para qué problema?

| Necesidad | Herramienta | Nivel de esfuerzo |
|-----------|-------------|-------------------|
| Reemplazar kube-proxy | Cilium | Medio (CNI swap) |
| Network policies avanzadas | Cilium | Bajo (CRDs) |
| Observabilidad de red | Hubble | Bajo (viene con Cilium) |
| Observabilidad de aplicación | Pixie | Bajo (DaemonSet) |
| Detección de amenazas | Falco | Bajo (Helm chart) |
| Enforcement de seguridad | Tetragon | Medio (TracingPolicies) |
| Service mesh sin sidecars | Cilium Service Mesh | Medio-Alto |
| Custom eBPF en K8s | Tu propio agent 🤘 | Alto (lo que aprendiste aquí) |

---

## Construir tu propio agent eBPF para K8s

Después de leer este libro, tienes las herramientas para escribir un agent eBPF custom. Lo que necesitas agregar para el contexto de K8s:

1. **Pod metadata**: mapear PID → pod name/namespace. Técnica: leer cgroups del proceso y correlacionar con la API de K8s.
2. **DaemonSet packaging**: container con tu binario Go + programas BPF compilados.
3. **Configuración vía CRDs** (opcional): definir políticas como objetos de Kubernetes.
4. **Exportación de datos**: Prometheus metrics, OTLP traces, o JSON logs a stdout (para que un log collector los recoja).

El patrón ya lo conoces del Capítulo 17: programas BPF que emiten eventos → ring buffer → consumer Go que clasifica y exporta. En K8s, solo agregas el contexto de pod/namespace.

---

## Recursos

- 💻 [Cilium — eBPF-based Networking, Security, and Observability](https://cilium.io/)
- 💻 [Tetragon — eBPF-based Security Observability and Runtime Enforcement](https://tetragon.io/)
- 💻 [Falco — Cloud-native Runtime Security](https://falco.org/)
- 💻 [Pixie — Instant Kubernetes Observability](https://px.dev/)
- 💻 [Hubble — Network Observability for Kubernetes](https://github.com/cilium/hubble)
- 📖 [Isovalent Labs — Hands-on eBPF + K8s tutorials](https://isovalent.com/labs/)
