# Repositorio de Código Complementario

> Código fuente de todos los ejemplos y ejercicios del libro **"eBPF: Macizo y Conciso"**.

## Estructura

```
code/
├── setup/                         # Entorno de desarrollo (VM, Docker, verificación)
├── cap01-kernel/                  # Cap 1: El kernel no muerde
│   └── ejercicio/                 #   Solo ejercicios de terminal (strace)
├── cap02-historia/                # Cap 2: Historia de eBPF
│   └── ejercicio/                 #   Solo ejercicios de terminal (bpftool)
├── cap03-laboratorio/             # Cap 3: Tu laboratorio de guerra
│   ├── bpf/                       #   Código BPF en C (programa mínimo)
│   ├── go/                        #   User space en Go (cilium/ebpf)
│   └── ejercicio/
│       ├── esqueleto/             #   Código parcial para que el lector complete
│       └── solucion/              #   Solución de referencia completa
├── cap04-hello-world/             # Cap 4: Hello World — Tu primer hook
│   ├── bpf/
│   ├── go/
│   └── ejercicio/{esqueleto,solucion}/
├── cap05-puente/                  # Cap 5: De novato a intermedio
│   └── ejercicio/                 #   Auto-evaluación (sin código BPF)
├── cap06-maps/                    # Cap 6: Maps — La memoria compartida
│   ├── bpf/
│   ├── go/
│   └── ejercicio/{esqueleto,solucion}/
├── cap07-verifier/                # Cap 7: El Verifier
│   ├── bpf/
│   ├── go/
│   └── ejercicio/{esqueleto,solucion}/
├── cap08-helpers/                 # Cap 8: Helper functions
│   ├── bpf/
│   ├── go/
│   └── ejercicio/{esqueleto,solucion}/
├── cap09-kprobes-tracepoints/     # Cap 9: Kprobes y Tracepoints
│   ├── bpf/
│   ├── go/
│   └── ejercicio/{esqueleto,solucion}/
├── cap10-xdp-tc/                  # Cap 10: XDP y TC
│   ├── bpf/
│   ├── go/
│   └── ejercicio/{esqueleto,solucion}/
├── cap11-frameworks/              # Cap 11: Frameworks en acción
│   ├── bpf/                       #   Código BPF compartido (C)
│   ├── go/                        #   Implementación principal (cilium/ebpf)
│   ├── rust/                      #   Implementación comparativa (Aya)
│   └── ejercicio/{esqueleto,solucion}/
├── cap12-user-kernel/             # Cap 12: User space ↔ Kernel
│   ├── bpf/
│   ├── go/
│   └── ejercicio/{esqueleto,solucion}/
├── cap13-puente-ninja/            # Cap 13: De intermedio a ninja
│   ├── bpf/
│   ├── go/
│   └── ejercicio/{esqueleto,solucion}/
├── cap14-tail-calls/              # Cap 14: Tail calls y composición
│   ├── bpf/
│   ├── go/
│   └── ejercicio/{esqueleto,solucion}/
├── cap15-btf-core/                # Cap 15: BTF y CO-RE
│   ├── bpf/
│   ├── go/
│   └── ejercicio/{esqueleto,solucion}/
├── cap16-networking-avanzado/     # Cap 16: Networking avanzado
│   ├── bpf/
│   ├── go/
│   └── ejercicio/{esqueleto,solucion}/
├── cap17-seguridad-observabilidad/ # Cap 17: Seguridad y observabilidad
│   ├── bpf/
│   ├── go/
│   └── ejercicio/{esqueleto,solucion}/
└── cap18-optimizacion/            # Cap 18: Optimización y contribuidor
    ├── bpf/
    ├── go/
    └── ejercicio/{esqueleto,solucion}/
```

## Convenciones

### Lenguajes

| Ubicación | Lenguaje | Propósito |
|-----------|----------|-----------|
| `bpf/` | C | Programas que corren en el kernel (BPF bytecode) |
| `go/` | Go (cilium/ebpf) | Programas de user space — el stack principal del libro |
| `rust/` | Rust (Aya) | Solo en capítulo 11, como comparación de frameworks |

### Nomenclatura de archivos

- Programas BPF: `nombre.bpf.c` (ej: `hello.bpf.c`, `counter.bpf.c`)
- Headers BPF generados: `nombre.bpf.h` (auto-generados por bpf2go)
- Loaders en Go: `main.go` con su `go.mod`
- Makefiles: un `Makefile` por capítulo cuando aplica

### Ejercicios

- **`ejercicio/esqueleto/`** — Código parcial con `// TODO:` donde el lector debe completar la lógica. Compila pero no funciona hasta que el lector implemente las partes faltantes.
- **`ejercicio/solucion/`** — Implementación de referencia completa y funcional. El lector debería intentar resolver el ejercicio antes de mirar aquí.

### Capítulos sin código BPF

Los capítulos 1, 2 y 5 son teóricos o de transición. Sus directorios `ejercicio/` contienen scripts de shell o instrucciones en texto para ejercicios basados en comandos de terminal (strace, bpftool, etc).

## Cómo usar este repositorio

### 1. Configura tu entorno

```bash
cd code/setup/

# Opción A: Vagrant (recomendado — entorno completo con kernel 6.1)
vagrant up
vagrant ssh

# Opción B: Docker (más ligero, para compilación)
docker build -t ebpf-lab .
docker run -it --privileged ebpf-lab

# Verificar que todo está en orden
./check-env.sh
```

### 2. Navega al capítulo que estés leyendo

```bash
cd code/cap04-hello-world/
```

### 3. Compila y ejecuta los ejemplos

```bash
# Compilar el programa BPF
cd bpf/
make

# Ejecutar el loader en Go
cd ../go/
go generate ./...
go build -o loader .
sudo ./loader
```

### 4. Intenta el ejercicio

```bash
# Empieza con el esqueleto
cd ejercicio/esqueleto/
# Lee los comentarios TODO y completa el código

# Cuando te atasques, consulta la solución
cd ../solucion/
```

## Requisitos del entorno

- **Kernel Linux** >= 5.15 (recomendado 6.1 LTS)
- **clang/LLVM** >= 14
- **Go** >= 1.21
- **bpftool** (incluido en linux-tools)
- **Rust** >= 1.70 (solo para capítulo 11)

Para más detalles, consulta [`setup/README.md`](setup/README.md).

## Licencia

El código de este repositorio acompaña al libro "eBPF: Macizo y Conciso" y se distribuye bajo los mismos términos que el libro. Puedes usarlo para aprendizaje personal y profesional.
