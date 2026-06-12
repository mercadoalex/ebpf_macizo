# Capítulo 11 — Contador XDP por Protocolo (Aya/Rust)

Este directorio contiene la implementación del mismo programa de referencia
(contador XDP por protocolo) usando **Aya** — el framework de eBPF para Rust.

## Estructura

```
rust/
├── Cargo.toml                        # Workspace con ambos crates
├── xdp-proto-counter/                # User space (Rust)
│   ├── Cargo.toml
│   └── src/main.rs
└── xdp-proto-counter-ebpf/           # Kernel space (Rust → BPF)
    ├── Cargo.toml
    └── src/main.rs
```

## Diferencias clave con la versión Go

| Aspecto | Go (cilium/ebpf) | Rust (Aya) |
|---------|-------------------|------------|
| Código BPF | C (compilado con clang) | Rust (compilado con rustc + BPF target) |
| Code gen | `bpf2go` genera structs Go | Aya genera bindings automáticamente |
| Compilación | `go generate` + `go build` | `cargo build` (todo junto) |
| Dependencias | Solo Go + clang/LLVM | Rust toolchain + bpf-linker |
| Curva de aprendizaje | Moderada | Alta (Rust + unsafe + no_std) |

## Compilación

```bash
# Prerequisitos:
# - Rust nightly (para BPF target)
# - bpf-linker: cargo install bpf-linker

# Compilar lado BPF (kernel):
cd xdp-proto-counter-ebpf
cargo +nightly build --target bpfeb-unknown-none -Z build-std=core

# Compilar user space:
cd ../xdp-proto-counter
cargo build --release

# Ejecutar:
sudo ./target/release/xdp-proto-counter --iface eth0
```

## ¿Por qué Aya?

Aya permite escribir **todo** (kernel + user space) en Rust:
- Seguridad de memoria en compile time (sin UAF, buffer overflows)
- Un solo lenguaje para todo el proyecto
- Sistema de tipos expresivo para modelar maps y programas
- Tooling excelente (cargo, rust-analyzer, clippy)

## ¿Cuándo NO usar Aya?

- Si tu equipo ya domina C + Go — no justifica la curva de aprendizaje
- Si necesitas máxima compatibilidad con herramientas existentes (bpftool, libbpf)
- Si trabajas en un entorno donde Rust no está aprobado
- Si el programa BPF es simple y no justifica la infraestructura adicional

## Nota importante

El código BPF en Aya se escribe en Rust con `#![no_std]` y compila a BPF
bytecode directamente. **No hay archivo .c** — es la única diferencia real
con los otros frameworks que todos usan C para el lado kernel.
