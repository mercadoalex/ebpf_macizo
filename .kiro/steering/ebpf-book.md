---
inclusion: always
---

# eBPF: Macizo y Conciso

## Sobre el proyecto

Este es un libro técnico en español sobre eBPF. No es un proyecto de software.
El título es "eBPF: Macizo y Conciso" con subtítulo "Desde tu primer hook hasta el sonido del metal contra el hueso del kernel".

## Reglas del libro

- Código BPF (kernel side): siempre en C (no hay alternativa)
- User space (principal): Go con cilium/ebpf — es el lenguaje de los ejemplos a lo largo de todo el libro
- Rust (Aya): se introduce como opción avanzada en el capítulo de frameworks (Nivel Ninja), no antes
- Python/BCC: solo se menciona brevemente como herramienta de scripting rápido, NO se usa en ejemplos
- Un solo lenguaje principal (Go) para no perder foco — el lector no salta entre stacks
- La terminología técnica de eBPF se mantiene en inglés con explicaciones en español
- El tono es directo, irreverente, punk pero honesto — sin relleno corporativo
- La audiencia son devs y gente técnica, ya sea novata o experta
- El libro va de novato a ninja en 3 niveles de progresión
