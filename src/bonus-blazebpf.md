# Bonus: BlazeBPF — Practica eBPF en el navegador

> "Leer está bien. Escribir código está mejor. Escribir código y ver si pasa el verifier en 2 segundos — eso es otro nivel."

---

## Qué es BlazeBPF

[BlazeBPF](https://blazebpf.com/) es una plataforma interactiva para aprender y practicar eBPF directamente desde el navegador. No necesitas una VM, no necesitas un kernel Linux corriendo en tu máquina, no necesitas configurar nada. Abres la página, escribes código eBPF en C, y lo compilas en tiempo real.

La plataforma incluye:

- **Compilador en línea** — Escribe programas eBPF, compílalos, revisa el bytecode generado, y verifica errores de sintaxis. Sin instalar clang, sin configurar headers.
- **Cheat Sheet interactivo** — Referencia de helper functions, patrones de código, tipos de maps, y más. Con un click insertas el snippet en tu código.
- **Challenges** — Retos para probar tus habilidades con eBPF. Desde lo básico hasta problemas avanzados.
- **Labs guiados** — Ejercicios paso a paso que te llevan desde un programa vacío hasta uno funcional.
- **Fill-in-the-blanks** — Ejercicios donde completas código parcial. Similar a los esqueletos de este libro, pero con feedback instantáneo.

## Por qué te sirve después de este libro

Este libro te dio la base sólida: entiendes el kernel, el modelo de ejecución, el verifier, los maps, los hooks. Sabes escribir programas reales en C y cargarlos con Go.

BlazeBPF te da el espacio para **iterar rápido**. Quieres probar una idea, verificar si una combinación de helpers compila, o practicar antes de montar tu VM — lo haces en segundos. Es el complemento perfecto: el libro te da profundidad, la plataforma te da velocidad de experimentación.

## Tu cupón: 1 año de suscripción + Badge digital

Como lector de "eBPF: Macizo y Conciso", tienes acceso a una suscripción de 1 año en BlazeBPF y un **badge digital verificable** que puedes compartir en LinkedIn y redes sociales.

**Cómo reclamarlo:**

1. Envía tu evidencia de compra de este libro (screenshot del recibo, confirmación de compra, o foto del libro físico) a: **like@blazebpf.com**
2. En el asunto del correo pon: `Cupón — eBPF Macizo y Conciso`
3. Recibirás tu código de activación en un plazo de 48 horas

Sin trucos, sin letras chicas. Compraste el libro, tienes acceso a la plataforma.

## Tu badge: "eBPF Macizo y Conciso — Reader"

Al activar tu cupón en BlazeBPF, recibes automáticamente el badge **"eBPF: Macizo y Conciso — Reader"**. Es un badge digital verificable que puedes:

- Compartir en **LinkedIn** como credencial profesional
- Agregar a tu perfil de GitHub o portfolio
- Publicar en redes con el hashtag **#eBPFMacizo**

El badge demuestra que invertiste en aprender eBPF en serio — no que leíste un artículo de 5 minutos. En un ecosistema donde pocas personas dominan esta tecnología, eso tiene peso.

### Badges de nivel (progresión en BlazeBPF)

Además del badge de lector, BlazeBPF genera badges por nivel conforme completas challenges y labs en la plataforma:

| Badge | Cómo se obtiene |
|-------|----------------|
| 🟢 **Novato eBPF** | Completa los challenges de nivel básico (hello world, maps, helpers) |
| 🟡 **Intermedio eBPF** | Completa labs de XDP, tracepoints, ring buffers |
| 🔴 **Ninja eBPF** | Completa challenges avanzados (tail calls, CO-RE, LSM, networking) |

Cada badge es compartible y verificable. Tu progresión queda registrada.

---

Nos vemos en el código. 🤘
