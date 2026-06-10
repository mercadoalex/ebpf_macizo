# Prefacio

> "No necesitas otro libro que te diga qué es el kernel. Necesitas uno que te enseñe a meterle código adentro."

---

## Por qué existe este libro

Porque no había ninguno en español. Punto.

El ecosistema de eBPF explotó en los últimos años — Cilium, Falco, Tetragon, Katran — y toda la documentación seria está en inglés. Los que hablamos español nos las arreglamos con docs oficiales, blog posts sueltos, y ese video de una conferencia que encontraste a las 3 AM. Pero no había un recurso que te llevara de cero a producción sin saltar entre 47 pestañas del navegador.

Este libro llena ese hueco. Sin relleno corporativo, sin rodeos académicos, sin "en futuras versiones se planea...". Código que compila, explicaciones que van al punto, y ejercicios que te obligan a ensuciarte las manos.

## Para quién es

Para ti si:

- Sabes moverte en una terminal Linux (cd, ls, grep — lo básico)
- Has escrito algo de código en C o Go (no necesitas ser experto, pero sí saber qué es un puntero)
- Quieres entender eBPF de verdad, no solo saber que existe
- Te interesa la observabilidad, el networking, la seguridad — o todo a la vez
- Preferirías leer algo directo en lugar de un textbook de 800 páginas con 600 de teoría

No importa si eres junior curioso o senior que quiere agregar eBPF a su arsenal. La progresión del libro está diseñada para los dos: arrancas desde el kernel y terminas escribiendo load balancers y sistemas de detección de intrusiones.

## Qué NO es este libro

- **No es un manual de referencia.** No vas a encontrar una lista exhaustiva de cada helper function con su firma. Para eso está `man bpf-helpers`. Aquí aprendes cuándo y por qué usar cada una.
- **No es un textbook académico.** No hay pruebas formales del modelo de verificación ni análisis de complejidad computacional del JIT. Hay código que corre y explicaciones que se entienden.
- **No es "eBPF para dummies".** Respetamos tu inteligencia. Si algo es complejo, lo explicamos con claridad pero sin infantilizarlo.
- **No es un tutorial de Python/BCC.** El código de este libro es C (lado BPF) + Go con cilium/ebpf (lado user space). Rust aparece en un capítulo como alternativa. Python se menciona y se deja ir.

## Qué te llevas

Al terminar este libro vas a poder:

1. Escribir programas eBPF desde cero y cargarlos al kernel
2. Usar maps, kprobes, tracepoints, XDP y TC para resolver problemas reales
3. Navegar el verifier sin querer tirar tu laptop por la ventana (o al menos, con menos frecuencia)
4. Diseñar soluciones de observabilidad y networking con eBPF en producción
5. Leer y entender código eBPF de proyectos open source serios
6. Contribuir al ecosistema si te da la gana

## El stack

Todo el libro usa un solo stack para que no pierdas foco:

- **Lado kernel (BPF):** C — no hay alternativa, es el lenguaje del kernel
- **Lado user space:** Go con [cilium/ebpf](https://github.com/cilium/ebpf) — limpio, tipado, bien mantenido
- **Comparación:** Rust con [Aya](https://github.com/aya-rs/aya) en el capítulo 11, para que conozcas la alternativa

No vas a estar saltando entre lenguajes cada dos capítulos. Un stack, un flujo, una forma de pensar.

## El repositorio de código

Todo el código de este libro vive en un repositorio complementario. Cada capítulo tiene su directorio con:

- Ejemplos completos y funcionales
- Esqueletos de ejercicios (para que los completes tú)
- Soluciones de referencia (para cuando te atoras)

```
code/
├── cap01-kernel/
├── cap02-historia/
├── cap03-laboratorio/    ← Tu primer programa compila aquí
├── cap04-hello-world/    ← Tu primer hook se adjunta aquí
├── ...
└── setup/                ← Vagrantfile + Dockerfile para el lab
```

## Cómo montar el laboratorio

eBPF es una tecnología del kernel **Linux**. No existe en macOS ni en Windows. Necesitas un entorno Linux real para ejecutar los programas de este libro.

Tienes varias opciones dependiendo de tu sistema:

- **Linux nativo** (kernel ≥ 5.15): Instala las herramientas y listo. La mejor experiencia.
- **macOS (Apple Silicon o Intel)**: Usa **Lima** (`brew install lima`) para correr una VM Linux nativa, o levanta una instancia en la nube (AWS, GCP, Hetzner — desde $0.01/hora).
- **Windows**: WSL2 con kernel reciente, o instancia en la nube.

> ☠️ Ni VirtualBox ni Docker Desktop te sirven para ejecutar programas BPF en Mac. VirtualBox no corre en Apple Silicon, y Docker Desktop usa una VM interna con kernel limitado. Necesitas una VM Linux real (Lima) o una máquina Linux de verdad (nube).

Ejecuta `code/setup/check-env.sh` para verificar que tienes todo listo antes de arrancar. Los detalles completos están en el Capítulo 3.

## Cómo leer este libro

Lee en orden. No es broma. Cada capítulo construye sobre el anterior. Si saltas al capítulo de XDP sin entender maps, vas a sufrir innecesariamente.

El libro tiene tres niveles:

- **Novato (Caps 1-5):** Entiendes el kernel, eBPF, y escribes tu primer programa
- **Intermedio (Caps 6-13):** Dominas maps, verifier, helpers, networking, y frameworks
- **Ninja (Caps 14-18):** Tail calls, CO-RE, XDP en producción, seguridad, optimización

Entre cada nivel hay un capítulo puente que consolida lo aprendido y te prepara para lo que viene.

---

Suficiente introducción. Pasemos al mapa de progresión y luego — a escribir código.
