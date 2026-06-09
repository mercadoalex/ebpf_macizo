# Implementation Plan: eBPF — Macizo y Conciso

## Overview

Este plan cubre la escritura completa del libro "eBPF: Macizo y Conciso" usando mdBook como formato de autoría. Las tareas están organizadas en: setup del proyecto, escritura de capítulos por nivel, creación de ejercicios y código complementario, apéndices, y proceso editorial. Todo el contenido se escribe en español con terminología técnica en inglés.

## Tasks

- [x] 1. Setup del proyecto mdBook y repositorio
  - [x] 1.1 Crear estructura base del proyecto mdBook
    - Crear `book.toml` con configuración de mdBook (título, autores, plugins mermaid y pdf)
    - Crear `src/SUMMARY.md` con la tabla de contenidos completa de los 18 capítulos y apéndices
    - Crear la estructura de directorios: `src/parte-1-novato/`, `src/parte-2-intermedio/`, `src/parte-3-ninja/`, `src/apendices/`
    - Crear archivos `.md` vacíos con el título de cada capítulo como placeholder
    - _Requirements: 1.1, 8.1_

  - [x] 1.2 Configurar theme y CSS personalizado
    - Crear `theme/custom.css` con estilos para los recuadros pedagógicos (🔥 Advertencia, 💡 Analogía, ⚙️ Nota técnica, 📜 Historia, ☠️ Cuidado)
    - Configurar tipografía y colores acordes al tono punk/directo del libro
    - Verificar que mdBook renderiza correctamente los recuadros con `mdbook serve`
    - _Requirements: 7.2, 7.3_

  - [x] 1.3 Crear estructura del repositorio de código complementario
    - Crear directorios `code/capNN-nombre/` para cada capítulo (01-18)
    - Crear subdirectorios `bpf/` (código kernel en C) y `go/` (user space con cilium/ebpf) para capítulos con código
    - Solo para capítulo 11: crear también `rust/` (comparación con Aya)
    - Crear subdirectorios `ejercicio/esqueleto/` y `ejercicio/solucion/` para ejercicios
    - Crear `code/README.md` con índice y convenciones del repo
    - _Requirements: 5.5, 8.3_

  - [x] 1.4 Configurar entorno de desarrollo para lectores
    - Crear `code/setup/Vagrantfile` con VM Ubuntu + kernel 6.1 LTS + herramientas BPF instaladas
    - Crear `code/setup/Dockerfile` como alternativa ligera para compilación
    - Crear `code/setup/check-env.sh` que verifique: versión de kernel, clang/LLVM, bpftool, Go
    - Documentar instrucciones de uso en `code/setup/README.md`
    - _Requirements: 2.2, 5.6_

  - [x] 1.5 Configurar CI para validación de código
    - Crear pipeline de CI (GitHub Actions) que compile todos los programas BPF (C con clang) y loaders en Go (go build)
    - Para capítulo 11: incluir también compilación de Rust (cargo build)
    - Agregar job que ejecute `BPF_PROG_TEST_RUN` en una VM con kernel adecuado para verificar que los programas BPF pasan el verifier
    - Agregar verificación de que los Makefiles y scripts producen los outputs documentados
    - _Requirements: 5.5, 5.6_

- [x] 2. Material frontal y mapa de progresión
  - [x] 2.1 Escribir prefacio y material introductorio
    - Escribir `src/prefacio.md` — tono directo, por qué existe este libro, para quién es, qué NO es
    - Crear `src/mapa-progresion.md` con diagrama Mermaid del mapa visual de progresión (18 capítulos, dependencias, niveles)
    - _Requirements: 1.2, 1.4_

- [~] 3. Checkpoint — Verificar setup
  - Asegurar que `mdbook build` compila sin errores, `mdbook serve` renderiza el CSS custom correctamente, y la CI pasa en verde. Preguntar al usuario si hay dudas.

- [ ] 4. Escribir Parte I — Nivel Novato (Capítulos 1-5)
  - [x] 4.1 Escribir Capítulo 1: El kernel no muerde
    - Escribir las 4 secciones: qué es el kernel, user space vs kernel space, system calls, por qué importa
    - Incluir diagrama Mermaid de arquitectura del kernel
    - Incluir analogía (sistema nervioso) y advertencia (no recompilar kernel)
    - Escribir ejercicio paso a paso (strace para observar syscalls)
    - Incluir lista de términos nuevos, objetivos, prerrequisitos, resumen y recursos
    - _Requirements: 2.1, 2.3, 2.4, 7.1, 7.2, 7.3, 7.4_

  - [x] 4.2 Escribir Capítulo 2: eBPF — La historia del parche que se comió al kernel
    - Escribir las 4 secciones: BPF a eBPF, modelo de ejecución, hooks y attach points, ecosistema 2024+
    - Incluir diagrama de línea de tiempo BPF→eBPF y diagrama del modelo de ejecución
    - Incluir analogía (plugins del kernel) y advertencia (eBPF ≠ módulo del kernel)
    - Escribir ejercicio paso a paso (bpftool prog list)
    - _Requirements: 2.1, 2.3, 7.1, 7.2, 7.3, 7.4_

  - [~] 4.3 Escribir Capítulo 3: Tu laboratorio de guerra
    - Escribir las 5 secciones: kernel mínimo, toolchain, panorama de frameworks (C/Go/Rust), primer "it works" con Go, contenedores y VMs
    - Incluir diagrama del toolchain (código → compilación → bytecode → kernel)
    - Incluir advertencia (kernel < 5.x)
    - Escribir ejercicio paso a paso (configurar entorno y ejecutar esqueleto en Go con cilium/ebpf)
    - _Requirements: 2.1, 2.2, 2.4, 5.6, 7.1_

  - [~] 4.4 Crear código de ejemplos y ejercicio del Capítulo 3
    - Escribir `code/cap03-laboratorio/bpf/minimal.bpf.c` y `Makefile`
    - Escribir `code/cap03-laboratorio/go/main.go` y `go.mod` (cilium/ebpf)
    - Verificar que compila correctamente en el entorno de setup
    - _Requirements: 2.2, 5.5_

  - [~] 4.5 Escribir Capítulo 4: Hello World — Tu primer hook
    - Escribir las 4 secciones: programa más simple, lado kernel (C), lado user space (Go con cilium/ebpf), anatomía de carga
    - Incluir diagrama de secuencia (open → carga → verificación → attach → output)
    - Incluir analogía (micrófono en habitación) y advertencia (trace_printk no es para prod)
    - Escribir ejercicio completo (Hello World que imprime PID y nombre en execve)
    - Definir criterio de éxito: carga sin errores, adjunta a sys_enter_execve, output en trace_pipe
    - _Requirements: 2.1, 2.4, 2.5, 2.7, 7.1, 7.2, 7.3, 7.4_

  - [~] 4.6 Crear código de ejemplos y ejercicio del Capítulo 4
    - Escribir Hello World: `hello.bpf.c` (programa BPF en C)
    - Escribir loader en Go (cilium/ebpf): `main.go` + `go.mod`
    - Escribir ejercicio (execve tracer): BPF en C + loader en Go, esqueleto y solución
    - Verificar que compila y produce output correcto
    - _Requirements: 2.5, 2.7, 5.2, 5.5_

  - [~] 4.7 Escribir Capítulo 5: De novato a intermedio — El puente
    - Escribir las 3 secciones: lo que ya sabes, lo que no puedes hacer, mapa de lo que viene
    - Incluir diagrama de conceptos aprendidos vs por aprender
    - Escribir ejercicio de auto-evaluación (checklist de conceptos)
    - _Requirements: 1.2, 1.5, 8.5_

  - [x] 4.8 Escribir introducciones de Parte I
    - Escribir `src/parte-1-novato/intro.md` con prerrequisitos verificables, objetivos de aprendizaje, resumen de capítulos
    - Declarar prerrequisitos del lector: línea de comandos Linux + programación básica en C
    - _Requirements: 1.2, 2.4, 2.6_

- [~] 5. Checkpoint — Parte I completa
  - Verificar que todos los capítulos 1-5 tienen los elementos de la plantilla (términos, objetivos, prerrequisitos, diagrama, advertencia, ejercicio, resumen, recursos). Verificar que el código del Cap 3 y Cap 4 compila. Preguntar al usuario si hay dudas.

- [ ] 6. Escribir Parte II — Nivel Intermedio (Capítulos 6-13)
  - [~] 6.1 Escribir Capítulo 6: Maps — La memoria compartida
    - Escribir las 6 secciones: qué son maps, hash maps, array/per-CPU, ring buffer, CRUD, patrones de uso
    - Incluir diagramas (memoria de un map, flujo ring buffer)
    - Incluir analogía (pizarras compartidas) y advertencia (memory leak sin cleanup)
    - Escribir ejercicio intermedio: contador de syscalls por proceso con hash map (esqueleto + criterios)
    - _Requirements: 3.1, 3.4, 3.5, 7.1, 7.2, 7.3_

  - [~] 6.2 Crear código del Capítulo 6
    - Escribir ejemplos de cada tipo de map: BPF en C + loader/consumer en Go
    - Crear esqueleto del ejercicio (`code/cap06-maps/ejercicio/esqueleto/`) con la estructura base y TODOs
    - Crear solución de referencia (`code/cap06-maps/ejercicio/solucion/`) completa y compilable
    - _Requirements: 3.2, 5.3, 5.5_

  - [~] 6.3 Escribir Capítulo 7: El Verifier — Tu enemigo favorito
    - Escribir las 5 secciones: por qué existe, reglas, errores comunes, trucos, falsos positivos
    - Incluir diagramas (flujo de decisión, árbol de estados)
    - Incluir analogía (guardia paranoico) y advertencia (loops sin bound)
    - Escribir ejercicio intermedio: diagnosticar y corregir 3 errores del verifier (pistas sin solución)
    - _Requirements: 3.1, 3.3, 3.5, 7.1, 7.3_

  - [~] 6.4 Crear código del Capítulo 7
    - Escribir programas rotos (`code/cap07-verifier/ejemplos/broken/`) que fallan el verifier de 3 formas distintas
    - Escribir versiones corregidas (`code/cap07-verifier/ejemplos/fixed/`)
    - Crear esqueleto y solución del ejercicio
    - _Requirements: 3.3, 5.3, 5.5_

  - [~] 6.5 Escribir Capítulo 8: Helper functions — El arsenal
    - Escribir las 6 secciones: qué son helpers, de contexto, de maps, de networking, de output, matriz de compatibilidad
    - Incluir diagrama (matriz helpers × tipos de programa)
    - Incluir advertencia (disponibilidad por tipo de programa)
    - Escribir ejercicio intermedio: medir latencia de syscalls con bpf_ktime_get_ns (esqueleto)
    - _Requirements: 3.1, 3.4, 3.5, 7.1_

  - [~] 6.6 Crear código del Capítulo 8
    - Escribir ejemplos de uso de helpers principales: BPF en C + loader en Go
    - Crear esqueleto del ejercicio de latencia y solución de referencia
    - _Requirements: 3.2, 5.3, 5.5_

  - [~] 6.7 Escribir Capítulo 9: Kprobes y Tracepoints — Escuchando al kernel
    - Escribir las 5 secciones: kprobes, kretprobes, tracepoints, fentry/fexit, patrones prácticos
    - Incluir diagramas (kprobe vs kretprobe, flujo de tracepoint)
    - Incluir analogía (breakpoints del kernel) y advertencia (kprobes inestables entre versiones)
    - Escribir ejercicio intermedio: tracer de filesystem operations (esqueleto + criterios)
    - _Requirements: 3.1, 3.3, 3.5, 7.1, 7.2, 7.3_

  - [~] 6.8 Crear código del Capítulo 9
    - Escribir ejemplos de kprobes/tracepoints: BPF en C + loader en Go
    - Crear esqueleto del filesystem tracer y solución de referencia
    - _Requirements: 3.2, 5.3, 5.5_

  - [~] 6.9 Escribir Capítulo 10: XDP y TC — Networking a velocidad del kernel
    - Escribir las 5 secciones: XDP, acciones XDP, TC, parseo de paquetes, XDP vs TC
    - Incluir diagramas (posición en network stack, flujo con decisiones XDP)
    - Incluir analogía (portero de discoteca) y advertencia (pointer fuera del paquete)
    - Escribir ejercicio intermedio: firewall XDP básico (esqueleto del parseo, lector implementa lógica)
    - _Requirements: 3.1, 3.3, 3.5, 7.1, 7.2, 7.3_

  - [~] 6.10 Crear código del Capítulo 10
    - Escribir ejemplos XDP y TC: BPF en C + loader en Go
    - Crear esqueleto del firewall XDP y solución de referencia
    - _Requirements: 3.2, 5.3, 5.5_

  - [~] 6.11 Escribir Capítulo 11: Frameworks en acción — cilium/ebpf, Aya, y el ecosistema
    - Escribir las 6 secciones: por qué Go es el principal, programa de referencia en Go, mismo programa en Aya (Rust), mención breve de libbpf/BCC, comparativa, guía de decisión
    - Incluir diagramas de arquitectura de cilium/ebpf y Aya
    - Incluir advertencia (no hay framework "mejor")
    - Escribir ejercicio intermedio: extender programa de referencia en Go (esqueleto + criterios)
    - _Requirements: 3.1, 3.2, 3.5, 7.1_

  - [~] 6.12 Crear código del Capítulo 11
    - Escribir el programa de referencia (contador XDP por protocolo) en Go (cilium/ebpf) — implementación principal
    - Escribir el mismo programa en Rust (Aya) — como comparación
    - Crear esqueleto y solución del ejercicio de extensión (conteo por IP destino) en Go
    - _Requirements: 3.2, 5.3, 5.5_

  - [~] 6.13 Escribir Capítulo 12: User space ↔ Kernel — La conversación
    - Escribir las 5 secciones: el problema, perf events, ring buffer, maps compartidos, patrones de diseño
    - Incluir diagramas (perf vs ring buffer, flujo end-to-end)
    - Incluir analogía (tubos neumáticos) y advertencia (back-pressure)
    - Escribir ejercicio intermedio: event logger con ring buffer (esqueleto BPF, lector implementa consumer)
    - _Requirements: 3.1, 3.4, 3.5, 7.1, 7.2, 7.3_

  - [~] 6.14 Crear código del Capítulo 12
    - Escribir ejemplos de perf events y ring buffer: BPF en C + consumer en Go
    - Crear esqueleto del event logger y solución de referencia
    - _Requirements: 3.2, 5.3, 5.5_

  - [~] 6.15 Escribir Capítulo 13: De intermedio a ninja — El puente
    - Escribir las 3 secciones: lo que ya dominas, las paredes que vas a golpear, el siguiente nivel
    - Incluir diagrama (mapa de conceptos completo hasta este punto)
    - Escribir ejercicio integrador: tool de observabilidad (kprobes + maps + ring buffer + consumer)
    - _Requirements: 1.2, 1.5, 3.4, 8.5_

  - [~] 6.16 Crear código del ejercicio integrador del Capítulo 13
    - Crear esqueleto del mini-proyecto integrador: BPF en C + Go para user space
    - Crear solución de referencia completa en Go (cilium/ebpf)
    - _Requirements: 5.3, 5.5_

  - [~] 6.17 Escribir introducción de Parte II
    - Escribir `src/parte-2-intermedio/intro.md` con prerrequisitos (completar Nivel Novato), objetivos, resumen de capítulos
    - _Requirements: 1.2, 3.4_

- [~] 7. Checkpoint — Parte II completa
  - Verificar todos los capítulos 6-13 con la checklist de completitud. Verificar que todo el código de ejemplos y ejercicios compila. Verificar progresión de terminología (no se usa término antes de introducirlo). Preguntar al usuario si hay dudas.

- [ ] 8. Escribir Parte III — Nivel Ninja (Capítulos 14-18)
  - [~] 8.1 Escribir Capítulo 14: Tail calls, function calls y composición
    - Escribir las 5 secciones: complejidad, tail calls, BPF-to-BPF calls, combinación, limitaciones
    - Incluir diagramas (pipeline tail calls, comparación tail call vs function call)
    - Incluir advertencia (límite de 33 tail calls) y análisis de limitaciones/trade-offs
    - Escribir ejercicio ninja: classifier multi-protocolo con tail calls (solo requisitos y restricciones)
    - Integrar conceptos: Maps (Cap 6) y Verifier (Cap 7)
    - _Requirements: 4.1, 4.3, 4.5, 7.1, 7.3_

  - [~] 8.2 Crear código del Capítulo 14
    - Escribir ejemplos de tail calls y function calls: BPF en C + loader en Go
    - Crear solución de referencia del classifier en Go
    - _Requirements: 4.6, 5.4, 5.5_

  - [~] 8.3 Escribir Capítulo 15: BTF y CO-RE — Escribe una vez, corre en todos lados
    - Escribir las 6 secciones: infierno de versiones, BTF, CO-RE, vmlinux.h, relocations, limitaciones
    - Incluir diagramas (con vs sin CO-RE, flujo de relocations)
    - Incluir advertencia (BTF requiere kernel con CONFIG_DEBUG_INFO_BTF)
    - Analizar limitaciones (2+), trade-offs, y alternativa sin eBPF (SystemTap)
    - Escribir ejercicio ninja: programa portable entre kernels 5.10/5.15/6.1 (solo requisitos)
    - _Requirements: 4.1, 4.3, 4.5, 7.1_

  - [~] 8.4 Crear código del Capítulo 15
    - Escribir ejemplos de BTF/CO-RE: BPF en C + loader en Go
    - Crear solución de referencia del ejercicio de portabilidad
    - _Requirements: 4.6, 5.4, 5.5_

  - [~] 8.5 Escribir Capítulo 16: Networking avanzado — XDP en producción
    - Escribir las 6 secciones: XDP en prod, load balancing, DDoS mitigation, redirect/devmap, AF_XDP, caso Katran
    - Incluir diagramas (arquitectura load balancer XDP, flujo XDP redirect)
    - Incluir 3 casos de estudio: Katran (Meta), Cilium, Cloudflare
    - Analizar limitaciones y alternativa sin eBPF (IPVS/HAProxy)
    - Escribir ejercicio ninja: load balancer L4 (<5µs/paquete, 100k conexiones)
    - _Requirements: 4.1, 4.2, 4.3, 4.5, 7.1_

  - [~] 8.6 Crear código del Capítulo 16
    - Escribir ejemplos de XDP avanzado (load balancing, redirect): BPF en C + loader en Go
    - Crear solución de referencia del load balancer L4
    - _Requirements: 4.6, 5.4, 5.5_

  - [~] 8.7 Escribir Capítulo 17: Seguridad y observabilidad — eBPF en las trincheras
    - Escribir las 6 secciones: seguridad, LSM hooks, detección anómala, observabilidad a escala, modelo de seguridad, caso Falco/Tetragon
    - Incluir diagramas (runtime security, pipeline observabilidad)
    - Incluir 3 casos de estudio: Falco, Tetragon, Pixie
    - Analizar limitaciones y alternativa sin eBPF (auditd)
    - Escribir ejercicio ninja: detección de container escapes (LSM + syscall monitoring + alerting)
    - _Requirements: 4.1, 4.2, 4.3, 4.5, 7.1_

  - [~] 8.8 Crear código del Capítulo 17
    - Escribir ejemplos de LSM hooks y syscall monitoring: BPF en C + loader en Go
    - Crear solución de referencia del sistema de detección
    - _Requirements: 4.6, 5.4, 5.5_

  - [~] 8.9 Escribir Capítulo 18: Optimización y el camino del contribuidor
    - Escribir las 6 secciones: profiling, optimización, testing BPF, contribuir al kernel, ecosistema 2024+, siguiente paso
    - Incluir diagramas (pipeline profiling, mapa del ecosistema)
    - Incluir caso de estudio: revisión de un parche real al subsistema BPF
    - Incluir advertencia (medir antes de optimizar)
    - Escribir ejercicio ninja: perfilar y optimizar un ejercicio previo con evidencia medida
    - _Requirements: 4.1, 4.3, 4.5, 7.1_

  - [~] 8.10 Crear código del Capítulo 18
    - Escribir ejemplos de profiling y optimización (BPF_PROG_TEST_RUN, per-CPU maps, batching)
    - Crear scripts de benchmarking como referencia
    - _Requirements: 4.6, 5.4, 5.5_

  - [~] 8.11 Escribir introducción de Parte III
    - Escribir `src/parte-3-ninja/intro.md` con prerrequisitos (completar Nivel Intermedio), objetivos, resumen de capítulos
    - _Requirements: 1.2, 4.4_

- [~] 9. Checkpoint — Parte III completa
  - Verificar todos los capítulos 14-18 con la checklist. Verificar código compilable. Verificar que cada capítulo integra al menos 2 conceptos de niveles anteriores. Verificar que hay al menos 3 casos de estudio documentados. Preguntar al usuario si hay dudas.

- [ ] 10. Escribir Apéndices
  - [~] 10.1 Escribir Apéndice A: Glosario bilingüe
    - Compilar todos los términos técnicos introducidos en los 18 capítulos (~80-120 términos)
    - Formato: término inglés, explicación español, referencia al capítulo de introducción
    - Organizar alfabéticamente por término en inglés
    - _Requirements: 6.1, 6.3_

  - [~] 10.2 Escribir Apéndice B: Referencia rápida de helper functions
    - Organizar helpers por tipo de programa (XDP, TC, Kprobes, LSM, universales)
    - Cada entrada: nombre, firma, descripción 1 línea, kernel mínimo requerido
    - _Requirements: 7.5_

  - [~] 10.3 Escribir Apéndice C: Cheatsheet de tipos de maps
    - Tabla rápida: tipo de map × características (max entries, per-CPU, user-accessible, etc.)
    - Incluir guía rápida de cuándo usar cada tipo
    - _Requirements: 3.1, 7.5_

  - [~] 10.4 Escribir Apéndice D: Troubleshooting del verifier
    - Documentar los 20 errores más comunes del verifier
    - Cada entrada: mensaje exacto, significado, cómo resolverlo, ejemplo antes/después
    - _Requirements: 3.1, 7.3_

  - [~] 10.5 Escribir Apéndice E: Recursos y comunidad
    - Documentación oficial, repositorios clave, conferencias, comunidades, blogs/newsletters
    - Organizar por categoría con descripciones breves
    - _Requirements: 7.4_

- [~] 11. Checkpoint — Apéndices completos
  - Verificar que el glosario contiene todos los términos introducidos en el texto. Verificar que la referencia de helpers cubre lo mencionado en Cap 8. Preguntar al usuario si hay dudas.

- [ ] 12. Revisión editorial y consistencia
  - [~] 12.1 Revisión de progresión terminológica
    - Verificar que ningún término técnico se usa antes de ser introducido (o tiene nota de referencia adelantada)
    - Verificar formato consistente de primera mención: `**término** (pronunciación) — explicación`
    - Generar lista maestra de términos con capítulo de introducción
    - _Requirements: 1.3, 1.5, 6.2, 6.3, 6.5, 6.6_

  - [~] 12.2 Revisión de completitud de capítulos
    - Verificar cada capítulo contra la checklist: título, cita, términos, objetivos, prerrequisitos, secciones (≥2), código, diagrama (≥1), advertencia (≥1), ejercicio, resumen (3-7 puntos), recursos (≥2)
    - Verificar que la distribución de páginas cumple: Novato 20-30%, Intermedio 40-50%, Ninja 25-35%
    - _Requirements: 8.1, 8.2, 8.3_

  - [~] 12.3 Revisión de tono y estilo
    - Verificar tono consistente: directo, irreverente, punk pero honesto, sin relleno corporativo
    - Verificar que cada capítulo abre con cita/frase acorde al estilo
    - Verificar que las analogías son cotidianas y no forzadas
    - _Requirements: 7.2, 7.3_

  - [~] 12.4 Verificación final del código
    - Ejecutar CI completa: todos los programas BPF compilan (C), todos los loaders compilan (Go), capítulo 11 compila (Rust)
    - Verificar que todos los ejercicios tienen esqueleto Y solución
    - Verificar que las soluciones producen el output documentado en el texto
    - _Requirements: 5.2, 5.3, 5.5_

- [~] 13. Checkpoint final — Libro listo para beta readers
  - Verificar build completo de mdBook sin errores. Verificar CI verde. Verificar que el libro es navegable y los recuadros se renderizan bien. Preguntar al usuario si hay dudas.

## Notes

- Este es un proyecto de ESCRITURA DE LIBRO, no de desarrollo de software
- Código BPF (kernel side): siempre C. User space: Go (cilium/ebpf) como lenguaje principal
- Rust (Aya) solo aparece en el capítulo 11 como comparación
- Python/BCC se menciona brevemente pero no se usa en ejemplos
- No aplica property-based testing — la calidad se valida con CI de compilación y revisión editorial
- El tono es punk, directo, irreverente pero honesto — zero relleno corporativo
- La terminología técnica de eBPF se mantiene en inglés con explicaciones en español
- Los checkpoints son puntos de revisión humana del contenido
- Cada tarea de escritura de capítulo incluye TODOS los elementos pedagógicos de la plantilla

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.4"] },
    { "id": 1, "tasks": ["1.2", "1.3", "1.5"] },
    { "id": 2, "tasks": ["2.1"] },
    { "id": 3, "tasks": ["4.1", "4.2", "4.8"] },
    { "id": 4, "tasks": ["4.3", "4.7"] },
    { "id": 5, "tasks": ["4.4", "4.5"] },
    { "id": 6, "tasks": ["4.6"] },
    { "id": 7, "tasks": ["6.1", "6.3", "6.5", "6.17"] },
    { "id": 8, "tasks": ["6.2", "6.4", "6.6", "6.7", "6.9"] },
    { "id": 9, "tasks": ["6.8", "6.10", "6.11", "6.13"] },
    { "id": 10, "tasks": ["6.12", "6.14", "6.15"] },
    { "id": 11, "tasks": ["6.16"] },
    { "id": 12, "tasks": ["8.1", "8.3", "8.5", "8.11"] },
    { "id": 13, "tasks": ["8.2", "8.4", "8.6", "8.7", "8.9"] },
    { "id": 14, "tasks": ["8.8", "8.10"] },
    { "id": 15, "tasks": ["10.1", "10.2", "10.3", "10.4", "10.5"] },
    { "id": 16, "tasks": ["12.1", "12.2", "12.3", "12.4"] }
  ]
}
```
