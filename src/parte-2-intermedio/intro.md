# Parte II: Intermedio

> "Saber que el kernel existe es turismo. Escribir código que vive dentro de él es otra cosa."

---

## Prerrequisitos

Para entrar aquí necesitas haber completado la Parte I — no de oído, de verdad. Verifica:

- **Entiendes la separación user space / kernel space.** Sabes qué vive de cada lado y por qué importa.
- **Sabes qué es eBPF y cómo funciona su modelo de ejecución.** Compilar → cargar → verificar → JIT → ejecutar. No es magia, es un pipeline.
- **Tienes un entorno de desarrollo funcional.** clang, LLVM, bpftool, Go con cilium/ebpf. Todo compilando y cargando sin errores.
- **Escribiste y ejecutaste tu primer programa eBPF.** Se cargó, se adjuntó a un tracepoint, y viste salida en trace_pipe. Si no llegaste ahí, vuelve al Capítulo 4.

### Checklist rápido

- [ ] Puedo explicar qué pasa entre que escribo un `.bpf.c` y el kernel lo ejecuta
- [ ] Sé qué es un attach point y puedo nombrar al menos dos tipos
- [ ] Mi toolchain compila programas BPF sin errores
- [ ] Cargué al menos un programa al kernel y vi su salida
- [ ] Entiendo por qué existe el verifier (aunque todavía me odie)

Todo marcado? Vamos. Si te falta algo, la Parte I está ahí atrás. No hay vergüenza en volver.

---

## Qué vas a aprender en esta parte

Al terminar los 8 capítulos del Nivel Intermedio vas a poder:

1. Crear y manipular maps para compartir datos entre kernel y user space
2. Escribir código que pasa el verifier sin rezar — entendiendo sus reglas
3. Usar helper functions para obtener contexto, medir tiempos y manipular paquetes
4. Instrumentar el kernel con kprobes, tracepoints y fentry/fexit
5. Procesar paquetes de red a velocidad de kernel con XDP y TC
6. Trabajar con cilium/ebpf (Go) en profundidad y conocer Aya (Rust) como alternativa
7. Implementar comunicación real entre kernel y user space con ring buffers
8. Combinar todo lo anterior en herramientas funcionales de observabilidad

Cuando salgas de esta parte, ya no vas a estar "aprendiendo eBPF". Vas a estar *usando* eBPF para resolver problemas reales.

---

## Cambio de formato en los ejercicios

En la Parte I te llevamos de la mano — paso a paso, código completo, resultado esperado. Eso se acabó.

A partir de aquí los ejercicios cambian a formato **esqueleto**: te damos la estructura del programa, los comentarios `// TODO` donde va tu lógica, pistas parciales, y criterios de éxito para que valides tu solución. El código completo ya no aparece en el enunciado.

¿Por qué? Porque copiar y pegar no te hace mejor programador. Pensar, equivocarte, debuggear y resolver sí.

---

## Los capítulos

### Capítulo 6: Maps — La memoria compartida

Estructuras de datos persistentes que viven en kernel space. Aprendes a crear, leer y escribir maps desde ambos lados — el programa BPF y tu código en user space — y a elegir el tipo correcto según tu problema.

### Capítulo 7: El Verifier — Tu enemigo favorito

Las reglas del juego: por qué el verifier rechaza tu código, qué está verificando, y cómo escribir programas que pasen a la primera. Vas a dejar de temerle y empezar a entenderlo.

### Capítulo 8: Helper functions — El arsenal

Las APIs disponibles para programas BPF: obtener PIDs, medir timestamps, manipular paquetes, escribir en maps. Conoces el catálogo, entiendes qué helpers van con qué tipos de programa, y los usas en código real.

### Capítulo 9: Kprobes y Tracepoints — Escuchando al kernel

Instrumentación del kernel en vivo. Te enganchas a funciones internas con kprobes, usas tracepoints estáticos, y capturas argumentos y valores de retorno sin tocar una línea del código del kernel.

### Capítulo 10: XDP y TC — Networking a velocidad del kernel

Procesamiento de paquetes antes de que el network stack los toque. Escribes programas XDP que deciden en nanosegundos si un paquete pasa, muere o se redirige, y usas TC para filtrado post-stack.

### Capítulo 11: Frameworks en acción — cilium/ebpf, Aya, y el ecosistema

cilium/ebpf (Go) en detalle: el framework principal de este libro, con todo lo que necesitas para escribir herramientas completas. Además, Aya (Rust) como alternativa para cuando necesitas safety garantizado.

### Capítulo 12: User space ↔ Kernel — La conversación

Comunicación real entre tus programas BPF y el mundo exterior. Ring buffers, perf events, maps compartidos — los mecanismos para sacar datos del kernel a tu aplicación de forma eficiente y sin perder eventos.

### Capítulo 13: De intermedio a ninja — El puente

Consolidación de todo lo aprendido y un mini-proyecto que integra maps + kprobes + ring buffer + consumer en user space. Identificamos las paredes que vas a golpear y te preparamos para las técnicas del Nivel Ninja.

---

A partir de aquí escribes código de verdad. Capítulo 6 arranca en la siguiente página.
