# Parte III: Ninja

> "Cualquiera carga un programa al kernel. Pocos saben por qué funciona — y qué hacer cuando deja de hacerlo."

---

## Prerrequisitos

Para entrar aquí necesitas haber completado la Parte II **entera**. No el 80%. No "los capítulos que me parecieron interesantes". Toda.

Verifica:

- **Dominas maps y su ciclo de vida.** Creas, lees, escribes y limpias maps desde ambos lados sin pensar. Sabes cuándo usar hash, cuándo array, cuándo per-CPU, y cuándo ring buffer.
- **El verifier ya no te paraliza.** Entiendes sus reglas, escribes código que pasa a la primera la mayoría de las veces, y cuando falla sabes leer el error y corregirlo.
- **Usas helper functions con criterio.** No copias recetas — eliges el helper correcto según tu tipo de programa y tu problema.
- **Instrumentas el kernel en vivo.** Kprobes, tracepoints, fentry — sabes engancharte a funciones internas y capturar datos sin tocar código del kernel.
- **Procesas paquetes a velocidad de kernel.** XDP y TC no son conceptos abstractos para ti. Has escrito código que decide el destino de paquetes en nanosegundos.
- **cilium/ebpf es tu herramienta diaria.** Cargas programas, lees maps, consumes ring buffers — todo desde Go, todo fluido.
- **Completaste el ejercicio integrador del Capítulo 13.** El mini-proyecto que combina kprobes + maps + ring buffer + consumer en user space. Si lo saltaste, vuelve y hazlo. En serio.

### Checklist rápido

- [ ] Puedo diseñar un sistema con múltiples programas BPF coordinados vía maps
- [ ] Sé por qué el verifier rechaza un acceso y cómo reestructurar el código para que pase
- [ ] He escrito programas XDP funcionales que parsean headers y toman decisiones
- [ ] Puedo implementar comunicación kernel → user space con ring buffer sin perder eventos
- [ ] Mi ejercicio integrador del Cap 13 funciona: carga, instrumenta, reporta

Todo marcado? Entonces estás listo para producción. Si te falta algo, la Parte II no se va a ningún lado.

---

## Qué vas a aprender en esta parte

Al terminar los 5 capítulos del Nivel Ninja vas a poder:

1. Componer sistemas eBPF complejos usando tail calls y function calls para modularizar lógica
2. Escribir programas portables entre versiones de kernel con BTF y CO-RE — compilar una vez, ejecutar en cualquier lado
3. Diseñar e implementar soluciones de networking de producción con XDP: load balancers, mitigación DDoS, redirección inteligente
4. Construir sistemas de seguridad y observabilidad a escala usando LSM hooks, detección de anomalías y pipelines de eventos
5. Perfilar, optimizar y medir tus programas eBPF con evidencia — y saber cómo contribuir al ecosistema upstream

Cuando salgas de esta parte, no vas a ser alguien que "sabe eBPF". Vas a ser alguien que *piensa en sistemas* — que diseña soluciones donde eBPF es una pieza, no un fin en sí mismo. La diferencia entre un programador de eBPF y un ingeniero de sistemas que usa eBPF se define aquí.

---

## Cambio de formato en los ejercicios

En la Parte I te llevamos paso a paso. En la Parte II te dimos esqueletos con `// TODO`. Eso se acabó.

A partir de aquí los ejercicios son **proyectos**: recibes requisitos funcionales y restricciones (de rendimiento, de diseño, de escala), y nada más. No hay esqueleto. No hay estructura sugerida. No hay pistas.

Tú diseñas la solución. Tú eliges la arquitectura. Tú implementas, pruebas y mides.

¿Por qué? Porque en producción nadie te da un esqueleto. Nadie te dice dónde poner el `// TODO`. Los problemas reales llegan como requisitos vagos y restricciones duras — y tu trabajo es convertir eso en código que funciona bajo presión. Este nivel te prepara para exactamente eso.

Las soluciones de referencia existen en el repositorio de código, pero son *una* solución posible, no *la* solución. Si tu implementación cumple los requisitos y respeta las restricciones, es válida.

---

## Los capítulos

### Capítulo 14: Tail calls, function calls y composición

Cuando un solo programa no alcanza. Aprendes a dividir lógica compleja en programas encadenados con tail calls, a reutilizar código con BPF-to-BPF function calls, y a diseñar pipelines de procesamiento modulares. También: las trampas, los límites, y cuándo NO usar composición.

### Capítulo 15: BTF y CO-RE — Escribe una vez, corre en todos lados

El infierno de las versiones de kernel: struct offsets que cambian, campos que desaparecen, programas que se rompen al actualizar. BTF y CO-RE resuelven esto. Aprendes a escribir programas verdaderamente portables que se adaptan al kernel donde corren — sin recompilar, sin parches, sin dolor.

### Capítulo 16: Networking avanzado — XDP en producción

XDP pasa de ejercicio didáctico a herramienta de producción. Load balancing L4 a millones de paquetes por segundo, mitigación DDoS en el edge, redirección con devmap, AF_XDP para bypass completo del stack. Casos reales de Meta (Katran), Cilium y Cloudflare.

### Capítulo 17: Seguridad y observabilidad — eBPF en las trincheras

eBPF como plataforma de seguridad runtime y observabilidad a escala. LSM hooks para enforcement, detección de container escapes, pipelines de observabilidad que no destruyen la performance. Casos reales de Falco, Tetragon y Pixie. El modelo de seguridad de eBPF mismo: qué puede salir mal.

### Capítulo 18: Optimización y el camino del contribuidor

Medir antes de optimizar. Perfilar programas BPF, usar per-CPU maps y batching para eliminar contención, `BPF_PROG_TEST_RUN` para testing sin kernel. Y después: cómo funciona el desarrollo upstream, cómo leer y enviar parches al subsistema BPF, y qué viene después de este libro.

---

A partir de aquí no hay red. Capítulo 14 arranca en la siguiente página.
