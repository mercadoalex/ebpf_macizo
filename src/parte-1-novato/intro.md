# Parte I: Novato

> "Todo experto fue primero un ignorante que no se quedó sentado."

---

## Prerrequisitos

Antes de arrancar, verifica que cumples con esto:

- **Línea de comandos Linux.** Sabes hacer `cd`, `ls`, `grep`, `cat`, `sudo`, instalar paquetes. No necesitas ser un wizard de bash, pero si la terminal te da miedo, resuelve eso primero.
- **Programación básica en C o Go.** Entiendes qué es un puntero, una struct, un tipo de dato. Si puedes leer un `for` y un `if` sin googlear, estás bien. No necesitas ser senior — necesitas no ser cero.

¿No cumples? No pasa nada. Hay miles de recursos para llegar a ese punto. Pero este libro no te va a enseñar a usar `cd` ni qué es una variable. Empezamos donde termina lo básico.

### Checklist rápido

Puedes verificarlo tú mismo:

- [ ] Puedo abrir una terminal y ejecutar `uname -r` sin ayuda
- [ ] Sé qué hace `gcc -o programa programa.c` (o `go build main.go`)
- [ ] Entiendo qué es un proceso y qué es un file descriptor
- [ ] He compilado y ejecutado al menos un programa en C o Go en mi vida

Si marcaste todo, adelante. Si no, invierte unas horas poniéndote al día y vuelve.

---

## Qué vas a aprender en esta parte

Al terminar los 5 capítulos del Nivel Novato vas a poder:

1. Explicar qué es el kernel Linux, qué hace, y por qué te importa como developer
2. Entender qué es eBPF, de dónde viene, y cómo ejecuta código dentro del kernel sin crashearlo
3. Montar un entorno de desarrollo funcional para escribir y cargar programas eBPF
4. Escribir, compilar, cargar y observar tu primer programa eBPF — de principio a fin
5. Distinguir los conceptos fundamentales que necesitas para pasar al siguiente nivel

No vas a salir de aquí siendo un experto. Vas a salir entendiendo el terreno, con un programa que corre en el kernel y con la confianza de que esto no es magia — es ingeniería.

---

## Los capítulos

### Capítulo 1: El kernel no muerde

Desmitificamos el kernel Linux. Qué es, qué hace, cómo se separa del user space, y por qué deberías pensar en él como una plataforma programable en vez de una caja negra intocable.

### Capítulo 2: eBPF — La historia del parche que se comió al kernel

De filtro de paquetes académico a máquina virtual dentro del kernel. La historia de eBPF, su modelo de ejecución, y el mapa de todo lo que puedes hacer con él hoy.

### Capítulo 3: Tu laboratorio de guerra

Manos a la obra: instalas el toolchain (clang, LLVM, bpftool, Go), configuras una VM o container con kernel adecuado, y verificas que todo compila. Sin lab funcional no hay libro.

### Capítulo 4: Hello World — Tu primer hook

Escribes tu primer programa eBPF real: código BPF en C, loader en Go con cilium/ebpf, lo cargas al kernel, lo adjuntas a un tracepoint, y ves la salida en tu terminal. El momento donde todo hace click.

### Capítulo 5: De novato a intermedio — El puente

Consolidamos lo aprendido, identificamos las limitaciones de lo que sabes hasta ahora, y te preparamos para el salto al Nivel Intermedio donde vas a empezar a escribir programas eBPF de verdad.

---

Listo. Capítulo 1 empieza en la siguiente página. A meterle.
