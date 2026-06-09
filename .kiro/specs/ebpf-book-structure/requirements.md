# Requirements Document

## Introduction

Este documento define los requisitos para la estructura de un libro de eBPF en español, diseñado para guiar al lector desde un nivel principiante ("novato") hasta un nivel avanzado ("ninja"). Será el primer libro de eBPF escrito en español y cubrirá conceptos teóricos, ejemplos prácticos y ejercicios progresivos. La terminología técnica de eBPF (maps, probes, verifier, tail calls, etc.) se mantendrá en inglés con explicaciones en español.

## Glossary

- **Estructura_del_Libro**: Organización jerárquica del contenido en partes, capítulos, secciones y ejercicios prácticos
- **Nivel_Novato**: Nivel inicial que cubre fundamentos del kernel Linux y conceptos básicos de eBPF sin conocimientos previos requeridos
- **Nivel_Intermedio**: Nivel que introduce programación activa con eBPF, uso de maps, interacción con el verifier y herramientas del ecosistema
- **Nivel_Ninja**: Nivel avanzado que cubre optimización, casos de uso en producción, networking avanzado, seguridad y contribución al ecosistema
- **Ejercicio_Práctico**: Actividad guiada con código funcional que el lector debe implementar para reforzar los conceptos del capítulo
- **Progresión_Didáctica**: Secuencia lógica de contenidos donde cada capítulo construye sobre los conocimientos del anterior
- **Terminología_Bilingüe**: Práctica de mantener términos técnicos de eBPF en inglés acompañados de explicaciones y contexto en español

## Requirements

### Requirement 1: Organización general del libro en niveles de progresión

**User Story:** Como lector hispanohablante interesado en eBPF, quiero que el libro esté organizado en niveles claros de progresión, para poder seguir un camino de aprendizaje desde cero hasta nivel avanzado.

#### Acceptance Criteria

1. THE Estructura_del_Libro SHALL organizar el contenido en exactamente tres partes principales: Nivel_Novato, Nivel_Intermedio y Nivel_Ninja
2. WHEN un lector comienza una parte nueva, THE Estructura_del_Libro SHALL incluir una introducción que contenga: una lista de prerequisitos verificables por el lector, los objetivos de aprendizaje enumerados para esa parte, y un resumen de los capítulos que la componen con una descripción de no más de 2 oraciones por capítulo
3. THE Progresión_Didáctica SHALL garantizar que cada capítulo solo utilice términos técnicos de eBPF y APIs que hayan sido explicados en capítulos anteriores o en la introducción de la parte correspondiente
4. THE Estructura_del_Libro SHALL incluir un mapa visual de progresión al inicio del libro que muestre el orden secuencial de los capítulos, las dependencias de conocimiento entre ellos, y la agrupación por nivel de dificultad
5. IF un capítulo necesita referenciar un término técnico de eBPF que se explica en un capítulo posterior, THEN THE Progresión_Didáctica SHALL incluir una nota indicando en qué capítulo se encuentra la explicación completa y proporcionar una definición breve de no más de 1 oración en el punto de uso

### Requirement 2: Contenido del Nivel Novato

**User Story:** Como principiante sin experiencia en eBPF, quiero una introducción sólida a los fundamentos, para poder entender qué es eBPF y cómo interactúa con el kernel Linux.

#### Acceptance Criteria

1. THE Nivel_Novato SHALL cubrir los siguientes temas en orden progresivo de complejidad: arquitectura del kernel Linux, qué es eBPF y su historia, el modelo de ejecución en el kernel, el concepto de hooks y attach points, y la escritura de un primer programa "Hello World" en eBPF
2. THE Nivel_Novato SHALL presentar el entorno de desarrollo incluyendo: compilador de BPF (clang/LLVM), libbpf o bcc como framework, versión mínima del kernel requerida, y los pasos de verificación para confirmar que el entorno está correctamente configurado
3. WHEN se introduce un término técnico en inglés por primera vez, THE Nivel_Novato SHALL proporcionar una definición en español de no más de 2 oraciones, su pronunciación aproximada entre paréntesis y un ejemplo de uso en contexto de eBPF
4. THE Nivel_Novato SHALL contener entre 4 y 6 capítulos ordenados secuencialmente desde la motivación hasta la ejecución del primer programa, donde cada capítulo asume únicamente conocimientos presentados en capítulos anteriores del mismo nivel
5. WHEN un capítulo del Nivel_Novato finaliza, THE Estructura_del_Libro SHALL incluir un Ejercicio_Práctico con instrucciones paso a paso donde cada paso contiene: la acción a realizar, el código completo a escribir o ejecutar, y el resultado esperado observable en terminal
6. THE Nivel_Novato SHALL declarar como prerrequisitos del lector: familiaridad básica con la línea de comandos Linux y conocimientos elementales de programación en C o Python
7. WHEN el programa "Hello World" en eBPF se ejecuta correctamente, THE Nivel_Novato SHALL definir el éxito como: el programa se carga en el kernel sin errores del verificador, se adjunta a un hook especificado, y produce una salida observable mediante bpf_trace_printk o equivalente

### Requirement 3: Contenido del Nivel Intermedio

**User Story:** Como desarrollador que ya entiende los fundamentos de eBPF, quiero profundizar en los mecanismos principales del framework, para poder escribir programas útiles que interactúen con el kernel.

#### Acceptance Criteria

1. THE Nivel_Intermedio SHALL cubrir los siguientes temas, dedicando al menos una sección con explicación conceptual, diagrama y ejemplo por cada uno: tipos de programas eBPF (kprobes, tracepoints, XDP, TC, cgroup), maps y sus tipos (hash, array, ring buffer, per-CPU), el verifier y sus reglas de validación, helper functions, y comunicación entre user space y kernel space
2. THE Nivel_Intermedio SHALL introducir al menos dos frameworks de desarrollo: libbpf (C) y un framework de alto nivel como Aya (Rust) o BCC (Python), incluyendo para cada framework un ejemplo compilable y ejecutable que demuestre carga de un programa eBPF, adjunto de mapa, y lectura de datos desde user space
3. WHEN se presenta un tipo de programa eBPF, THE Nivel_Intermedio SHALL incluir un diagrama del flujo de datos y un ejemplo funcional que contenga código fuente compilable, instrucciones de compilación y ejecución, y la salida esperada que el lector pueda verificar
4. THE Nivel_Intermedio SHALL contener entre 5 y 8 capítulos ordenados de forma que cada capítulo requiera conceptos del capítulo anterior, comenzando por maps y helper functions y progresando hacia programas que combinan múltiples attach points y comunicación user-kernel
5. WHEN un capítulo del Nivel_Intermedio finaliza, THE Estructura_del_Libro SHALL incluir un Ejercicio_Práctico que describa el problema a resolver, los criterios de éxito observables para que el lector valide su solución, y entre 2 y 4 pistas parciales sin proporcionar el código completo de la solución

### Requirement 4: Contenido del Nivel Ninja

**User Story:** Como desarrollador experimentado en eBPF, quiero dominar técnicas avanzadas y casos de uso en producción, para poder implementar soluciones complejas y contribuir al ecosistema.

#### Acceptance Criteria

1. THE Nivel_Ninja SHALL cubrir los siguientes temas avanzados: tail calls y function calls, BTF (BPF Type Format) y CO-RE (Compile Once - Run Everywhere), networking avanzado con XDP y TC, seguridad y sandboxing con eBPF, observabilidad en producción, y optimización de rendimiento
2. THE Nivel_Ninja SHALL incluir al menos 3 casos de estudio de organizaciones con despliegues de eBPF en producción documentados públicamente (como Cilium, Falco, o Katran), donde cada caso de estudio incluya descripción del problema, arquitectura de la solución eBPF, resultados o métricas obtenidas, y lecciones aprendidas
3. WHEN se presenta una técnica avanzada, THE Nivel_Ninja SHALL analizar al menos 2 limitaciones, los trade-offs principales, y al menos 1 escenario donde una alternativa sin eBPF es más apropiada
4. THE Nivel_Ninja SHALL contener entre 4 y 6 capítulos, donde cada capítulo integre al menos 2 conceptos de niveles anteriores (Novato o Intermedio)
5. WHEN un capítulo del Nivel_Ninja finaliza, THE Estructura_del_Libro SHALL incluir un Ejercicio_Práctico de tipo proyecto que combine al menos 2 técnicas avanzadas del nivel, defina un escenario con restricciones de producción (volumen de datos, latencia, o disponibilidad), y permita más de una solución válida
6. THE Nivel_Ninja SHALL incluir al menos 2 ejemplos de código funcional y comentado por cada tema avanzado cubierto

### Requirement 5: Ejercicios prácticos y progresión de dificultad

**User Story:** Como lector, quiero ejercicios prácticos que se adapten a mi nivel, para poder consolidar mi aprendizaje de forma progresiva.

#### Acceptance Criteria

1. THE Estructura_del_Libro SHALL incluir al menos un Ejercicio_Práctico por cada nivel de dificultad (Nivel_Novato, Nivel_Intermedio, Nivel_Ninja) en cada capítulo del libro
2. IF un ejercicio pertenece al Nivel_Novato, THEN THE Ejercicio_Práctico SHALL proporcionar código completo con instrucciones paso a paso numeradas y una salida esperada documentada que el lector pueda comparar con su propia ejecución
3. IF un ejercicio pertenece al Nivel_Intermedio, THEN THE Ejercicio_Práctico SHALL proporcionar un enunciado del problema, un esqueleto de código parcial con comentarios indicando las secciones a completar, y al menos un caso de prueba ejecutable que valide la solución
4. IF un ejercicio pertenece al Nivel_Ninja, THEN THE Ejercicio_Práctico SHALL proporcionar solo requisitos funcionales y restricciones de rendimiento o diseño, dejando el diseño e implementación al lector
5. THE Estructura_del_Libro SHALL incluir un repositorio de código complementario con soluciones de referencia para todos los ejercicios
6. WHEN un ejercicio requiere un entorno específico, THE Ejercicio_Práctico SHALL incluir instrucciones de configuración usando contenedores o máquinas virtuales que permitan al lector ejecutar el ejercicio obteniendo los mismos resultados independientemente de su sistema operativo
7. THE Ejercicio_Práctico SHALL indicar su nivel de dificultad (Nivel_Novato, Nivel_Intermedio o Nivel_Ninja) y los conceptos previos requeridos para su resolución

### Requirement 6: Tratamiento de terminología bilingüe

**User Story:** Como lector hispanohablante, quiero entender la terminología técnica de eBPF que está en inglés, para poder leer documentación oficial y participar en la comunidad internacional.

#### Acceptance Criteria

1. THE Estructura_del_Libro SHALL incluir un glosario bilingüe (inglés-español) como apéndice al final del libro que contenga todos los términos técnicos en inglés introducidos en el texto, cada entrada con el término en inglés, su explicación en español y la referencia al capítulo donde se introduce por primera vez
2. WHEN un término técnico en inglés aparece por primera vez en el texto, THE Terminología_Bilingüe SHALL presentarlo en formato: "**término_inglés** (explicación en español de entre 3 y 15 palabras)"
3. THE Terminología_Bilingüe SHALL mantener consistencia usando siempre el mismo término en inglés a lo largo de todo el libro una vez introducido
4. THE Estructura_del_Libro SHALL incluir al inicio de cada capítulo una lista de todos los términos técnicos en inglés que se introducen por primera vez en ese capítulo
5. IF un término técnico tiene una traducción en español utilizada en al menos dos fuentes técnicas o documentación oficial de referencia en español, THEN THE Terminología_Bilingüe SHALL mencionarla entre paréntesis tras la primera aparición del término en inglés, y usar preferentemente el término en inglés en el resto del texto
6. WHEN un término técnico en inglés se utiliza después de su primera introducción, THE Terminología_Bilingüe SHALL presentarlo sin la explicación entre paréntesis, usando únicamente el término en inglés ya introducido

### Requirement 7: Elementos pedagógicos complementarios

**User Story:** Como lector, quiero elementos adicionales que faciliten mi comprensión, para poder aprender de manera más efectiva.

#### Acceptance Criteria

1. THE Estructura_del_Libro SHALL incluir al menos 1 diagrama arquitectónico por capítulo que ilustre la interacción entre componentes del kernel y programas eBPF, acompañado de una descripción textual que explique los elementos representados
2. WHEN se introduce una nueva abstracción del kernel, un nuevo tipo de mapa, o una interacción multi-componente, THE Estructura_del_Libro SHALL incluir un recuadro de "Analogía" que relacione el concepto con situaciones cotidianas no técnicas
3. THE Estructura_del_Libro SHALL incluir al menos 1 recuadro de "Advertencia" por capítulo que identifique un error común o trampa frecuente, indicando tanto el comportamiento erróneo como la práctica correcta recomendada
4. WHEN un capítulo finaliza, THE Estructura_del_Libro SHALL incluir una sección de "Resumen" con entre 3 y 7 puntos clave del capítulo, y una sección de "Para saber más" con al menos 2 recursos adicionales categorizados por tipo (documentación oficial, artículos, o repositorios de código)
5. THE Estructura_del_Libro SHALL incluir un apéndice con la referencia rápida de helper functions organizadas por tipo de programa

### Requirement 8: Estructura de capítulos propuesta

**User Story:** Como autor, quiero una estructura de capítulos detallada, para poder planificar la escritura del libro de forma organizada.

#### Acceptance Criteria

1. THE Estructura_del_Libro SHALL definir un índice que incluya, para cada capítulo: título del capítulo, al menos 2 secciones principales con sus títulos, y una estimación de páginas comprendida entre 10 y 40 páginas por capítulo
2. THE Estructura_del_Libro SHALL distribuir el número de páginas estimadas de forma equilibrada: entre 20% y 30% para Nivel_Novato, entre 40% y 50% para Nivel_Intermedio, y entre 25% y 35% para Nivel_Ninja
3. THE Estructura_del_Libro SHALL especificar para cada capítulo: entre 2 y 4 objetivos de aprendizaje formulados como capacidades observables, los prerequisitos del capítulo anterior que el lector debe dominar, y el entregable del Ejercicio_Práctico asociado
4. IF el capítulo es el primero del libro, THEN THE Estructura_del_Libro SHALL indicar que no requiere prerequisitos previos y SHALL definir únicamente los conocimientos base asumidos del lector
5. THE Estructura_del_Libro SHALL incluir al menos 1 capítulo de transición entre cada par de niveles consecutivos, donde cada capítulo de transición contenga un resumen de conceptos clave del nivel anterior y una introducción a los conceptos del nivel siguiente
6. THE Estructura_del_Libro SHALL totalizar entre 15 y 20 capítulos sin contar apéndices ni material complementario
