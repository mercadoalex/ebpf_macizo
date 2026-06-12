# =============================================================================
# Makefile — Compilación de programas BPF del Capítulo 15 (BTF y CO-RE)
#
# Uso:
#   make          Compila todos los programas BPF → .bpf.o
#   make clean    Elimina archivos generados
#   make inspect  Muestra BTF embebido en los objetos (para ver relocations)
#
# NOTA: La flag -g es OBLIGATORIA para CO-RE.
# Sin -g, clang no emite la información BTF ni los relocations que
# el loader necesita para resolver offsets en runtime.
# =============================================================================

# Herramientas
CLANG   ?= clang
BPFTOOL ?= bpftool

# Flags de compilación — -g es OBLIGATORIO para CO-RE
# -O2: optimización estándar para BPF
# -g: emitir DWARF → BTF (OBLIGATORIO para CO-RE)
# -target bpf: generar bytecode BPF
# -Wall: todos los warnings
CFLAGS := -O2 -target bpf -g -Wall -c

# Detectar arquitectura para vmlinux.h
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CFLAGS += -D__TARGET_ARCH_$(ARCH)

# Incluir directorio local para vmlinux.h
CFLAGS += -I.

# Archivos fuente y objetos
BPF_SRCS := hardcoded_offsets.bpf.c core_exit_tracer.bpf.c core_fentry.bpf.c
BPF_OBJS := $(BPF_SRCS:.bpf.c=.bpf.o)

# =============================================================================
# Targets
# =============================================================================

.PHONY: all clean inspect btf-check

all: $(BPF_OBJS)

# Nota: hardcoded_offsets.bpf.c NO usa vmlinux.h (es el ejemplo "malo")
# Los otros sí lo usan, y REQUIEREN -g para que CO-RE funcione.
%.bpf.o: %.bpf.c
	$(CLANG) $(CFLAGS) $< -o $@
	@echo "✓ Compilado: $< → $@"

clean:
	rm -f $(BPF_OBJS)
	@echo "✓ Limpieza completada"

# Inspeccionar BTF embebido — muestra los tipos y relocations.
# Esto es lo que el loader (cilium/ebpf) usa para resolver offsets.
inspect: $(BPF_OBJS)
	@for obj in $(BPF_OBJS); do \
		echo ""; \
		echo "═══════════════════════════════════════════════════════════════"; \
		echo "  BTF embebido en: $$obj"; \
		echo "═══════════════════════════════════════════════════════════════"; \
		$(BPFTOOL) btf dump file $$obj 2>/dev/null || \
			echo "  (sin BTF — compilado sin -g o herramienta no disponible)"; \
		echo ""; \
	done

# Verificar que el kernel actual tiene BTF disponible
btf-check:
	@echo "Verificando BTF del kernel..."
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		echo "✓ BTF disponible en /sys/kernel/btf/vmlinux"; \
		echo "  Tamaño: $$(du -h /sys/kernel/btf/vmlinux | cut -f1)"; \
	else \
		echo "✗ BTF NO disponible — CO-RE no funcionará en este kernel"; \
		echo "  Necesitas: CONFIG_DEBUG_INFO_BTF=y en la config del kernel"; \
	fi
