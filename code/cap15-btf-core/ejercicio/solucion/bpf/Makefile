# =============================================================================
# Makefile — Ejercicio Ninja: Portable Tracer (Capítulo 15)
#
# Compila el programa BPF con CO-RE habilitado (-g OBLIGATORIO).
# El objeto resultante funciona en kernels 5.10, 5.15 y 6.1 sin recompilación.
#
# Uso:
#   make          Compila portable_tracer.bpf.o
#   make clean    Elimina archivos generados
#   make inspect  Muestra BTF y relocations embebidos
# =============================================================================

# Herramientas
CLANG   ?= clang
BPFTOOL ?= bpftool

# Flags — -g es OBLIGATORIO para CO-RE
CFLAGS := -O2 -target bpf -g -Wall -c

# Arquitectura
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CFLAGS += -D__TARGET_ARCH_$(ARCH)

# Incluir directorio local para vmlinux.h
CFLAGS += -I.

# Archivos
BPF_SRCS := portable_tracer.bpf.c
BPF_OBJS := $(BPF_SRCS:.bpf.c=.bpf.o)

# =============================================================================
# Targets
# =============================================================================

.PHONY: all clean inspect

all: $(BPF_OBJS)

%.bpf.o: %.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) $< -o $@
	@echo "✓ Compilado (CO-RE): $< → $@"
	@echo "  Este objeto funciona en kernels 5.10, 5.15 y 6.1"

clean:
	rm -f $(BPF_OBJS)
	@echo "✓ Limpieza completada"

inspect: $(BPF_OBJS)
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "  BTF embebido en portable_tracer.bpf.o"
	@echo "  (esto es lo que CO-RE usa para resolver offsets)"
	@echo "═══════════════════════════════════════════════════════════════"
	@$(BPFTOOL) btf dump file portable_tracer.bpf.o 2>/dev/null || \
		echo "  (bpftool no disponible)"
