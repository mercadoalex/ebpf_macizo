# =============================================================================
# Makefile — Ejercicio Capítulo 17: Container Escape Detector (Solución)
#
# Uso:
#   make          Compila el programa BPF → escape_detector.bpf.o
#   make clean    Elimina archivos generados
#   make inspect  Muestra secciones ELF del objeto
# =============================================================================

# Herramientas
CLANG   ?= clang
OBJDUMP ?= llvm-objdump

# Flags de compilación
CFLAGS := -O2 -target bpf -g -Wall -c

# Detectar arquitectura
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CFLAGS += -D__TARGET_ARCH_$(ARCH)

# Archivos
BPF_SRCS := escape_detector.bpf.c
BPF_OBJS := $(BPF_SRCS:.bpf.c=.bpf.o)

# =============================================================================
# Targets
# =============================================================================

.PHONY: all clean inspect

all: $(BPF_OBJS)

%.bpf.o: %.bpf.c
	$(CLANG) $(CFLAGS) $< -o $@
	@echo "✓ Compilado: $< → $@"

clean:
	rm -f $(BPF_OBJS)
	@echo "✓ Limpieza completada"

inspect: $(BPF_OBJS)
	@for obj in $(BPF_OBJS); do \
		echo "=== $$obj — Secciones ELF ==="; \
		$(OBJDUMP) -h $$obj; \
		echo ""; \
	done
