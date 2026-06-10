# =============================================================================
# Makefile — Compilación del programa BPF Hello World (Capítulo 4)
#
# Uso:
#   make          Compila hello.bpf.c → hello.bpf.o
#   make clean    Elimina archivos generados
#   make inspect  Muestra información del ELF generado
# =============================================================================

# Herramientas
CLANG   ?= clang
LLC     ?= llc
OBJDUMP ?= llvm-objdump
BPFTOOL ?= bpftool

# Flags de compilación
# -O2       : Optimización necesaria para que el verifier acepte el código
# -target bpf : Genera bytecode BPF (no x86/ARM)
# -g        : Incluye información de debug y BTF
# -Wall     : Muestra todos los warnings
# -c        : Solo compila (no linkea)
CFLAGS := -O2 -target bpf -g -Wall -c

# Detectar arquitectura para el define correcto
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CFLAGS += -D__TARGET_ARCH_$(ARCH)

# Archivos fuente y objeto
BPF_SRC := hello.bpf.c
BPF_OBJ := hello.bpf.o

# =============================================================================
# Targets
# =============================================================================

.PHONY: all clean inspect

all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(CFLAGS) $< -o $@
	@echo "✓ Compilado: $< → $@"

clean:
	rm -f $(BPF_OBJ)
	@echo "✓ Limpieza completada"

# Target de inspección — útil para debug
inspect: $(BPF_OBJ)
	@echo "=== Secciones ELF ==="
	$(OBJDUMP) -h $(BPF_OBJ)
	@echo ""
	@echo "=== Bytecode BPF desensamblado ==="
	$(OBJDUMP) -d $(BPF_OBJ)
