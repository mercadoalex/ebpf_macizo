# =============================================================================
# Makefile — Compilación del programa BPF de helpers de contexto (Capítulo 8)
#
# Uso:
#   make          Compila context_helpers.bpf.c → context_helpers.bpf.o
#   make clean    Elimina archivos generados
#   make inspect  Muestra información del ELF generado
# =============================================================================

# Herramientas
CLANG   ?= clang
OBJDUMP ?= llvm-objdump

# Flags de compilación
# -O2         : Optimización requerida por el verifier
# -target bpf : Genera bytecode BPF
# -g          : Incluye BTF y debug info
# -Wall       : Todos los warnings
# -c          : Solo compila (no linkea)
CFLAGS := -O2 -target bpf -g -Wall -c

# Detectar arquitectura
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CFLAGS += -D__TARGET_ARCH_$(ARCH)

# Archivos
BPF_SRC := context_helpers.bpf.c
BPF_OBJ := context_helpers.bpf.o

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

inspect: $(BPF_OBJ)
	@echo "=== Secciones ELF ==="
	$(OBJDUMP) -h $(BPF_OBJ)
	@echo ""
	@echo "=== Bytecode BPF ==="
	$(OBJDUMP) -d $(BPF_OBJ)
