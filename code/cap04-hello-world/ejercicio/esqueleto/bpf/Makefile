# =============================================================================
# Makefile — Compilación del ejercicio Hello World (Capítulo 4)
#
# Uso:
#   make          Compila hello.bpf.c → hello.bpf.o
#   make clean    Elimina archivos generados
# =============================================================================

CLANG  ?= clang
CFLAGS := -O2 -target bpf -g -Wall -c

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CFLAGS += -D__TARGET_ARCH_$(ARCH)

BPF_SRC := hello.bpf.c
BPF_OBJ := hello.bpf.o

.PHONY: all clean

all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(CFLAGS) $< -o $@
	@echo "✓ Compilado: $< → $@"

clean:
	rm -f $(BPF_OBJ)
	@echo "✓ Limpieza completada"
