# =============================================================================
# Makefile — Compilación del ejercicio Event Logger (Capítulo 12) — Solución
#
# Uso:
#   make          Compila event_logger.bpf.c → event_logger.bpf.o
#   make clean    Elimina archivos generados
# =============================================================================

CLANG  ?= clang
CFLAGS := -O2 -target bpf -g -Wall -c

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CFLAGS += -D__TARGET_ARCH_$(ARCH)

BPF_SRC := event_logger.bpf.c
BPF_OBJ := event_logger.bpf.o

.PHONY: all clean

all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(CFLAGS) $< -o $@
	@echo "✓ Compilado: $< → $@"

clean:
	rm -f $(BPF_OBJ)
	@echo "✓ Limpieza completada"
