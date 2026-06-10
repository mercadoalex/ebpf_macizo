# =============================================================================
# Makefile — Capítulo 7: El Verifier
#
# Compila SOLO las versiones corregidas (fixed/).
# Las versiones rotas (broken/) están ahí para que el lector entienda
# los errores — no se espera que compilen ni pasen el verifier.
#
# Uso:
#   make            Compila todas las versiones corregidas
#   make clean      Elimina archivos generados
#   make inspect    Muestra secciones ELF de los objetos compilados
#   make try-broken Intenta compilar los rotos (para ver los warnings)
# =============================================================================

# Herramientas
CLANG   ?= clang
OBJDUMP ?= llvm-objdump

# Flags de compilación
CFLAGS := -O2 -target bpf -g -Wall -c

# Detectar arquitectura
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CFLAGS += -D__TARGET_ARCH_$(ARCH)

# Archivos fuente (solo fixed/)
FIXED_SRC := $(wildcard fixed/*.bpf.c)
FIXED_OBJ := $(FIXED_SRC:.bpf.c=.bpf.o)

# Archivos rotos (para target try-broken)
BROKEN_SRC := $(wildcard broken/*.bpf.c)

# =============================================================================
# Targets
# =============================================================================

.PHONY: all clean inspect try-broken

all: $(FIXED_OBJ)
	@echo ""
	@echo "✓ Todas las versiones corregidas compiladas exitosamente"
	@echo "  Estos programas pasarán el verifier al cargarse."

fixed/%.bpf.o: fixed/%.bpf.c
	$(CLANG) $(CFLAGS) $< -o $@
	@echo "✓ Compilado: $< → $@"

clean:
	rm -f fixed/*.bpf.o
	@echo "✓ Limpieza completada"

inspect: $(FIXED_OBJ)
	@for obj in $(FIXED_OBJ); do \
		echo "=== $$obj ==="; \
		$(OBJDUMP) -h $$obj; \
		echo ""; \
	done

# Target educativo: intentar compilar los programas rotos.
# Algunos ni siquiera compilan (errores de C), otros compilan pero
# fallarán el verifier al intentar cargarlos.
try-broken:
	@echo "⚠️  Intentando compilar programas rotos..."
	@echo "    (Algunos van a compilar pero fallarán el verifier al cargar)"
	@echo ""
	@for src in $(BROKEN_SRC); do \
		echo "--- $$src ---"; \
		$(CLANG) $(CFLAGS) $$src -o /dev/null 2>&1 || true; \
		echo ""; \
	done
