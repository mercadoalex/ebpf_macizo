#!/bin/bash
# =============================================================================
# benchmark.sh — Capítulo 18: Script de benchmarking para programas eBPF
#
# Ejecuta BPF_PROG_TEST_RUN a través del programa Go y recolecta resultados
# en múltiples configuraciones. Útil para comparar antes/después de
# optimizaciones o para generar datos de rendimiento reproducibles.
#
# Uso:
#   ./scripts/benchmark.sh              # Benchmark completo
#   ./scripts/benchmark.sh --quick      # Benchmark rápido (menos rondas)
#   ./scripts/benchmark.sh --compare    # Compara naive vs optimizado
#
# Requisitos:
#   - Go 1.22+
#   - Linux con kernel >= 5.10
#   - Ejecutar como root (sudo)
#   - clang instalado (para compilar BPF)
# =============================================================================

set -euo pipefail

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuración
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
GO_DIR="$PROJECT_DIR/go"
EJERCICIO_DIR="$PROJECT_DIR/ejercicio/solucion/go"
RESULTS_DIR="$PROJECT_DIR/results"

# Parámetros por defecto
ROUNDS=50
REPEAT=10000
MODE="full"

# =============================================================================
# Funciones
# =============================================================================

usage() {
    echo "Uso: $0 [--quick|--full|--compare] [--rounds N] [--repeat N]"
    echo ""
    echo "Modos:"
    echo "  --quick     Benchmark rápido (10 rondas, 1000 repeticiones)"
    echo "  --full      Benchmark completo (50 rondas, 10000 repeticiones) [default]"
    echo "  --compare   Ejecuta ambos programas y compara resultados"
    echo ""
    echo "Opciones:"
    echo "  --rounds N  Número de rondas (default: 50)"
    echo "  --repeat N  Repeticiones por ronda (default: 10000)"
    echo "  --help      Muestra esta ayuda"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_requirements() {
    log_info "Verificando requisitos..."

    # Verificar root
    if [ "$EUID" -ne 0 ]; then
        log_error "Este script debe ejecutarse como root (sudo)"
        exit 1
    fi

    # Verificar Go
    if ! command -v go &> /dev/null; then
        log_error "Go no encontrado. Instala Go 1.22+"
        exit 1
    fi
    local go_version
    go_version=$(go version | awk '{print $3}' | sed 's/go//')
    log_success "Go $go_version encontrado"

    # Verificar clang
    if ! command -v clang &> /dev/null; then
        log_error "clang no encontrado. Instala clang/LLVM"
        exit 1
    fi
    log_success "clang encontrado: $(clang --version | head -1)"

    # Verificar kernel
    local kernel_version
    kernel_version=$(uname -r | cut -d. -f1-2)
    log_success "Kernel: $(uname -r)"

    echo ""
}

build_program() {
    local dir=$1
    local name=$2

    log_info "Compilando $name en $dir..."

    cd "$dir"

    # Generar bindings de BPF
    if ! go generate ./... 2>&1; then
        log_error "go generate falló para $name"
        return 1
    fi

    # Compilar
    if ! go build -o "bench-$name" . 2>&1; then
        log_error "go build falló para $name"
        return 1
    fi

    log_success "$name compilado → bench-$name"
    cd - > /dev/null
}

run_benchmark() {
    local dir=$1
    local name=$2
    local output_file=$3

    log_info "Ejecutando benchmark: $name (rounds=$ROUNDS, repeat=$REPEAT)..."
    echo ""

    cd "$dir"
    ./bench-"$name" -rounds "$ROUNDS" -repeat "$REPEAT" | tee "$output_file"
    echo ""

    cd - > /dev/null
    log_success "Resultados guardados en: $output_file"
}

# =============================================================================
# Parsear argumentos
# =============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            MODE="quick"
            ROUNDS=10
            REPEAT=1000
            shift
            ;;
        --full)
            MODE="full"
            ROUNDS=50
            REPEAT=10000
            shift
            ;;
        --compare)
            MODE="compare"
            shift
            ;;
        --rounds)
            ROUNDS="$2"
            shift 2
            ;;
        --repeat)
            REPEAT="$2"
            shift 2
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            log_error "Opción desconocida: $1"
            usage
            exit 1
            ;;
    esac
done

# =============================================================================
# Main
# =============================================================================

echo "═══════════════════════════════════════════════════════════════"
echo "  Capítulo 18 — Benchmark de programas eBPF"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  Modo: $MODE | Rondas: $ROUNDS | Repeticiones: $REPEAT"
echo ""

check_requirements

# Crear directorio de resultados
mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

case $MODE in
    "full"|"quick")
        # Benchmark del programa principal
        build_program "$GO_DIR" "xdp"
        run_benchmark "$GO_DIR" "xdp" "$RESULTS_DIR/bench_xdp_${TIMESTAMP}.txt"
        ;;

    "compare")
        # Benchmark comparativo: programa principal vs ejercicio optimizado
        log_info "Modo comparativo: ejecutando ambas versiones..."
        echo ""

        # Programa principal (baseline)
        build_program "$GO_DIR" "xdp"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "  BASELINE: Programa XDP estándar"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        run_benchmark "$GO_DIR" "xdp" "$RESULTS_DIR/bench_baseline_${TIMESTAMP}.txt"

        echo ""
        echo ""

        # Programa optimizado (ejercicio)
        build_program "$EJERCICIO_DIR" "optimized"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "  OPTIMIZADO: Programa XDP con técnicas del Cap 18"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        run_benchmark "$EJERCICIO_DIR" "optimized" "$RESULTS_DIR/bench_optimized_${TIMESTAMP}.txt"

        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "  Compara los resultados en:"
        echo "    Baseline:   $RESULTS_DIR/bench_baseline_${TIMESTAMP}.txt"
        echo "    Optimizado: $RESULTS_DIR/bench_optimized_${TIMESTAMP}.txt"
        echo "═══════════════════════════════════════════════════════════════"
        ;;
esac

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Benchmark completado."
echo "  Resultados en: $RESULTS_DIR/"
echo "═══════════════════════════════════════════════════════════════"
