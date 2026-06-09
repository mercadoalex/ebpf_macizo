#!/usr/bin/env bash
#
# check-env.sh — Verifica que el entorno de desarrollo está listo para eBPF
#
# Uso:
#   chmod +x check-env.sh
#   ./check-env.sh
#
# Este script verifica:
#   1. Versión del kernel (mínimo 5.15, recomendado 6.1+)
#   2. clang/LLVM instalado y funcional
#   3. bpftool disponible
#   4. Go instalado (para cilium/ebpf)
#   5. Headers del kernel disponibles
#   6. Soporte BPF en el kernel
#

set -euo pipefail

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m' # Sin color

PASS=0
WARN=0
FAIL=0

pass() {
    echo -e "  ${GREEN}✓${NC} $1"
    ((PASS++))
}

warn() {
    echo -e "  ${YELLOW}⚠${NC} $1"
    ((WARN++))
}

fail() {
    echo -e "  ${RED}✗${NC} $1"
    ((FAIL++))
}

header() {
    echo -e "\n${BOLD}$1${NC}"
}

# --- Versión mínima requerida ---
MIN_KERNEL_MAJOR=5
MIN_KERNEL_MINOR=15
REC_KERNEL_MAJOR=6
REC_KERNEL_MINOR=1
MIN_CLANG_VERSION=12
MIN_GO_MAJOR=1
MIN_GO_MINOR=21

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════╗"
echo "║  eBPF: Macizo y Conciso — Check de Entorno  ║"
echo "╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ============================================================
# 1. KERNEL
# ============================================================
header "[1/6] Kernel Linux"

KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

if [[ $KERNEL_MAJOR -gt $REC_KERNEL_MAJOR ]] || \
   [[ $KERNEL_MAJOR -eq $REC_KERNEL_MAJOR && $KERNEL_MINOR -ge $REC_KERNEL_MINOR ]]; then
    pass "Kernel $KERNEL_VERSION (>= $REC_KERNEL_MAJOR.$REC_KERNEL_MINOR recomendado)"
elif [[ $KERNEL_MAJOR -gt $MIN_KERNEL_MAJOR ]] || \
     [[ $KERNEL_MAJOR -eq $MIN_KERNEL_MAJOR && $KERNEL_MINOR -ge $MIN_KERNEL_MINOR ]]; then
    warn "Kernel $KERNEL_VERSION (mínimo $MIN_KERNEL_MAJOR.$MIN_KERNEL_MINOR cumplido, pero se recomienda >= $REC_KERNEL_MAJOR.$REC_KERNEL_MINOR)"
else
    fail "Kernel $KERNEL_VERSION (se requiere >= $MIN_KERNEL_MAJOR.$MIN_KERNEL_MINOR, se recomienda >= $REC_KERNEL_MAJOR.$REC_KERNEL_MINOR)"
fi

# ============================================================
# 2. CLANG / LLVM
# ============================================================
header "[2/6] Clang / LLVM"

if command -v clang &>/dev/null; then
    CLANG_VER=$(clang --version | head -1 | grep -oP '\d+' | head -1)
    if [[ $CLANG_VER -ge $MIN_CLANG_VERSION ]]; then
        pass "clang versión $CLANG_VER (>= $MIN_CLANG_VERSION)"
    else
        warn "clang versión $CLANG_VER (se recomienda >= $MIN_CLANG_VERSION)"
    fi
else
    fail "clang no encontrado. Instala con: apt install clang llvm"
fi

if command -v llc &>/dev/null; then
    LLC_VER=$(llc --version 2>&1 | grep -oP 'version \K\d+' | head -1)
    pass "llc disponible (versión $LLC_VER)"
else
    fail "llc no encontrado. Instala con: apt install llvm"
fi

# ============================================================
# 3. BPFTOOL
# ============================================================
header "[3/6] bpftool"

if command -v bpftool &>/dev/null; then
    BPFTOOL_VER=$(bpftool version 2>&1 | head -1)
    pass "bpftool disponible ($BPFTOOL_VER)"
else
    fail "bpftool no encontrado. Instala con: apt install linux-tools-\$(uname -r)"
fi

# ============================================================
# 4. GO
# ============================================================
header "[4/6] Go"

if command -v go &>/dev/null; then
    GO_VER=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+')
    GO_MAJOR=$(echo "$GO_VER" | cut -d. -f1)
    GO_MINOR=$(echo "$GO_VER" | cut -d. -f2)
    if [[ $GO_MAJOR -ge $MIN_GO_MAJOR && $GO_MINOR -ge $MIN_GO_MINOR ]]; then
        pass "Go versión $GO_VER (>= $MIN_GO_MAJOR.$MIN_GO_MINOR)"
    else
        warn "Go versión $GO_VER (se recomienda >= $MIN_GO_MAJOR.$MIN_GO_MINOR para cilium/ebpf)"
    fi
else
    fail "Go no encontrado. Instala desde: https://go.dev/dl/"
fi

# ============================================================
# 5. HEADERS DEL KERNEL
# ============================================================
header "[5/6] Headers del kernel"

HEADER_PATH="/lib/modules/$(uname -r)/build"
if [[ -d "$HEADER_PATH" ]]; then
    pass "Headers disponibles en $HEADER_PATH"
else
    # Intentar ruta alternativa
    if [[ -d "/usr/src/linux-headers-$(uname -r)" ]]; then
        pass "Headers disponibles en /usr/src/linux-headers-$(uname -r)"
    else
        fail "Headers del kernel no encontrados. Instala con: apt install linux-headers-\$(uname -r)"
    fi
fi

# ============================================================
# 6. SOPORTE BPF EN EL KERNEL
# ============================================================
header "[6/6] Soporte BPF en el kernel"

if [[ -d /sys/fs/bpf ]]; then
    pass "/sys/fs/bpf montado (bpffs disponible)"
else
    warn "/sys/fs/bpf no montado. Monta con: mount -t bpf bpf /sys/fs/bpf"
fi

if [[ -f /proc/config.gz ]]; then
    if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_BPF=y"; then
        pass "CONFIG_BPF=y habilitado en el kernel"
    fi
    if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_BPF_SYSCALL=y"; then
        pass "CONFIG_BPF_SYSCALL=y habilitado"
    fi
    if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_DEBUG_INFO_BTF=y"; then
        pass "CONFIG_DEBUG_INFO_BTF=y habilitado (BTF/CO-RE disponible)"
    else
        warn "CONFIG_DEBUG_INFO_BTF no detectado (BTF/CO-RE podría no funcionar)"
    fi
elif [[ -f "/boot/config-$(uname -r)" ]]; then
    KCONFIG="/boot/config-$(uname -r)"
    if grep -q "CONFIG_BPF=y" "$KCONFIG"; then
        pass "CONFIG_BPF=y habilitado en el kernel"
    fi
    if grep -q "CONFIG_BPF_SYSCALL=y" "$KCONFIG"; then
        pass "CONFIG_BPF_SYSCALL=y habilitado"
    fi
    if grep -q "CONFIG_DEBUG_INFO_BTF=y" "$KCONFIG"; then
        pass "CONFIG_DEBUG_INFO_BTF=y habilitado (BTF/CO-RE disponible)"
    else
        warn "CONFIG_DEBUG_INFO_BTF no detectado (BTF/CO-RE podría no funcionar)"
    fi
else
    warn "No se pudo leer la configuración del kernel (/proc/config.gz o /boot/config-*)"
fi

# ============================================================
# RESUMEN
# ============================================================
echo ""
echo -e "${BOLD}═══════════════════════════════════${NC}"
echo -e "${BOLD} Resumen${NC}"
echo -e "${BOLD}═══════════════════════════════════${NC}"
echo -e "  ${GREEN}✓ Pasaron:${NC}     $PASS"
echo -e "  ${YELLOW}⚠ Advertencias:${NC} $WARN"
echo -e "  ${RED}✗ Fallaron:${NC}    $FAIL"
echo ""

if [[ $FAIL -eq 0 && $WARN -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}🤘 Entorno perfecto. Estás listo para eBPF.${NC}"
    exit 0
elif [[ $FAIL -eq 0 ]]; then
    echo -e "${YELLOW}${BOLD}⚡ Entorno funcional con advertencias. Puedes continuar, pero revisa los warnings.${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}💀 Hay problemas que corregir antes de continuar.${NC}"
    exit 1
fi
