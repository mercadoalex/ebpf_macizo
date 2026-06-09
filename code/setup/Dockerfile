# Dockerfile para "eBPF: Macizo y Conciso"
# Alternativa ligera para compilación de programas BPF y loaders en Go.
#
# NOTA: Este contenedor sirve para COMPILAR programas BPF y código user space.
# Para EJECUTAR programas BPF necesitas un kernel con soporte (la VM o tu host Linux).
#
# Uso:
#   docker build -t ebpf-macizo .
#   docker run -it --rm -v $(pwd)/../..:/workspace ebpf-macizo
#
# Para ejecución con acceso al kernel del host (requiere Linux con kernel >= 5.15):
#   docker run -it --rm --privileged \
#     -v /sys/kernel/debug:/sys/kernel/debug \
#     -v /sys/fs/bpf:/sys/fs/bpf \
#     -v $(pwd)/../..:/workspace \
#     ebpf-macizo
#

FROM ubuntu:22.04

LABEL maintainer="eBPF: Macizo y Conciso"
LABEL description="Entorno de compilación y desarrollo para los ejemplos del libro"

ENV DEBIAN_FRONTEND=noninteractive
ENV GO_VERSION=1.22.4

# Herramientas de compilación BPF
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
      clang \
      llvm \
      libelf-dev \
      libbpf-dev \
      linux-headers-generic \
      build-essential \
      pkg-config \
      make \
      gcc-multilib \
      git \
      wget \
      ca-certificates \
      && rm -rf /var/lib/apt/lists/*

# bpftool (compilado desde fuentes para máxima compatibilidad)
RUN git clone --depth 1 https://github.com/libbpf/bpftool.git /tmp/bpftool && \
    cd /tmp/bpftool/src && \
    make -j$(nproc) && \
    make install && \
    rm -rf /tmp/bpftool

# Go
RUN wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/root/go"
ENV PATH="${GOPATH}/bin:${PATH}"

WORKDIR /workspace

# Verificación rápida al construir la imagen
RUN echo "=== Verificación del entorno ===" && \
    clang --version | head -1 && \
    llc --version | head -1 && \
    bpftool version && \
    go version && \
    echo "=== Entorno listo ==="

CMD ["/bin/bash"]
