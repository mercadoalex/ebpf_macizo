# Entorno de Desarrollo — eBPF: Macizo y Conciso

Este directorio contiene todo lo necesario para configurar un entorno de desarrollo funcional donde ejecutar los ejemplos y ejercicios del libro.

## Requisitos del entorno

Para trabajar con eBPF necesitas:

| Herramienta | Versión mínima | Recomendada | Propósito |
|-------------|---------------|-------------|-----------|
| Kernel Linux | 5.15 LTS | 6.1 LTS | Soporte de features BPF modernas |
| clang/LLVM | 12 | 15+ | Compilar programas BPF (C → bytecode) |
| bpftool | — | última | Inspeccionar y gestionar programas BPF |
| Go | 1.21 | 1.22+ | User space con cilium/ebpf |
| Headers del kernel | misma que kernel | — | Compilación de programas BPF |

## Opciones de entorno

Tienes dos caminos para montar tu lab:

### Opción 1: Vagrant (recomendada para empezar)

Una VM completa con todo preinstalado. Funciona en cualquier sistema operativo (macOS, Windows, Linux).

**Requisitos previos:**
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads) instalado
- [Vagrant](https://developer.hashicorp.com/vagrant/downloads) instalado

**Pasos:**

```bash
cd code/setup/

# Levantar la VM (primera vez tarda ~10 min)
vagrant up

# Reiniciar para arrancar con kernel 6.1
vagrant reload

# Conectarte a la VM
vagrant ssh

# Ya estás dentro. El repo está en /vagrant/
cd /vagrant/code
./setup/check-env.sh
```

**Comandos útiles:**

```bash
vagrant halt      # Apagar la VM
vagrant up        # Encender la VM
vagrant destroy   # Eliminar la VM por completo
vagrant ssh       # Conectarte
```

### Opción 2: Docker (alternativa ligera)

Un contenedor para **compilar** programas BPF y código Go. Más rápido de montar, pero con limitaciones para ejecución.

**Para compilar solamente:**

```bash
cd code/setup/

# Construir la imagen
docker build -t ebpf-macizo .

# Ejecutar (monta el repo completo)
docker run -it --rm -v $(pwd)/../..:/workspace ebpf-macizo
```

**Para compilar Y ejecutar** (requiere host Linux con kernel >= 5.15):

```bash
docker run -it --rm --privileged \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v $(pwd)/../..:/workspace \
  ebpf-macizo
```

> 🔥 **Advertencia**: El modo `--privileged` da acceso completo al kernel del host. Úsalo solo en tu máquina de desarrollo, nunca en producción.

### ¿Cuál elegir?

| Criterio | Vagrant | Docker |
|----------|---------|--------|
| Funciona en macOS/Windows | ✅ | Solo compilación |
| Ejecuta programas BPF | ✅ | Solo en Linux con --privileged |
| Tiempo de setup | ~10 min | ~3 min |
| Consumo de recursos | Alto (VM completa) | Bajo |
| Kernel controlado | ✅ (6.1 LTS) | Usa el del host |

**Recomendación:** Si estás en macOS o Windows, usa Vagrant. Si estás en Linux con kernel >= 5.15, Docker con `--privileged` es más ágil.

## Verificar tu entorno

Independientemente de la opción que elijas, ejecuta el script de verificación:

```bash
./check-env.sh
```

El script verifica:
1. **Kernel** — versión >= 5.15 (recomendado 6.1+)
2. **clang/LLVM** — compilador BPF disponible
3. **bpftool** — herramienta de gestión BPF
4. **Go** — lenguaje para user space (cilium/ebpf)
5. **Headers del kernel** — necesarios para compilar
6. **Soporte BPF** — CONFIG_BPF, CONFIG_BPF_SYSCALL, CONFIG_DEBUG_INFO_BTF

Si todo pasa en verde, estás listo para el Capítulo 3.

## Solución de problemas

### "Kernel demasiado viejo"

Si tu kernel es anterior a 5.15:
- **Ubuntu/Debian:** `sudo apt install linux-image-generic-hwe-22.04`
- **Fedora:** `sudo dnf upgrade --refresh && sudo dnf install kernel`
- **O usa la VM** que ya tiene kernel 6.1

### "clang no encontrado"

```bash
# Ubuntu/Debian
sudo apt install clang llvm

# Fedora
sudo dnf install clang llvm
```

### "bpftool no encontrado"

```bash
# Ubuntu/Debian
sudo apt install linux-tools-$(uname -r)

# Si no existe para tu kernel, compilar desde fuentes:
git clone --depth 1 https://github.com/libbpf/bpftool.git
cd bpftool/src && make && sudo make install
```

### "Go no encontrado"

Descarga desde [go.dev/dl](https://go.dev/dl/):

```bash
wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### "CONFIG_DEBUG_INFO_BTF no habilitado"

BTF es necesario a partir del Capítulo 15 (CO-RE). Si tu kernel no lo tiene:
- Actualiza a un kernel de distribución reciente (Ubuntu 22.04+ lo incluye por defecto)
- O usa la VM que ya lo tiene habilitado

## Estructura de este directorio

```
code/setup/
├── Vagrantfile     # Definición de la VM (Ubuntu + kernel 6.1 + herramientas)
├── Dockerfile      # Contenedor para compilación (alternativa ligera)
├── check-env.sh    # Script de verificación del entorno
└── README.md       # Este archivo
```
