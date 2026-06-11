# Ejercicio — Capítulo 7: Diagnostica y corrige al verifier

📋 **Nivel:** Intermedio  
📚 **Conceptos previos:** Maps (Cap 6), Verifier (este capítulo), programas XDP  
🖥️ **Entorno:** Lab con kernel 6.1+, clang, Go 1.22+, cilium/ebpf configurado (Cap 3)

## 🎯 Problema

Se te proporciona un programa XDP que **cuenta paquetes TCP por IP de origen** y almacena los primeros bytes del payload. El programa tiene funcionalidad correcta... pero el **verifier lo rechaza con 3 errores distintos**.

Tu misión: **diagnosticar y corregir cada error** para que el programa pase la verificación y se cargue exitosamente.

## 📂 Estructura

```
esqueleto/
├── verifier_challenge.bpf.c   ← Programa BPF con 3 errores (CORREGIR ESTE)
├── main.go                    ← Loader en Go (no tocar)
├── go.mod
└── go.sum

solucion/
├── verifier_challenge.bpf.c   ← Versión corregida (NO VER HASTA INTENTAR)
├── main.go                    ← Loader completo con stats
├── go.mod
└── go.sum
```

## 🔧 Cómo ejecutar

```bash
cd esqueleto/

# 1. Intentar compilar y cargar (va a fallar)
go generate
go build -o verifier-challenge
sudo ./verifier-challenge

# 2. Leer los errores del verifier
# 3. Corregir verifier_challenge.bpf.c
# 4. Repetir hasta que los 3 errores estén resueltos
```

## 🕵️ Los 3 errores

El programa tiene exactamente **3 errores** que hacen que el verifier lo rechace:

| # | Tipo de error | Pista |
|---|---------------|-------|
| 1 | Acceso inseguro a memoria del paquete | ¿Qué pasa si el paquete tiene 10 bytes? `eth->h_proto` explota. |
| 2 | Posible dereferencia de puntero NULL | ¿Qué retorna `bpf_map_lookup_elem` si la key no existe? |
| 3 | Datos no inicializados en el stack | ¿Cuántos bytes tiene `struct packet_count`? ¿Cuántos inicializaste? |

## 💡 Pistas progresivas

### Pista nivel 1 (suave)
- El verifier necesita **pruebas matemáticas** de que tus accesos a memoria son seguros.
- Cada puntero a datos del paquete necesita un bounds check **antes** de usarlo.
- Los helpers de map pueden fallar — el verifier lo sabe.
- Toda la memoria que pasas a una helper function debe estar inicializada.

### Pista nivel 2 (más directa)
- **Error 1:** Busca dónde accedes a `eth->h_proto`. ¿El verifier sabe que `eth` apunta a memoria válida dentro del paquete?
- **Error 2:** Busca `bpf_map_lookup_elem`. ¿Qué haces con el resultado si es NULL? Estás accediendo `counter->count` sin verificar.
- **Error 3:** Busca la `struct packet_count new_entry`. Son 272 bytes (8 + 8 + 256). ¿Inicializaste el campo `last_payload` entero?

### Pista nivel 3 (casi la respuesta)
- **Error 1:** Agrega `if ((void *)(eth + 1) > data_end) return XDP_PASS;` antes de acceder a cualquier campo de `eth`.
- **Error 2:** Verifica `if (!counter)` *antes* de dereferenciarlo, o reorganiza el código para que el update solo ocurra cuando counter no es NULL.
- **Error 3:** Inicializa la struct con `struct packet_count new_entry = {};` — eso pone todos los 272 bytes a cero.

## ✅ Criterios de éxito

- [ ] Identificar los 3 errores del verifier (escribir qué mensaje darías tú si fueras el verifier)
- [ ] Corregir cada error sin cambiar la funcionalidad del programa
- [ ] El programa compila sin warnings: `go generate` exitoso
- [ ] El programa se carga sin errores del verifier: `sudo ./verifier-challenge` muestra "✅ Programa cargado"
- [ ] El programa se adjunta a una interfaz XDP exitosamente
- [ ] Al generar tráfico TCP (`curl localhost`), el programa cuenta paquetes

## 📝 Qué aprendes

1. **Bounds checking** — Cómo demostrar al verifier que tus accesos a paquetes son seguros
2. **Null safety** — Por qué siempre debes verificar retornos de helpers que pueden fallar
3. **Inicialización completa** — Por qué el verifier protege contra information disclosure del stack del kernel. `struct packet_count` tiene 272 bytes, y si solo inicializas `count` y `bytes` (16 bytes), los 256 restantes de `last_payload` pueden contener basura del stack del kernel.

## 🏁 Cuando termines

Compara tu solución con `solucion/verifier_challenge.bpf.c`. No hay una única forma correcta — cualquier solución que pase el verifier y cuente paquetes es válida.

### Reto extra

Si corregiste los 3 errores y el programa carga, intenta esta variante: en vez de copiar payload al stack (que consume 256 bytes de tus preciosos 512), usa un per-CPU array map como scratch buffer. ¿Cuántos bytes de stack liberas?
