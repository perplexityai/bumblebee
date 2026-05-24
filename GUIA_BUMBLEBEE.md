# Bumblebee — Guía de uso para principiantes

**Bumblebee** es una herramienta de seguridad que escanea tu computadora en modo de solo lectura y te dice qué paquetes, extensiones y configuraciones de herramientas de desarrollo tienes instaladas. Sirve para detectar si algún paquete comprometido (con malware de cadena de suministro) está presente en tu máquina.

> No modifica ni borra nada. Solo lee y reporta.

---

## Índice

1. [Windows](#windows)
2. [Linux](#linux)
3. [macOS](#macos)
4. [Entender los resultados](#entender-los-resultados)
5. [Comandos de referencia rápida](#referencia-rápida)

---

## Windows

### Paso 1 — Instalar Go

Bumblebee está escrito en Go, así que necesitas tenerlo instalado.

1. Abre una terminal (busca **PowerShell** en el menú Inicio)
2. Escribe el siguiente comando y presiona Enter:

```powershell
winget install --id GoLang.Go --silent --accept-package-agreements --accept-source-agreements
```

3. Cuando termine, **cierra y vuelve a abrir** la terminal para que el PATH se actualice
4. Verifica que Go quedó instalado:

```powershell
go version
```

Deberías ver algo como: `go version go1.26.3 windows/amd64`

---

### Paso 2 — Instalar Bumblebee

Tienes dos opciones:

#### Opción A — Instalar directamente desde internet (recomendado)

```powershell
go install github.com/perplexityai/bumblebee/cmd/bumblebee@latest
```

Esto descarga y compila Bumblebee automáticamente. El ejecutable quedará en `%USERPROFILE%\go\bin\bumblebee.exe`.

#### Opción B — Compilar desde el código fuente (si ya tienes el código)

Si ya tienes el repositorio en tu equipo (por ejemplo en `E:\Fenixoft\Perplexity`):

```powershell
cd E:\Fenixoft\Perplexity
go build -o bumblebee.exe ./cmd/bumblebee
```

---

### Paso 3 — Verificar que funciona

```powershell
bumblebee selftest
```

Si ves `selftest OK`, todo está listo.

---

### Paso 4 — Tu primer escaneo

#### Escaneo básico (liviano, recomendado para empezar)

```powershell
bumblebee scan --profile baseline
```

Escanea tus herramientas globales: extensiones de VS Code/Cursor, configuraciones de MCP (Claude), módulos de Go, extensiones de Chrome/Edge, etc.

#### Ver qué rutas va a escanear (sin escanear aún)

```powershell
bumblebee roots --profile baseline
```

#### Guardar los resultados en un archivo

```powershell
bumblebee scan --profile baseline > inventario.ndjson
```

#### Escanear tus proyectos de código

```powershell
bumblebee scan --profile project --root "$env:USERPROFILE\code" --root "$env:USERPROFILE\Projects"
```

#### Escaneo de incidente (búsqueda profunda en toda tu carpeta de usuario)

```powershell
bumblebee scan --profile deep --root "$env:USERPROFILE" --max-duration 15m > escaneo_profundo.ndjson
```

> Este escaneo puede tardar varios minutos dependiendo del tamaño de tu disco.

---

### Paso 5 — Verificar contra amenazas conocidas

Bumblebee incluye un catálogo de amenazas reales. Puedes usarlo así:

```powershell
bumblebee scan --profile deep --root "$env:USERPROFILE" --exposure-catalog .\threat_intel\ --findings-only
```

Si no aparece nada, no se encontraron coincidencias con amenazas conocidas. Si aparece algo, el resultado indicará qué paquete y qué advisory lo reporta.

---

## Linux

### Paso 1 — Instalar Go

Abre una terminal y ejecuta:

```bash
# Descargar e instalar Go (versión 1.25 o superior)
wget https://go.dev/dl/go1.26.3.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.26.3.linux-amd64.tar.gz
```

Luego agrega Go al PATH. Abre `~/.bashrc` o `~/.zshrc` y agrega al final:

```bash
export PATH=$PATH:/usr/local/go/bin
```

Recarga el perfil:

```bash
source ~/.bashrc   # o source ~/.zshrc si usas zsh
```

Verifica la instalación:

```bash
go version
```

---

### Paso 2 — Instalar Bumblebee

```bash
go install github.com/perplexityai/bumblebee/cmd/bumblebee@latest
```

El ejecutable quedará en `~/go/bin/bumblebee`. Asegúrate de que `~/go/bin` esté en tu PATH:

```bash
export PATH=$PATH:~/go/bin
```

(También puedes agregar esta línea a tu `~/.bashrc`)

---

### Paso 3 — Verificar que funciona

```bash
bumblebee selftest
```

Deberías ver: `selftest OK (3 findings in Xms)`

---

### Paso 4 — Tu primer escaneo

#### Escaneo básico

```bash
bumblebee scan --profile baseline
```

#### Ver rutas que se van a escanear

```bash
bumblebee roots --profile baseline
```

#### Guardar resultados

```bash
bumblebee scan --profile baseline > inventario.ndjson
```

#### Escanear tus proyectos

```bash
bumblebee scan --profile project \
  --root "$HOME/code" \
  --root "$HOME/proyectos"
```

#### Escaneo profundo de tu carpeta de usuario

```bash
bumblebee scan --profile deep \
  --root "$HOME" \
  --max-duration 15m \
  > escaneo_profundo.ndjson
```

---

### Paso 5 — Verificar contra amenazas conocidas

Si clonaste el repositorio y tienes la carpeta `threat_intel/`:

```bash
bumblebee scan --profile deep \
  --root "$HOME" \
  --exposure-catalog ./threat_intel/ \
  --findings-only
```

---

## macOS

### Paso 1 — Instalar Go

#### Opción A — Con Homebrew (recomendado si ya tienes Homebrew)

```bash
brew install go
```

#### Opción B — Instalador oficial

1. Abre Safari y ve a **https://go.dev/dl/**
2. Descarga el instalador `.pkg` para macOS (versión arm64 para Mac con chip Apple M1/M2/M3/M4, o amd64 para Mac Intel)
3. Abre el `.pkg` descargado y sigue los pasos del instalador

Verifica:

```bash
go version
```

---

### Paso 2 — Instalar Bumblebee

```bash
go install github.com/perplexityai/bumblebee/cmd/bumblebee@latest
```

El ejecutable quedará en `~/go/bin/bumblebee`.

Si el comando `bumblebee` no se reconoce, agrega esto a tu `~/.zshrc` (macOS usa zsh por defecto):

```bash
export PATH=$PATH:~/go/bin
source ~/.zshrc
```

---

### Paso 3 — Verificar que funciona

```bash
bumblebee selftest
```

---

### Paso 4 — Tu primer escaneo

#### Escaneo básico

```bash
bumblebee scan --profile baseline
```

Escanea: extensiones de VS Code/Cursor, configuraciones de Claude (en `~/Library/Application Support/Claude`), módulos de Go, paquetes de Homebrew, extensiones de Chrome/Safari/Firefox, paquetes de Python/Ruby/npm.

#### Ver rutas que se van a escanear

```bash
bumblebee roots --profile baseline
```

#### Guardar resultados

```bash
bumblebee scan --profile baseline > inventario.ndjson
```

#### Escanear tus proyectos

```bash
bumblebee scan --profile project \
  --root "$HOME/code" \
  --root "$HOME/Developer"
```

#### Escaneo profundo de tu carpeta de usuario

```bash
bumblebee scan --profile deep \
  --root "$HOME" \
  --max-duration 15m \
  > escaneo_profundo.ndjson
```

#### Escanear TODOS los usuarios del Mac (requiere permisos de administrador)

```bash
sudo bumblebee scan --profile baseline --all-users
```

---

### Paso 5 — Verificar contra amenazas conocidas

```bash
bumblebee scan --profile deep \
  --root "$HOME" \
  --exposure-catalog ./threat_intel/ \
  --findings-only
```

---

## Entender los resultados

Los resultados se muestran en formato **NDJSON** (una línea JSON por cada paquete encontrado). Así luce un resultado típico:

```json
{
  "record_type": "package",
  "ecosystem": "npm",
  "package_name": "@tanstack/query-core",
  "version": "5.59.20",
  "source_type": "pnpm-lockfile",
  "source_file": "/Users/tu-usuario/code/mi-app/pnpm-lock.yaml",
  "confidence": "high"
}
```

### Campos importantes

| Campo | Qué significa |
|---|---|
| `record_type` | `package` = paquete encontrado, `finding` = amenaza detectada |
| `ecosystem` | De dónde viene: `npm`, `pypi`, `go`, `mcp`, `editor-extension`, etc. |
| `package_name` | Nombre del paquete |
| `version` | Versión instalada |
| `source_file` | Archivo donde se encontró (lockfile, manifest, etc.) |
| `confidence` | `high` = certero, `medium` = probable, `low` = referencia |

### Si aparece un `finding` (amenaza detectada)

```json
{
  "record_type": "finding",
  "severity": "critical",
  "catalog_name": "example-pkg 1.2.3 (compromised release)",
  "package_name": "example-pkg",
  "version": "1.2.3",
  "evidence": "exact name+version match"
}
```

Esto significa que tienes instalado un paquete que coincide con una amenaza conocida. Revisa el campo `catalog_name` para saber más sobre el advisory.

### Leer los resultados de forma legible

Instala `jq` para filtrar y leer los resultados más fácilmente:

```bash
# Solo ver paquetes npm
cat inventario.ndjson | jq 'select(.ecosystem == "npm")'

# Solo ver amenazas detectadas
cat inventario.ndjson | jq 'select(.record_type == "finding")'

# Contar paquetes por ecosistema
cat inventario.ndjson | jq -r '.ecosystem' | sort | uniq -c | sort -rn
```

En Windows con PowerShell:

```powershell
# Ver solo los findings (amenazas)
Get-Content inventario.ndjson | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.record_type -eq "finding" }
```

---

## Referencia rápida

| Comando | Para qué sirve |
|---|---|
| `bumblebee selftest` | Verifica que la instalación funciona |
| `bumblebee version` | Muestra la versión instalada |
| `bumblebee roots --profile baseline` | Lista las rutas que escaneará sin escanear |
| `bumblebee scan --profile baseline` | Escaneo liviano de herramientas globales |
| `bumblebee scan --profile project --root ~/code` | Escaneo de tus proyectos |
| `bumblebee scan --profile deep --root ~` | Escaneo profundo de toda tu carpeta |
| `bumblebee scan ... --exposure-catalog ./threat_intel/` | Verifica contra amenazas conocidas |
| `bumblebee scan ... --findings-only` | Solo muestra amenazas (no el inventario completo) |
| `bumblebee scan ... --ecosystem npm,pypi` | Filtra por ecosistema específico |
| `bumblebee scan ... --max-duration 10m` | Limita la duración del escaneo |

---

> **Repositorio oficial:** https://github.com/perplexityai/bumblebee  
> **Licencia:** Apache 2.0  
> **Versión:** v0.1.1
