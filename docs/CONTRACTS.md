# Contratos de datos de EnvFingerprint v1

Este documento define los tres documentos JSON que constituyen el contrato
público de EnvFingerprint:

1. **Huella de entorno** (`fingerprint json`, esquema 1) — producida por `inspect`.
2. **Reglas de proyecto** (`.envfingerprint.json`, esquema 1) — escritas por cada proyecto.
3. **Resultado de comparación** (`diff json`, esquema 1) — producido por `diff --json`.

Todos los valores de ejemplo son ficticios. Los esquemas JSON formales están en
`schemas/` y sirven para validación en editores y CI externo; la validación
autoritativa la implementa `internal/model` (sin dependencias externas).

---

## 1. Huella de entorno

```json
{
  "schema": 1,
  "tool": { "name": "envfingerprint", "version": "0.1.0" },
  "environment": {
    "profile": "ci",
    "os": "linux",
    "arch": "amd64",
    "container": false,
    "ci": true
  },
  "runtimes": [
    { "name": "go", "version": "1.23.2", "source": "go version" },
    { "name": "node", "version": "20.9.0", "source": "node --version" }
  ],
  "files": [
    { "path": "go.mod", "kind": "config", "present": true },
    { "path": "go.sum", "kind": "lockfile", "present": true, "digest": "sha256:2cf24..." },
    { "path": "package-lock.json", "kind": "lockfile", "present": false }
  ],
  "variables": [
    { "key": "NODE_ENV", "state": "present", "sensitive": false, "compare": "value", "value": "production" },
    { "key": "DATABASE_URL", "state": "present", "sensitive": true, "compare": "presence" },
    { "key": "CACHE_DIR", "state": "absent", "sensitive": false, "compare": "presence" }
  ],
  "meta": { "hashAlgorithm": "sha256-canonical-json-v1" },
  "fingerprint": "sha256:9b1c0f..."
}
```

### Campos

| Campo | Tipo | Clase | En hash | Descripción y normalización |
|---|---|---|---|---|
| `schema` | int | **obligatorio** | no | Versión del esquema. Actual: `1`. |
| `tool.name` | string | obligatorio | no | Siempre `"envfingerprint"`. |
| `tool.version` | string | obligatorio | no | Versión semver de la herramienta (`MAJOR.MINOR.PATCH`, sin prefijo `v`). Informativo: dos huellas generadas por distintas versiones de la herramienta pueden no ser comparables (ver §4). |
| `environment.profile` | enum | obligatorio | sí | `local` \| `container` \| `ci` \| `unknown`. Perfil inferido del entorno. |
| `environment.os` | string | obligatorio | sí | Minúsculas, vocabulario de `GOOS`: `linux`, `darwin`, `windows`, … |
| `environment.arch` | string | obligatorio | sí | Minúsculas, vocabulario de `GOARCH`: `amd64`, `arm64`, … |
| `environment.container` | bool | obligatorio | sí | Heurística de contenedor (presencia de `/.dockerenv` o cgroup); documentada como heurística, no garantía. |
| `environment.ci` | bool | obligatorio | sí | Detección por variables `CI`, `GITHUB_ACTIONS`, etc. |
| `runtimes[]` | array | opcional | sí | Un elemento por runtime solicitado. Ordenado por `name` ascendente (normalización para el hash). |
| `runtimes[].name` | string | obligatorio | sí | Minúsculas, `^[a-z0-9._-]+$`. |
| `runtimes[].version` | string | obligatorio | sí | **Normalizada**: se extrae el primer `MAJOR.MINOR.PATCH` (o `MAJOR.MINOR`) de la salida del comando; se eliminan prefijos (`v`, `go version go…`). Sin sufijos de build (`+meta`) ni pre-release para el hash; si el runtime tiene pre-release, se conserva en `raw` pero no participa en el hash. |
| `runtimes[].raw` | string | opcional | **no** (volátil) | Salida cruda del comando, para depuración humana. Nunca entra al hash. |
| `runtimes[].source` | string | opcional | no | Comando usado (p. ej. `go version`). Informativo. |
| `files[]` | array | opcional | sí | Indicadores de lockfiles/config. Ordenado por `path`. |
| `files[].path` | string | obligatorio | sí | **Ruta relativa al proyecto**, con separador `/` en todas las plataformas. Prohibidas rutas absolutas, `..` y unidades Windows (`C:\`). |
| `files[].kind` | enum | obligatorio | sí | `config` \| `lockfile`. |
| `files[].present` | bool | obligatorio | sí | Existencia del archivo. |
| `files[].digest` | string | opcional | sí (solo si presente) | `sha256:<hex>` del contenido del archivo. Solo se calcula si el proyecto lo pide explícitamente (reglas). |
| `variables[]` | array | opcional | sí | Solo variables **declaradas por el proyecto** (en reglas o flags); nunca el entorno completo. Ordenadas por `key`. |
| `variables[].key` | string | obligatorio | sí | `^[A-Za-z_][A-Za-z0-9_]*$`. |
| `variables[].state` | enum | obligatorio | sí | `present` \| `absent`. |
| `variables[].sensitive` | bool | obligatorio | sí | Marcada por patrón de las reglas o valor por defecto (`*_TOKEN`, `*_SECRET`, `*_KEY`, `*_PASSWORD`, `*_PASS`, `*_CREDENTIALS`, `*_URL`, `*_URI`, `*_DSN`). |
| `variables[].compare` | enum | obligatorio | no | `presence` \| `value`. Decide si el diff compara solo presencia o también valor. Para `sensitive: true` debe ser `presence`. |
| `variables[].value` | string | opcional | sí (solo si `compare: value`) | Valor en claro, **prohibido si `sensitive: true`**. Solo apto para variables de configuración no sensibles (p. ej. `NODE_ENV`). |
| `meta.hashAlgorithm` | string | obligatorio | no | Identificador del algoritmo de hash: `sha256-canonical-json-v1`. Si cambia la canonicalización, cambia este identificador y el esquema. |
| `fingerprint` | string | obligatorio (puede estar vacío durante la generación) | no | `sha256:<64 hex>` sobre el subconjunto marcado "En hash". Vacío solo en huellas intermedias antes de calcularse. |

### Clasificación de campos

- **Obligatorios**: sin ellos el documento es inválido.
- **Opcionales**: secciones ausentes se omiten del JSON (`omitempty`). En el **hash**, ausente, vacío (`[]`) y `null` son equivalentes (todos se omiten de la representación canónica) para garantizar reproducibilidad entre productores y marshallers. El motor de **diff** puede distinguir documentalmente ausente de vacío, pero esa distinción nunca altera el hash (ver §3).
- **Volátiles** (`runtimes[].raw`, `tool.version`, `meta`): útiles para humanos, excluidos del hash para garantizar reproducibilidad entre máquinas y versiones de la herramienta.
- **Sensibles** (`variables[].value` con `sensitive: true`): **prohibidos**. Ningún documento, log ni mensaje de error puede contener valores de secretos. No se calculan hashes de secretos (un hash de un valor de baja entropía es atacable por diccionario); los secretos se comparan solo por **presencia/ausencia**.

### Cómputo del hash (`sha256-canonical-json-v1`)

`internal/fingerprint` calcula el hash exactamente en este orden:

1. **Proyección**: solo los campos marcados "En hash: sí". Por construcción quedan fuera `schema`, `tool.*`, `meta.*`, `runtimes[].raw/source`, `variables[].compare`, `fingerprint` y cualquier campo JSON desconocido.
2. **Selección por política** (`Policy.Sections`): el hash principal usa todas las secciones (`environment`, `runtimes`, `files`, `variables`). `check` y `compare` podrán recalcular con el subconjunto de `rules.compare.sections`; ese *hash de comparación* es deliberadamente distinto del hash del documento.
3. **Canonicalización**: JSON con claves ordenadas por orden de bytes, sin espacios, sin escapado HTML, UTF-8; arrays ordenados por su clave natural (`name`, `path`, `key`); secciones ausentes/vacías/nulas y campos opcionales vacíos se omiten de forma idéntica.
4. **Separación de dominios**: entrada del SHA-256 = `"sha256-canonical-json-v1\n" + canonico`.

No se hace **ninguna** normalización semántica de valores en este paso (las versiones y rutas ya vienen normalizadas de la colección y son verificadas por `Validate`): colapsar valores ocultaría diferencias reales.

**El hash garantiza**: dos huellas producen el mismo hash si y solo si sus campos seleccionados son iguales bajo las reglas anteriores.
**El hash NO garantiza**: identidad de los entornos (hay hechos no recolectados y metadatos fuera del hash) ni integridad/autenticidad (no es una firma).

### Datos excluidos por diseño

Para garantizar hashes reproducibles entre máquinas y no filtrar información
personal, el esquema **no contempla**: timestamps, rutas absolutas, nombres de
usuario, hostname ni direcciones IP. Si en el futuro se añaden (p. ej. un campo
`capturedAt`), serán opcionales y excluidos del hash.

---

## 2. Reglas de proyecto (`.envfingerprint.json`)

```json
{
  "schema": 1,
  "variables": {
    "required": ["CONFIG_PROVIDER", "DATABASE_URL"],
    "compareValues": ["CONFIG_PROVIDER"],
    "sensitivePatterns": ["*_TOKEN", "*_SECRET", "*_KEY", "*_PASSWORD"]
  },
  "tools": [
    { "name": "go", "minVersion": "1.22.0" },
    { "name": "node", "minVersion": "20.0.0" }
  ],
  "files": ["go.mod", "go.sum"],
  "fileDigests": ["go.sum"],
  "compare": {
    "sections": ["environment", "runtimes", "files", "variables"]
  },
  "expectedFingerprint": "sha256:9b1c0f..."
}
```

| Campo | Clase | Descripción |
|---|---|---|
| `schema` | obligatorio | `1`. |
| `variables.required` | opcional | Variables que deben existir; su ausencia hace fallar `validate` (exit 1). Solo se comprueba presencia, nunca valor. |
| `variables.compareValues` | opcional | Subconjunto de requeridas (u otras) cuyos valores **no sensibles** pueden registrarse y compararse. Un error de validación impide que una variable sensible aparezca aquí. |
| `variables.sensitive` | opcional | Nombres exactos que el proyecto declara sensibles (para nombres que no casan con los patrones). Se añaden al conjunto recolectado como solo-presencia. |
| `variables.sensitivePatterns` | opcional | Patrones glob adicionales de nombres sensibles; se unen a los por defecto (`*_TOKEN`, `*_SECRET`, `*_KEY`, `*_PASSWORD`, `*_PASS`, `*_CREDENTIALS`, `*_URL`, `*_URI`, `*_DSN`, y los exactos `PASSWORD`, `TOKEN`, `SECRET`, `API_KEY`, `PRIVATE_KEY`). |
| `tools[].name` / `tools[].minVersion` | obligatorio/opcional | Runtime a comprobar y versión mínima semver (`MAJOR.MINOR.PATCH`). La comparación de versiones es semver estricta sobre la versión normalizada. |
| `files` | opcional | Archivos (rutas relativas) cuya presencia se registra. |
| `fileDigests` | opcional | Subconjunto de `files` del que además se calcula digest de contenido. |
| `compare.sections` | opcional | Secciones que el diff/`validate` consideran; por defecto todas. Permite excluir secciones irrelevantes para el proyecto. |
| `expectedFingerprint` | opcional | Si se declara, `validate` falla (exit 1) si el hash calculado difiere, y **no muestra** las diferencias de variables sensibles. |

---

## 3. Resultado de comparación (`diff --json`)

```json
{
  "schema": 1,
  "equal": false,
  "compatible": true,
  "notes": ["variables.DATABASE_URL: sensible, comparada solo por presencia"],
  "changes": [
    { "path": "environment.profile", "kind": "modified", "severity": "info",
      "description": "el perfil del entorno difiere en profile", "a": "local", "b": "ci" },
    { "path": "files[package-lock.json]", "kind": "removed", "severity": "info",
      "description": "el archivo package-lock.json no fue comprobado en la huella B", "a": "false" },
    { "path": "runtimes[go].version", "kind": "modified", "severity": "warning",
      "description": "la versión de go difiere entre entornos", "a": "1.22.5", "b": "1.23.2" },
    { "path": "variables[CACHE_DIR].state", "kind": "modified", "severity": "warning",
      "description": "la variable CACHE_DIR está presente en un entorno y ausente en el otro", "a": "absent", "b": "present" }
  ]
}
```

| Campo | Descripción |
|---|---|
| `schema` | `1`. |
| `equal` | `true` si no hay cambios en las secciones comparadas. |
| `compatible` | `false` si las huellas tienen `schema` o `hashAlgorithm` distintos; en ese caso `changes` puede estar incompleto y debe aparecer una nota. |
| `notes[]` | Aclaraciones para humanos (comparaciones degradadas, secciones ignoradas, sensibles). Nunca contienen valores sensibles. |
| `changes[].path` | Ruta estable del campo: `seccion`, `seccion.campo`, `seccion[clave].campo`. Las claves de `runtimes`, `files` y `variables` son `name`, `path` y `key` respectivamente. |
| `changes[].kind` | `added` \| `removed` \| `modified` \| `unknown`. `unknown` = no comparable por falta de información (p. ej. solo una parte permite comparación por valor); **no** cuenta como diferencia para `equal` ni para el exit code. |
| `changes[].severity` | `info` \| `warning` \| `error`. `error` solo cuando una regla declarada lo respalda (variable requerida ausente, herramienta declarada ausente, `minVersion` incumplido, esquema incompatible). Sin reglas, ninguna diferencia es `error` por defecto. |
| `changes[].description` | Descripción legible del hecho observado; nunca especula causas. |
| `changes[].rule` | Regla relacionada (p. ej. `variables.required`, `tools[node].minVersion`), si existe. |
| `changes[].advice` | Recomendación de diagnóstico respaldada por la información disponible; vacía si no hay fundamento. |
| `changes[].a` / `.b` | Valores como strings ya normalizados; ausentes según `kind`. Jamás valores de variables sensibles. |

Orden de `changes`: por `path` ascendente sin duplicados (determinista, apto para snapshots en tests). `notes` ordenado alfabéticamente.

**Códigos de salida de `compare`**: sin `--exit-code`, 0 salvo error de ejecución; con `--exit-code`, 0 sin diferencias, 1 si hay cambios (los `unknown` no cuentan), 2 si las huellas son incompatibles (`schema`/`hashAlgorithm` distintos) o hay errores de lectura/validación.

---

## 4. Evolución del formato

El campo `schema` gobierna la compatibilidad:

- **Cambios aditivos** (nuevo campo opcional, nuevo valor de enum solo de salida)
  → **no** incrementan `schema`. Los lectores ignoran campos desconocidos
  (modo tolerante por defecto; `--strict` los rechaza para detección temprana).
- **Cambios rupturistas** (renombrar/eliminar campos, cambiar canonicalización
  del hash, cambiar la semántica de un campo) → `schema` se incrementa.
- Regla del lector:
  - `schema == soportado` → procesar.
  - `schema > soportado` → error claro: "huella generada con un esquema más
    nuevo (N); actualiza envfingerprint" (código de salida 2).
  - `schema < soportado` → no ocurre en v1; en v2 se documentará migración.
  - `hashAlgorithm` distinto entre dos huellas → `compatible: false` en diff;
    comparar de todos modos por campos, pero el hash no es significativo.
- `tool.version` sigue semver del binario y es independiente de `schema`: la
  herramienta puede evolucionar sin cambiar el formato.

---

## 5. Comportamiento ante entradas incorrectas

`internal/model` expone `Load*` (tolerante) y `Validate*` (estricto) para cada
documento. Política común:

- JSON sintácticamente inválido → error de parseo, exit 2.
- Campos obligatorios ausentes, tipos incorrectos, enums fuera de vocabulario,
  normalizaciones violadas (ruta absoluta, versión no normalizada, `value` en
  variable sensible) → error de validación listado por campo, exit 2.
- Campo desconocido → ignorado en modo tolerante; error en modo estricto.
- Toda validación se ejecuta sobre los ejemplos de `examples/` en
  `internal/model/model_test.go`.
