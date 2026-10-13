# Recolectores

`internal/collector` implementa la recolección del comando `scan`. Los
contratos de los datos producidos están en `docs/CONTRACTS.md`.

## Diseño

Cuatro recolectores independientes, ensamblados por `Collect`:

| Recolector | Produce | Dependencias |
|---|---|---|
| system | `environment` (os, arch, container, ci, profile) | `Env`, `FS.ExistsAbs` |
| tools | `runtimes` | `Proc` |
| files | `files` (presencia + digests opcionales) | `FS` |
| variables | `variables` (presencia; valor solo si se permite) | `Env` |

Interfaces pequeñas y falsificables en pruebas:

- `Env`: lectura puntual de variables de entorno.
- `Proc`: ejecución de comandos externos con timeout (5 s) y salida acotada
  (64 KiB), **sin shell**; las líneas de comando están hardcodeadas en
  `DefaultToolSpecs`, nunca provienen de la configuración del proyecto.
- `FS`: acceso a archivos **relativos al proyecto** (rechaza absolutas y `..`);
  digest solo para rutas de `fileDigests` con límite de 10 MiB.

Los fallos son recuperables: un recolector que falla añade un `Diagnostic`
(stderr, prefijo `aviso:`) y el resto de la huella se conserva. Solo un
documento final que no pase `model.Validate` es error (exit 2).

## Estado de herramientas

Cada runtime produce exactamente uno de estos resultados:

- **ok**: versión normalizada (`MAJOR.MINOR[.PATCH]`) + `raw`/`source`.
- **no instalado**: el binario no está en `PATH` (`exec.LookPath` falla).
- **versión desconocida**: el comando funcionó pero la salida no casa el
  patrón esperado.
- **error de ejecución**: fallo del proceso o timeout.

Los casos no-ok generan diagnóstico y omiten el runtime de la huella (el
contrato exige `version` normalizada cuando la entrada existe).

## Selección de datos

- **Runtimes**: los 4 por defecto (go, node, python, dotnet) o los listados en
  `rules.tools`. Python prueba `python3` y luego `python`.
- **Archivos**: lista fija `DefaultFiles` si las reglas no declaran `files`.
  Sin globbing ni recorrido del sistema de archivos.
- **Variables**: solo la unión de `required` ∪ `compareValues`. Nunca se
  enumera el entorno completo ni se leen archivos `.env`. Las sensibles son
  siempre solo-presencia (defensa en profundidad además de la validación de
  reglas).

## Limitaciones multiplataforma conocidas

- La detección de contenedor es una heurística documentada (`/.dockerenv`,
  `/run/.containerenv`, variable `container`); en **Windows devuelve siempre
  `false`** (no existe un probe estable equivalente). Bajo WSL se reporta Linux.
- En Windows, `python3` rara vez existe: se usa `python`. El launcher `py` no
  se prueba.
- El timeout de 5 s puede quedarse corto para `dotnet --version` en primeras
  ejecuciones (JIT/init); el runtime se reporta como error de ejecución y el
  scan continúa.
- `runtimes[].raw` incluye la salida cruda del comando (p. ej.
  `go version go1.23.2 linux/amd64`): son datos del toolchain, nunca rutas ni
  usuarios, y quedan fuera del hash.
