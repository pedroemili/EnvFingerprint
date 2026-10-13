# Estructura del repositorio

Layout del proyecto y decisiones asociadas. Si algo cambia, actualiza este archivo.

```
cmd/envfingerprint/     Punto de entrada. Solo delega en internal/cli.
internal/cli/           Dispatch de subcomandos, flags, ayuda, códigos de salida.
internal/model/         Contratos de datos (huella, reglas, diff) + validación.
internal/collector/     Recolección de hechos (system, tools, files, variables) vía interfaces Env/Proc/FS.
internal/fingerprint/   Proyección, serialización canónica y hash SHA-256 reproducible (Policy explícita).
internal/compare/       Motor de comparación (Compare, FormatHuman); severidades info/warning/error.
internal/redact/        Clasificador de sensibilidad + Scrub (barrera antes de serializar).
internal/rules/         (pendiente) Evaluación de reglas del proyecto.
internal/report/        (pendiente) Informes legibles (md/txt).
schemas/                Esquemas JSON (draft 2020-12) de los 3 documentos.
examples/               Documentos JSON de ejemplo con valores ficticios.
tests/                  Pruebas de integración de la superficie CLI.
docs/                   Documentación técnica (CONTRACTS.md, este archivo).
Makefile                build/test/vet/fmt; inyecta la versión por -ldflags.
```

## Decisiones

1. **CLI con stdlib `flag` + dispatch manual** en lugar de Cobra/urfave: la CLI
   tiene 4 subcomandos con pocos flags; un framework añadiría una dependencia sin
   beneficio real. El MVP exige dependencias externas mínimas (actualmente: 0).
2. **`schemas/` y `examples/` en raíz** (en vez de `docs/schemas` y `testdata/`):
   son artefactos públicos del contrato, no detalles internos; así los CI de
   terceros pueden referenciarlos con rutas estables.
3. **Versión por `-ldflags`** sobre `internal/cli.Version` (defecto `0.1.0`,
   mismo valor que usan las huellas de ejemplo). El Makefile toma el tag git si
   existe; el campo `tool.version` del contrato exige semver sin prefijo `v`.
4. **Códigos de salida**: 0 correcto, 1 diferencias/violaciones (compare/check),
   2 error de uso/ejecución. Los comandos pendientes devuelven 2 con mensaje
   explícito; nunca simulan haber realizado la operación.
5. **Toda la lógica reside en `internal/`** y `cmd/envfingerprint` es trivial;
   `cli.Run(args, stdout, stderr) int` es testable sin procesos.

## Convenciones

- Español en mensajes de usuario; inglés en identificadores y godoc.
- `gofmt`, `go vet ./...` y `go test ./...` deben pasar antes de cada fase.
- Ningún archivo exportado, log ni mensaje puede contener valores de secretos.
