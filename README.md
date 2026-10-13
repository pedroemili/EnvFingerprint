# EnvFingerprint

CLI multiplataforma en Go para detectar y explicar diferencias relevantes entre
entornos de desarrollo, contenedores y CI.

**Estado: MVP en construcción.** El contrato de datos v1 está cerrado
(`docs/CONTRACTS.md`). `scan` recolecta el entorno y emite huellas JSON
válidas con hash reproducible; `compare` produce diferencias estructuradas con
severidades (`--json`, `--exit-code`, `--rules`); `check` y `report` están
pendientes y responden explícitamente con exit 2.

## Uso

```
envfingerprint --help
envfingerprint --version
envfingerprint scan [--rules .envfingerprint.json] [--out huella.json] [--dry-run]
envfingerprint compare [--json] [--exit-code] [--rules rules.json] a.json b.json
envfingerprint check [--rules .envfingerprint.json]
envfingerprint report [--format md|txt] huella-o-diff.json
```

Códigos de salida: `0` correcto, `1` diferencias o reglas incumplidas,
`2` error de uso/ejecución (incluye funcionalidad pendiente).

## Compilación y pruebas

Requiere Go ≥ 1.23. Sin dependencias externas.

```
make build   # bin/envfingerprint (versión inyectada por -ldflags)
make test    # go test ./...
make vet     # go vet ./...
```

## Documentación

- `docs/CONTRACTS.md` — contratos de datos v1 (huella, reglas, diff, evolución).
- `docs/LAYOUT.md` — estructura del repositorio y decisiones técnicas.
- `schemas/` — esquemas JSON; `examples/` — documentos de ejemplo.
