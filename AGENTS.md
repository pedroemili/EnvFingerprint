# AGENTS.md

## Entorno: Go NO está instalado en el sistema

El host no tiene `go` en PATH. El SDK vive en `/tmp/opencode/go-sdk` (instalado
de forma aislada); **se pierde cuando /tmp se limpia**. Si `go` no responde:

```sh
cd /tmp/opencode && curl -fsSLo go.tgz https://go.dev/dl/go1.23.2.linux-amd64.tar.gz \
  && tar xzf go.tgz && mv go go-sdk
export PATH=/tmp/opencode/go-sdk/bin:$PATH
```

## Comandos

- Verificación obligatoria tras cada cambio: `gofmt -l .` (debe dar vacío),
  `go vet ./...`, `go test ./... -count=1`.
- Un solo paquete: `go test ./internal/fingerprint/ -count=1`; un solo test:
  `go test ./internal/fingerprint/ -run TestGoldenHash -count=1`.
- `make build` compila a `bin/`. Los tests de integración usan `cli.Run`
  directamente (no el binario), así que `make test` no requiere build previo.
- Hay tests que hacen `os.Chdir` (Go 1.23 ⇒ no existe `t.Chdir`; usa el helper
  `chdir` de `tests/`). No marques esos tests como `t.Parallel`.

## Reglas del proyecto (del usuario, obligatorias)

- **Trabajo por fases**: no implementes funcionalidad de fases futuras
  (compare/check/report están pendientes a propósito; deben devolver exit 2 con
  mensaje "pendiente de implementación" hasta su fase).
- **Ningún commit/push sin autorización explícita del usuario.** `git init` ya
  está hecho y hay archivos staged, pero no se ha commiteado nada.
- **Cero dependencias externas** es requisito del MVP. No añadas imports fuera
  de la stdlib (nota: no hay CI aún; go.sum no existe porque no hay deps).
- Español en mensajes de usuario; inglés en identificadores/godoc.

## Arquitectura y contratos

- El contrato de datos es ley: `docs/CONTRACTS.md` + `schemas/*.json`. La
  validación autoritativa es `internal/model` (`Validate` hand-rolled, sin libs
  JSON Schema); los `.schema.json` son de apoyo. Si cambias campos, actualiza
  modelo + schema + CONTRACTS + ejemplos de `examples/`, todo a la vez.
- Layout y decisiones documentados en `docs/LAYOUT.md` — actualízalo si mueves
  paquetes. Detalles de colección en `docs/COLLECTORS.md`.
- La versión es `internal/version.Version` (único lugar; se inyecta con
  `-ldflags -X .../internal/version.Version=` desde el Makefile). No la pongas
  en `cli` ni en `collector`: causaba un ciclo de imports.
- Collector: NUNCA enumerar el entorno completo, leer `.env`, ejecutar scripts
  del proyecto ni recorrer el FS (lista fija de archivos + rutas relativas
  validadas). Variables sensibles (ver `model.DefaultSensitivePatterns`) son
  solo-presencia, con defensa en profundidad en `variablesCollector`.
- Hash (`internal/fingerprint`): se computa sobre una **proyección canónica**,
  nunca sobre el JSON del documento. Ausente ≡ vacío ≡ null en el hash.
  `TestGoldenHash` es una regresión intencionada: si falla porque la receta
  cambia, debes subir `meta.hashAlgorithm` y el `schema` (ver CONTRACTS §4), no
  solo actualizar la constante.
- Códigos de salida: 0 ok, 1 diferencias/violaciones (compare/check), 2 error
  de uso/ejecución/comandos pendientes.
