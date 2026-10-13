# Modelo de seguridad y redacción

## Principio rector: recolección mínima

La primera y más fuerte barrera **no es redactar al final**: es no recopilar.
`scan` solo puede leer:

- las variables **explícitamente declaradas** en las reglas del proyecto
  (`required` ∪ `compareValues` ∪ `sensitive`);
- las versiones de las herramientas de una lista cerrada (`DefaultToolSpecs`),
  mediante comandos hardcodeados, sin shell, con timeout de 5 s y salida
  acotada a 64 KiB — los comandos **nunca** provienen de la configuración;
- la presencia (y digests bajo petición, ≤10 MiB) de una lista cerrada de
  rutas **relativas validadas**; no hay recorrido del sistema de archivos.

Nunca se enumera el entorno del proceso, nunca se lee ningún `.env`, y nada se
sube ni comparte: todos los comandos operan localmente.

## Clasificación de sensibilidad

Una variable es sensible si cumple cualquiera de estas reglas
(`redact.Classifier`):

1. **Patrón por defecto** (conservador, en `model.DefaultSensitivePatterns`):
   sufijos `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_KEY` (cubre `API_KEY`,
   `PRIVATE_KEY`), `*_PASS`, `*_CREDENTIALS`; cadenas de conexión `*_URL`,
   `*_URI`, `*_DSN`; y nombres exactos `PASSWORD`, `TOKEN`, `SECRET`,
   `API_KEY`, `PRIVATE_KEY`.
2. **Patrón del proyecto**: `variables.sensitivePatterns` (globs).
3. **Declaración exacta del proyecto**: `variables.sensitive` — la vía
   documentada para nombres inesperados que no casan patrones.

## Defensa en profundidad (tres capas)

1. **Validación de reglas**: una variable sensible en `compareValues` hace
   fallar `scan` con exit 2 — la configuración peligrosa no se ejecuta.
2. **Colección**: `variablesCollector` ignora el valor de toda variable
   clasificada sensible aunque la configuración llegara a colarse.
3. **Redacción antes de salida**: `cli` aplica `redact.Scrub` a la huella
   **antes de hashearla y serializarla**: fuerza `sensitive: true`,
   `compare: presence` y borra cualquier valor de clave sensible.

Además: no se computan hashes de secretos (un hash de un valor de baja
entropía es un oráculo de ataque por diccionario) — las sensibles se comparan
solo por presencia. Los comandos externos reciben argumentos fijos, nunca
valores de variables. Los mensajes de error nombran rutas y claves, jamás
valores.

## Vista previa

`envfingerprint scan --dry-run` imprime el plan de recolección (herramientas,
archivos y variables con su clasificación) **sin leer valores ni escribir
archivos**, para auditar qué se exportará antes de permitirlo.

## Lo que NO garantiza (limitaciones documentadas)

- La detección **por nombre**: una credencial con nombre insospechado
  (p. ej. `MYAPP_X`) solo es sensible si el proyecto la declara
  (`variables.sensitive`). El `--dry-run` es la herramienta de auditoría
  para detectarlo antes de exportar.
- El **contenido** de valores no sensibles declarados en `compareValues` se
  exporta en claro: es responsabilidad del proyecto no declarar ahí nada
  confidencial (la validación lo impide si el *nombre* es sensible).
- El scan no inspecciona el *contenido* de otros archivos en busca de
  secretos incrustados (p. ej. un `config.yml` con una contraseña dentro):
  solo registra presencia/digest. Si existe riesgo, el proyecto debe excluir
  el archivo de `files`.
- La huella revela **presencia/ausencia** de variables sensibles; eso ya es
  metadata potencialmente informativa, pero es el mínimo necesario para
  validar requisitos.

La auditoría automatizada vive en `tests/security_test.go` (secretos
ficticios de varias formas comprobados contra huella, stderr, errores y
preview) y `internal/redact/redact_test.go`.
