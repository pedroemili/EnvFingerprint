# EnvFingerprint — compilación y pruebas

# Versión de la herramienta: coincide con `internal/cli.Version`. Si hay tags
# git (p. ej. v0.1.0), se usa el tag sin el prefijo "v".
VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')
ifeq ($(strip $(VERSION)),)
VERSION = 0.1.0
endif
GO      ?= go
LDFLAGS  = -X github.com/envfingerprint/envfingerprint/internal/version.Version=$(VERSION)

.PHONY: build test vet fmt clean

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/envfingerprint ./cmd/envfingerprint

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

clean:
	rm -rf bin
