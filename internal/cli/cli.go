// Package cli implements the command-line interface of envfingerprint.
//
// Design decision: subcommand dispatch and flag parsing use only the standard
// library ("flag"). The CLI has four subcommands plus --help/--version; a
// command framework such as Cobra would add a dependency without paying for
// itself at this size. (See docs/LAYOUT.md.)
package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/envfingerprint/envfingerprint/internal/collector"
	"github.com/envfingerprint/envfingerprint/internal/model"
	"github.com/envfingerprint/envfingerprint/internal/version"
)

// Version is the tool version embedded in fingerprints (tool.version, semver
// MAJOR.MINOR.PATCH without "v"). The value lives in internal/version and is
// overridable at build time; the Makefile sets it from `git describe --tags`.
var Version = version.Version

// Exit codes, stable for CI automation.
const (
	// ExitOK: command succeeded (or, for compare/check, no differences
	// or violations found).
	ExitOK = 0
	// ExitViolation: compare found differences in --exit-code mode, or
	// check found a rule violation. Reserved for later phases.
	ExitViolation = 1
	// ExitUsage: wrong arguments, unreadable files, unimplemented
	// commands, or any other execution error.
	ExitUsage = 2
)

const usageText = `envfingerprint %s — detecta y explica diferencias entre entornos

Uso:
  envfingerprint <comando> [argumentos]
  envfingerprint --help | --version

Comandos:
  scan      Inspecciona el entorno actual y emite una huella JSON (esquema v1)
  compare   Compara dos huellas JSON y muestra sus diferencias
  check     Valida el entorno actual contra las reglas de .envfingerprint.json
  report    Genera un informe legible a partir de una huella o un diff

Opciones globales:
  --help       muestra esta ayuda
  --version    muestra la versión de la herramienta

Usa "envfingerprint <comando> --help" para ver los argumentos de cada comando.

Códigos de salida:
  0  correcto / sin diferencias / sin violaciones
  1  diferencias encontradas o reglas incumplidas (compare/check)
  2  error de uso o de ejecución (incluye comandos aún no implementados)
`

// Run executes the CLI. It returns the process exit code; main() passes it to
// os.Exit. All output goes to the provided writers so tests can capture it.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, usageText, Version)
		fmt.Fprintln(stderr, "\nerror: falta un comando")
		return ExitUsage
	}

	switch args[0] {
	case "--help", "-h", "help":
		fmt.Fprintf(stdout, usageText, Version)
		return ExitOK
	case "--version", "-v", "version":
		fmt.Fprintf(stdout, "envfingerprint %s\n", Version)
		return ExitOK
	case "scan":
		return cmdScan(args[1:], stdout, stderr)
	case "compare":
		return cmdCompare(args[1:], stdout, stderr)
	case "check":
		return cmdCheck(args[1:], stdout, stderr)
	case "report":
		return cmdReport(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "error: comando desconocido %q\n\n", args[0])
		fmt.Fprintf(stderr, usageText, Version)
		return ExitUsage
	}
}

// pending reports a command whose argument parsing is done but whose engine is
// not implemented in this phase. It never pretends success.
func pending(stderr io.Writer, name, phase string) int {
	fmt.Fprintf(stderr, "%s: funcionalidad pendiente de implementación (%s)\n", name, phase)
	return ExitUsage
}

// newFlagSet creates a FlagSet for a subcommand; we print our own usage text
// on error, so flag output is discarded and Usage is a no-op.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

func commandUsage(name, text string) string {
	return fmt.Sprintf("Uso: envfingerprint %s %s", name, text)
}

var scanUsage = commandUsage("scan", `[opciones]

Inspecciona el entorno actual y emite una huella JSON conforme al esquema v1.

Opciones:
  --rules <ruta>   archivo de reglas que declara variables, herramientas y
                   archivos a inspectar (por defecto .envfingerprint.json)
  --out <ruta>     escribe la huella en un archivo en lugar de stdout`)

var compareUsage = commandUsage("compare", `[opciones] <huella-a.json> <huella-b.json>

Compara dos huellas de entorno e informa de las diferencias por secciones.

Opciones:
  --json          emite el resultado como JSON (esquema diff v1)
  --exit-code     devuelve 1 si hay diferencias (por defecto devuelve 0)`)

var checkUsage = commandUsage("check", `[opciones]

Valida el entorno actual contra las reglas del proyecto sin emitir la huella.

Opciones:
  --rules <ruta>   archivo de reglas (por defecto .envfingerprint.json)`)

var reportUsage = commandUsage("report", `[opciones] <huella-o-diff.json>

Genera un informe legible para humanos a partir de una huella o un diff.

Opciones:
  --format <fmt>   formato del informe: md | txt (por defecto md)`)

// parse reports a flag parsing error (including --help) in a uniform way.
func parse(name, usage string, fs *flag.FlagSet, args []string, stdout io.Writer) (help bool, err error) {
	for _, a := range args {
		if a == "--help" || a == "-h" {
			fmt.Fprintln(stdout, usage)
			return true, nil
		}
	}
	if err := fs.Parse(args); err != nil {
		return false, fmt.Errorf("%s: %w\n\n%s", name, err, usage)
	}
	return false, nil
}

func cmdScan(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("scan")
	rulesPath := fs.String("rules", ".envfingerprint.json", "")
	outPath := fs.String("out", "", "")
	help, err := parse("scan", scanUsage, fs, args, stdout)
	if help {
		return ExitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "error: scan no acepta argumentos posicionales %q\n\n%s\n", fs.Arg(0), scanUsage)
		return ExitUsage
	}

	rulesExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "rules" {
			rulesExplicit = true
		}
	})
	rules, err := loadRules(*rulesPath, rulesExplicit)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return ExitUsage
	}

	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(stderr, "error: no se pudo determinar el directorio del proyecto: %v\n", err)
		return ExitUsage
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := collector.Collect(ctx, collector.RealDeps(root), collector.Options{
		ToolNames:   toolNames(rules),
		FilePaths:   rules.Files,
		DigestPaths: asSet(rules.FileDigests),
		Variables:   rules.Variables,
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return ExitUsage
	}

	for _, d := range res.Diagnostics {
		fmt.Fprintf(stderr, "aviso: %s\n", d)
	}
	if res.Fingerprint.Fingerprint == "" {
		fmt.Fprintln(stderr, "aviso: el campo fingerprint (hash) se calculará en la fase de hashing; ahora está vacío")
	}

	data, err := json.MarshalIndent(res.Fingerprint, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "error: no se pudo serializar la huella: %v\n", err)
		return ExitUsage
	}
	data = append(data, '\n')

	if *outPath == "" {
		stdout.Write(data)
		return ExitOK
	}
	if err := os.WriteFile(*outPath, data, 0o644); err != nil {
		fmt.Fprintf(stderr, "error: no se pudo escribir %q: %v\n", *outPath, err)
		return ExitUsage
	}
	fmt.Fprintf(stdout, "huella escrita en %s\n", *outPath)
	return ExitOK
}

// loadRules loads project rules. A missing default rules file is fine (scan
// runs with built-in defaults); a missing explicitly-given file is an error.
func loadRules(path string, explicit bool) (*model.Rules, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !explicit && os.IsNotExist(err) {
			return &model.Rules{Schema: model.SchemaVersion}, nil
		}
		return nil, fmt.Errorf("no se pudo leer las reglas %q: %w", path, err)
	}
	rules, err := model.LoadRules(data, false)
	if err != nil {
		return nil, fmt.Errorf("reglas %q inválidas: %w", path, err)
	}
	if err := rules.Validate(); err != nil {
		return nil, fmt.Errorf("reglas %q inválidas: %w", path, err)
	}
	return rules, nil
}

func toolNames(r *model.Rules) []string {
	var names []string
	for _, t := range r.Tools {
		names = append(names, t.Name)
	}
	return names
}

func asSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func cmdCompare(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("compare")
	asJSON := fs.Bool("json", false, "")
	exitCode := fs.Bool("exit-code", false, "")
	help, err := parse("compare", compareUsage, fs, args, stdout)
	if help {
		return ExitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return ExitUsage
	}
	if fs.NArg() != 2 {
		fmt.Fprintf(stderr, "error: compare requiere exactamente 2 huellas JSON, recibidas %d\n\n%s\n", fs.NArg(), compareUsage)
		return ExitUsage
	}
	_ = *asJSON
	_ = *exitCode
	return pending(stderr, "compare", "motor de comparación en fase posterior")
}

func cmdCheck(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("check")
	rules := fs.String("rules", ".envfingerprint.json", "")
	help, err := parse("check", checkUsage, fs, args, stdout)
	if help {
		return ExitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "error: check no acepta argumentos posicionales %q\n\n%s\n", fs.Arg(0), checkUsage)
		return ExitUsage
	}
	_ = *rules
	return pending(stderr, "check", "evaluación de reglas en fase posterior")
}

func cmdReport(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("report")
	format := fs.String("format", "md", "")
	help, err := parse("report", reportUsage, fs, args, stdout)
	if help {
		return ExitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(stderr, "error: report requiere exactamente 1 archivo de entrada, recibidos %d\n\n%s\n", fs.NArg(), reportUsage)
		return ExitUsage
	}
	switch *format {
	case "md", "txt":
	default:
		fmt.Fprintf(stderr, "error: --format debe ser md o txt, recibido %q\n\n%s\n", *format, reportUsage)
		return ExitUsage
	}
	return pending(stderr, "report", "generación de informes en fase posterior")
}
