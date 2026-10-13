package collector

import (
	"context"
	"fmt"

	"github.com/envfingerprint/envfingerprint/internal/model"
	"github.com/envfingerprint/envfingerprint/internal/version"
)

// Options configures what Collect gathers.
type Options struct {
	ToolNames   []string        // nil = all DefaultToolSpecs
	FilePaths   []string        // nil = DefaultFiles
	DigestPaths map[string]bool // subset of FilePaths to hash
	Variables   model.VariableRules
}

// Result is the outcome of a full collection pass.
type Result struct {
	Fingerprint *model.Fingerprint
	Diagnostics []Diagnostic
}

// Collect runs every collector and assembles a contract-valid fingerprint.
// Individual collector failures degrade into Diagnostics; only an invalid
// final document is a hard error.
func Collect(ctx context.Context, deps Deps, opts Options) (*Result, error) {
	fp := &model.Fingerprint{
		Schema: model.SchemaVersion,
		Tool:   model.Tool{Name: "envfingerprint", Version: version.Version},
		Meta:   model.Meta{HashAlgorithm: model.HashAlgorithm},
		// Fingerprint hash intentionally empty: canonical hashing is filled
		// in by internal/fingerprint in a later phase (valid per contract).
	}
	res := &Result{Fingerprint: fp}

	sys := systemCollector{env: deps.Env, fs: deps.FS}
	fp.Environment, _ = sys.Collect()

	tools := toolsCollector{proc: deps.Proc, specs: selectSpecs(opts.ToolNames)}
	rts, d := tools.Collect(ctx)
	fp.Runtimes = rts
	res.Diagnostics = append(res.Diagnostics, d...)

	files := filesCollector{fs: deps.FS, specs: selectFiles(opts)}
	fes, d := files.Collect()
	fp.Files = fes
	res.Diagnostics = append(res.Diagnostics, d...)

	vars := variablesCollector{
		env:            deps.Env,
		declared:       declaredSet(opts.Variables),
		compareValues:  asSet(opts.Variables.CompareValues),
		sensitiveExtra: opts.Variables.SensitivePatterns,
	}
	vs, d := vars.Collect()
	fp.Variables = vs
	res.Diagnostics = append(res.Diagnostics, d...)

	if err := fp.Validate(); err != nil {
		return nil, fmt.Errorf("la huella recolectada no cumple el contrato: %w", err)
	}
	return res, nil
}

func selectSpecs(names []string) []ToolSpec {
	if len(names) == 0 {
		return append([]ToolSpec{}, DefaultToolSpecs...)
	}
	want := asSet(names)
	var out []ToolSpec
	for _, s := range DefaultToolSpecs {
		if want[s.Name] {
			out = append(out, s)
		}
	}
	return out
}

func selectFiles(opts Options) []fileSpec {
	var specs []fileSpec
	if len(opts.FilePaths) == 0 {
		for _, f := range DefaultFiles {
			specs = append(specs, fileSpec{path: f.Path})
		}
		return specs
	}
	for _, p := range opts.FilePaths {
		specs = append(specs, fileSpec{path: p, digest: opts.DigestPaths[p]})
	}
	return specs
}

func declaredSet(v model.VariableRules) map[string]bool {
	set := asSet(v.Required)
	for _, k := range v.CompareValues {
		set[k] = true
	}
	return set
}

func asSet(keys []string) map[string]bool {
	set := make(map[string]bool, len(keys))
	for _, k := range keys {
		set[k] = true
	}
	return set
}
