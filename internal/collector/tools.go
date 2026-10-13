package collector

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/envfingerprint/envfingerprint/internal/model"
)

// ToolSpec describes how to obtain and normalize one runtime version. Command
// lines are hardcoded here — never built from project configuration.
type ToolSpec struct {
	Name string
	// Candidates are tried in order until one runs successfully
	// (e.g. python3, then python).
	Candidates [][]string
	// Pattern must capture the MAJOR.MINOR[.PATCH] version in group 1.
	Pattern *regexp.Regexp
}

// DefaultToolSpecs covers the MVP runtimes: Go, Node.js, Python, .NET.
var DefaultToolSpecs = []ToolSpec{
	{
		Name:       "go",
		Candidates: [][]string{{"go", "version"}}, // "go version go1.23.2 linux/amd64"
		Pattern:    regexp.MustCompile(`\bgo(\d+\.\d+(?:\.\d+)?)\s`),
	},
	{
		Name:       "node",
		Candidates: [][]string{{"node", "--version"}}, // "v20.9.0"
		Pattern:    regexp.MustCompile(`^v?(\d+\.\d+\.\d+)`),
	},
	{
		Name: "python",
		Candidates: [][]string{
			{"python3", "--version"},
			{"python", "--version"},
		}, // "Python 3.12.1"
		Pattern: regexp.MustCompile(`Python (\d+\.\d+(?:\.\d+)?)`),
	},
	{
		Name:       "dotnet",
		Candidates: [][]string{{"dotnet", "--version"}}, // "8.0.404"
		Pattern:    regexp.MustCompile(`^(\d+\.\d+(?:\.\d+)?)$`),
	},
}

// toolsCollector probes installed runtimes. Every failure is recoverable: the
// tool is omitted from the result and a Diagnostic explains why.
type toolsCollector struct {
	proc  Proc
	specs []ToolSpec
}

type ToolOutcome int

const (
	ToolOK ToolOutcome = iota
	ToolNotInstalled
	ToolUnknownVersion
	ToolError
)

func (c toolsCollector) Name() string { return "tools" }

func (c toolsCollector) Collect(ctx context.Context) ([]model.Runtime, []Diagnostic) {
	var runtimes []model.Runtime
	var diags []Diagnostic

	for _, spec := range c.specs {
		rt, outcome, detail := c.probe(ctx, spec)
		switch outcome {
		case ToolOK:
			runtimes = append(runtimes, rt)
		case ToolNotInstalled:
			diags = append(diags, Diagnostic{Collector: "tools", Message: fmt.Sprintf("%s: no instalado", spec.Name)})
		case ToolUnknownVersion:
			diags = append(diags, Diagnostic{Collector: "tools", Message: fmt.Sprintf("%s: versión desconocida (salida no reconocida)", spec.Name)})
		case ToolError:
			diags = append(diags, Diagnostic{Collector: "tools", Message: fmt.Sprintf("%s: %s", spec.Name, detail)})
		}
	}

	sort.Slice(runtimes, func(i, j int) bool { return runtimes[i].Name < runtimes[j].Name })
	return runtimes, diags
}

func (c toolsCollector) probe(ctx context.Context, spec ToolSpec) (model.Runtime, ToolOutcome, string) {
	var sawNotInstalled bool
	for _, cand := range spec.Candidates {
		out, err := c.proc.Run(ctx, cand[0], cand[1:]...)
		if err != nil {
			if errors.Is(err, ErrNotInstalled) {
				sawNotInstalled = true
				continue // try next candidate
			}
			return model.Runtime{}, ToolError, err.Error()
		}
		m := spec.Pattern.FindStringSubmatch(strings.TrimSpace(out))
		if m == nil {
			return model.Runtime{}, ToolUnknownVersion, ""
		}
		return model.Runtime{
			Name:    spec.Name,
			Version: m[1],
			Raw:     strings.TrimSpace(out),
			Source:  strings.Join(cand, " "),
		}, ToolOK, ""
	}
	if sawNotInstalled {
		return model.Runtime{}, ToolNotInstalled, ""
	}
	return model.Runtime{}, ToolUnknownVersion, ""
}
