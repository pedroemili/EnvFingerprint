// Package compare implements the structural comparison engine for
// `envfingerprint compare`.
//
// Severities are assigned only from verifiable facts and declared rules:
// a difference is never promoted to error without a rule (e.g. a required
// variable missing on one side, a declared tool absent, a minVersion
// violation). Unknown causes are never invented: if a variable is absent we
// report its absence, not a reason for it. Sensitive variables are compared
// by presence only and their values never appear in the output.
//
// Results are deterministic: changes are sorted by path, notes are sorted.
package compare

import (
	"fmt"
	"sort"
	"strings"

	"github.com/envfingerprint/envfingerprint/internal/model"
)

// Result wraps the contract document with computed exit-code helpers.
type Result struct {
	Diff *model.DiffResult
}

// Compare structurally compares two fingerprints a and b. rules may be nil
// (then only default severities apply). Both documents must pass
// model.Validate except schema/hashAlgorithm compatibility, which is
// reported inside the result instead of failing: a caller diffing artifacts
// from other tool versions needs a useful answer, not a refusal.
func Compare(a, b *model.Fingerprint, rules *model.Rules) (*model.DiffResult, error) {
	for name, fp := range map[string]*model.Fingerprint{"a": a, "b": b} {
		if fp == nil {
			return nil, fmt.Errorf("huella %s: documento nulo", name)
		}
		if fp.Schema != model.SchemaVersion || fp.Meta.HashAlgorithm != model.HashAlgorithm {
			// Incompatibility is reported in-band, not as a Go error.
			return incompatible(a, b, fp, name), nil
		}
		if err := fp.Validate(); err != nil {
			return nil, fmt.Errorf("huella %s inválida: %w", name, err)
		}
	}

	out := &model.DiffResult{
		Schema:     model.SchemaVersion,
		Compatible: true,
		Notes:      []string{},
		Changes:    []model.Change{},
	}

	if a.Fingerprint != "" && b.Fingerprint != "" && a.Fingerprint == b.Fingerprint {
		out.Notes = append(out.Notes, "los hashes de ambas huellas coinciden: los campos relevantes son iguales")
	}

	compareEnvironment(a, b, out)
	compareRuntimes(a, b, rules, out)
	compareFiles(a, b, out)
	compareVariables(a, b, rules, out)

	sort.Slice(out.Changes, func(i, j int) bool { return out.Changes[i].Path < out.Changes[j].Path })
	sort.Strings(out.Notes)
	out.Equal = true
	for _, c := range out.Changes {
		if c.Kind != model.ChangeUnknown {
			out.Equal = false
			break
		}
	}
	return out, nil
}

// incompatible builds the result for cross-schema or cross-algorithm pairs.
func incompatible(a, b, bad *model.Fingerprint, which string) *model.DiffResult {
	notes := []string{fmt.Sprintf("huella %s: esquema=%d hashAlgorithm=%q; esta herramienta soporta schema=%d y %q",
		which, bad.Schema, bad.Meta.HashAlgorithm, model.SchemaVersion, model.HashAlgorithm)}
	changes := []model.Change{}
	if a.Schema != b.Schema {
		changes = append(changes, model.Change{
			Path:        "schema",
			Kind:        model.ChangeModified,
			Severity:    model.SeverityError,
			Description: "las huellas usan versiones de esquema distintas; la comparación estructural no es fiable",
			A:           fmt.Sprint(a.Schema),
			B:           fmt.Sprint(b.Schema),
			Advice:      "regenera las huellas con la misma versión de envfingerprint o actualiza la herramienta",
		})
	}
	if a.Meta.HashAlgorithm != b.Meta.HashAlgorithm {
		changes = append(changes, model.Change{
			Path:        "meta.hashAlgorithm",
			Kind:        model.ChangeModified,
			Severity:    model.SeverityError,
			Description: "las huellas usan recetas de hash distintas; sus hashes no son comparables",
			A:           a.Meta.HashAlgorithm,
			B:           b.Meta.HashAlgorithm,
		})
	}
	return &model.DiffResult{
		Schema:     model.SchemaVersion,
		Equal:      false,
		Compatible: false,
		Notes:      notes,
		Changes:    changes,
	}
}

func compareEnvironment(a, b *model.Fingerprint, out *model.DiffResult) {
	fields := []struct {
		path string
		get  func(*model.Environment) string
	}{
		{"environment.profile", func(e *model.Environment) string { return e.Profile }},
		{"environment.os", func(e *model.Environment) string { return e.OS }},
		{"environment.arch", func(e *model.Environment) string { return e.Arch }},
		{"environment.container", func(e *model.Environment) string { return boolstr(e.Container) }},
		{"environment.ci", func(e *model.Environment) string { return boolstr(e.CI) }},
	}
	for _, f := range fields {
		va, vb := f.get(&a.Environment), f.get(&b.Environment)
		if va == vb {
			continue
		}
		out.Changes = append(out.Changes, model.Change{
			Path:        f.path,
			Kind:        model.ChangeModified,
			Severity:    model.SeverityInfo,
			Description: fmt.Sprintf("el perfil del entorno difiere en %s", strings.TrimPrefix(f.path, "environment.")),
			A:           va,
			B:           vb,
		})
	}
}

func compareRuntimes(a, b *model.Fingerprint, rules *model.Rules, out *model.DiffResult) {
	ra := runtimesByName(a)
	rb := runtimesByName(b)
	for _, name := range unionKeys(ra, rb) {
		rta, okA := ra[name]
		rtb, okB := rb[name]
		path := "runtimes[" + name + "]"
		declared := toolDeclared(rules, name)
		switch {
		case okA && !okB:
			c := model.Change{
				Path:        path,
				Kind:        model.ChangeRemoved,
				Severity:    model.SeverityWarning,
				Description: fmt.Sprintf("el runtime %s no aparece en la huella B (no instalado, sin versión reconocida o sección omitida)", name),
				A:           rta.Version,
			}
			if declared {
				c.Severity = model.SeverityError
				c.Rule = "tools"
				c.Description = fmt.Sprintf("el runtime %s, declarado en las reglas del proyecto, no aparece en la huella B", name)
				c.Advice = fmt.Sprintf("verifica que %s esté instalado y en PATH del entorno B", name)
			}
			out.Changes = append(out.Changes, c)
		case !okA && okB:
			c := model.Change{
				Path:        path,
				Kind:        model.ChangeAdded,
				Severity:    model.SeverityWarning,
				Description: fmt.Sprintf("el runtime %s solo aparece en la huella B", name),
				B:           rtb.Version,
			}
			if declared {
				c.Severity = model.SeverityError
				c.Rule = "tools"
				c.Advice = fmt.Sprintf("verifica que %s esté instalado y en PATH del entorno A", name)
			}
			out.Changes = append(out.Changes, c)
		case rta.Version != rtb.Version:
			c := model.Change{
				Path:        path + ".version",
				Kind:        model.ChangeModified,
				Severity:    model.SeverityWarning,
				Description: fmt.Sprintf("la versión de %s difiere entre entornos", name),
				A:           rta.Version,
				B:           rtb.Version,
			}
			if min := toolMinVersion(rules, name); min != "" {
				bad := violatesMin(rta.Version, min) || violatesMin(rtb.Version, min)
				if bad {
					c.Severity = model.SeverityError
					c.Rule = fmt.Sprintf("tools[%s].minVersion", name)
					c.Description = fmt.Sprintf("alguna versión de %s incumple el mínimo declarado (%s)", name, min)
					c.Advice = fmt.Sprintf("actualiza %s a >= %s en el entorno afectado", name, min)
				}
			}
			out.Changes = append(out.Changes, c)
		}
	}
}

func compareFiles(a, b *model.Fingerprint, out *model.DiffResult) {
	fa := filesByPath(a)
	fb := filesByPath(b)
	for _, p := range unionKeys(fa, fb) {
		ea, okA := fa[p]
		eb, okB := fb[p]
		path := "files[" + p + "]"
		switch {
		case okA && !okB:
			out.Changes = append(out.Changes, model.Change{
				Path:        path,
				Kind:        model.ChangeRemoved,
				Severity:    model.SeverityInfo,
				Description: fmt.Sprintf("el archivo %s no fue comprobado en la huella B", p),
				A:           boolstr(ea.Present),
			})
		case !okA && okB:
			out.Changes = append(out.Changes, model.Change{
				Path:        path,
				Kind:        model.ChangeAdded,
				Severity:    model.SeverityInfo,
				Description: fmt.Sprintf("el archivo %s solo fue comprobado en la huella B", p),
				B:           boolstr(eb.Present),
			})
		case ea.Present != eb.Present:
			out.Changes = append(out.Changes, model.Change{
				Path:        path + ".present",
				Kind:        model.ChangeModified,
				Severity:    model.SeverityInfo,
				Description: fmt.Sprintf("el archivo %s existe en un entorno y no en el otro", p),
				A:           boolstr(ea.Present),
				B:           boolstr(eb.Present),
			})
		case ea.Present && eb.Present && ea.Digest != "" && eb.Digest != "" && ea.Digest != eb.Digest:
			out.Changes = append(out.Changes, model.Change{
				Path:        path + ".digest",
				Kind:        model.ChangeModified,
				Severity:    model.SeverityWarning,
				Description: fmt.Sprintf("el contenido de %s difiere entre entornos (digest distinto)", p),
				Advice:      fmt.Sprintf("revisa si %s está actualizado en ambos entornos (p. ej. bloqueo de dependencias)", p),
				// The digests themselves are long and unhelpful in reports;
				// presence of difference is the signal.
			})
		}
	}
}

func compareVariables(a, b *model.Fingerprint, rules *model.Rules, out *model.DiffResult) {
	va := varsByKey(a)
	vb := varsByKey(b)
	for _, key := range unionKeys(va, vb) {
		va1, okA := va[key]
		vb1, okB := vb[key]
		path := fmt.Sprintf("variables[%s]", key)
		sensitive := va1.Sensitive || vb1.Sensitive
		if sensitive {
			out.Notes = append(out.Notes, fmt.Sprintf("variables[%s]: sensible, comparada solo por presencia", key))
		}
		switch {
		case okA && !okB || !okA && okB:
			// Variable declared in only one document: we cannot know its real
			// state there, so this is informational.
			kind, val := model.ChangeRemoved, va1.State
			if !okA {
				kind, val = model.ChangeAdded, vb1.State
			}
			out.Changes = append(out.Changes, model.Change{
				Path:        path,
				Kind:        kind,
				Severity:    model.SeverityInfo,
				Description: fmt.Sprintf("la variable %s solo fue declarada en una de las huellas", key),
				A:           tern(kind == model.ChangeRemoved, val, ""),
				B:           tern(kind == model.ChangeAdded, val, ""),
			})
		case va1.State != vb1.State:
			c := model.Change{
				Path:        path + ".state",
				Kind:        model.ChangeModified,
				Severity:    model.SeverityWarning,
				Description: fmt.Sprintf("la variable %s está presente en un entorno y ausente en el otro", key),
				A:           va1.State,
				B:           vb1.State,
			}
			if isRequired(rules, key) {
				c.Severity = model.SeverityError
				c.Rule = "variables.required"
				c.Description = fmt.Sprintf("la variable obligatoria %s está ausente en un entorno", key)
				c.Advice = fmt.Sprintf("declara %s en el entorno donde falta (p. ej. en la configuración o secrets del CI); la causa concreta no puede determinarse desde la huella", key)
			}
			out.Changes = append(out.Changes, c)
		default:
			// Values are only comparable when BOTH sides opted into
			// value comparison; otherwise state it as unknown-by-policy.
			if va1.Compare == model.CompareValue && vb1.Compare == model.CompareValue && !sensitive {
				if va1.Value != vb1.Value {
					out.Changes = append(out.Changes, model.Change{
						Path:        path + ".value",
						Kind:        model.ChangeModified,
						Severity:    model.SeverityWarning,
						Description: fmt.Sprintf("el valor de configuración de %s difiere", key),
						A:           va1.Value,
						B:           vb1.Value,
					})
				}
			} else if va1.Compare != vb1.Compare && va1.State == model.StatePresent && vb1.State == model.StatePresent {
				out.Changes = append(out.Changes, model.Change{
					Path:        path,
					Kind:        model.ChangeUnknown,
					Severity:    model.SeverityInfo,
					Description: fmt.Sprintf("no se puede comparar el valor de %s: solo una huella permite comparación por valor", key),
				})
			}
		}
	}
}

// --- helpers (pure, deterministic) ---

func boolstr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func tern[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}

func runtimesByName(f *model.Fingerprint) map[string]model.Runtime {
	m := make(map[string]model.Runtime, len(f.Runtimes))
	for _, rt := range f.Runtimes {
		m[rt.Name] = rt
	}
	return m
}

func filesByPath(f *model.Fingerprint) map[string]model.FileEntry {
	m := make(map[string]model.FileEntry, len(f.Files))
	for _, fe := range f.Files {
		m[fe.Path] = fe
	}
	return m
}

func varsByKey(f *model.Fingerprint) map[string]model.Variable {
	m := make(map[string]model.Variable, len(f.Variables))
	for _, v := range f.Variables {
		m[v.Key] = v
	}
	return m
}

func unionKeys[T any](a, b map[string]T) []string {
	set := map[string]bool{}
	for k := range a {
		set[k] = true
	}
	for k := range b {
		set[k] = true
	}
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func toolDeclared(rules *model.Rules, name string) bool {
	if rules == nil {
		return false
	}
	for _, t := range rules.Tools {
		if t.Name == name {
			return true
		}
	}
	return false
}

func toolMinVersion(rules *model.Rules, name string) string {
	if rules == nil {
		return ""
	}
	for _, t := range rules.Tools {
		if t.Name == name {
			return t.MinVersion
		}
	}
	return ""
}

func isRequired(rules *model.Rules, key string) bool {
	if rules == nil {
		return false
	}
	for _, k := range rules.Variables.Required {
		if k == key {
			return true
		}
	}
	return false
}

// violatesMin reports whether version v (MAJOR.MINOR[.PATCH]) is below min.
// Plain numeric comparison; both are already normalized per contract.
func violatesMin(v, min string) bool {
	return compareVersions(v, min) < 0
}

func compareVersions(a, b string) int {
	pa := semverParts(a)
	pb := semverParts(b)
	for i := range pa {
		switch {
		case pa[i] < pb[i]:
			return -1
		case pa[i] > pb[i]:
			return 1
		}
	}
	return 0
}

func semverParts(v string) [3]int {
	var out [3]int
	for i, p := range strings.SplitN(v, ".", 3) {
		fmt.Sscanf(p, "%d", &out[i])
	}
	return out
}
