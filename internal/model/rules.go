package model

import "path"

// DefaultSensitivePatterns are always active, on top of any patterns a
// project declares. A variable matching any of these is presence-only:
// its value is never recorded, hashed, compared or printed.
var DefaultSensitivePatterns = []string{
	"*_TOKEN", "*_SECRET", "*_PASSWORD", "*_KEY", "*_CREDENTIALS", "*_PASS",
	"*_URL", "*_URI", "*_DSN", // conexiones que suelen llevar credenciales incrustadas
}

// Rules is the project rules document (.envfingerprint.json, schema v1).
// See docs/CONTRACTS.md §2.
type Rules struct {
	Schema    int           `json:"schema"`
	Variables VariableRules `json:"variables,omitempty"`
	Tools     []ToolRule    `json:"tools,omitempty"`
	Files     []string      `json:"files,omitempty"`
	// FileDigests lists a subset of Files whose content digest is recorded.
	FileDigests         []string     `json:"fileDigests,omitempty"`
	Compare             CompareRules `json:"compare,omitempty"`
	ExpectedFingerprint string       `json:"expectedFingerprint,omitempty"`
}

type VariableRules struct {
	// Required must be present in the environment; presence-only checks.
	Required []string `json:"required,omitempty"`
	// CompareValues names non-sensitive variables whose values may be
	// recorded and compared. Naming a sensitive variable here is an error.
	CompareValues []string `json:"compareValues,omitempty"`
	// SensitivePatterns extend DefaultSensitivePatterns (glob, uppercase suffix style).
	SensitivePatterns []string `json:"sensitivePatterns,omitempty"`
}

type ToolRule struct {
	Name       string `json:"name"`
	MinVersion string `json:"minVersion,omitempty"` // semver, optional
}

// Section names valid in CompareRules.Sections.
const (
	SectionEnvironment = "environment"
	SectionRuntimes    = "runtimes"
	SectionFiles       = "files"
	SectionVariables   = "variables"
)

type CompareRules struct {
	// Sections limits which parts of a fingerprint participate in diff and
	// expectedFingerprint validation. Empty means all sections.
	Sections []string `json:"sections,omitempty"`
}

// IsSensitive reports whether key is sensitive under the given extra patterns
// plus the built-in defaults.
func IsSensitive(key string, extraPatterns []string) bool {
	for _, pat := range append(append([]string{}, DefaultSensitivePatterns...), extraPatterns...) {
		if ok, err := path.Match(pat, key); err == nil && ok {
			return true
		}
	}
	return false
}

// LoadRules decodes a rules document (tolerant by default, like LoadFingerprint).
func LoadRules(data []byte, strict bool) (*Rules, error) {
	var r Rules
	if err := decodeJSON(data, &r, strict); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *Rules) Validate() error {
	var errs Errors

	if err := checkSchema(r.Schema); err != nil {
		errs = append(errs, errf("schema: %v", err))
	}

	required := map[string]bool{}
	for i, key := range r.Variables.Required {
		if !envKeyPattern.MatchString(key) {
			errs = append(errs, errf("variables.required[%d]: invalid environment variable name %q", i, key))
		}
		if required[key] {
			errs = append(errs, errf("variables.required: duplicate entry %q", key))
		}
		required[key] = true
	}
	for i, key := range r.Variables.CompareValues {
		if !envKeyPattern.MatchString(key) {
			errs = append(errs, errf("variables.compareValues[%d]: invalid environment variable name %q", i, key))
		}
		if IsSensitive(key, r.Variables.SensitivePatterns) {
			// Security rule: a sensitive variable must never be value-compared,
			// otherwise its value would end up recorded in fingerprints.
			errs = append(errs, errf("variables.compareValues[%d]: %q matches a sensitive pattern; its value must never be recorded", i, key))
		}
	}
	for i, pat := range r.Variables.SensitivePatterns {
		if _, err := path.Match(pat, "PROBE"); err != nil {
			errs = append(errs, errf("variables.sensitivePatterns[%d]: invalid glob %q: %v", i, pat, err))
		}
	}

	toolNames := map[string]bool{}
	for i, t := range r.Tools {
		where := errf("tools[%d]", i)
		if !namePattern.MatchString(t.Name) {
			errs = append(errs, errf("%s.name: must match ^[a-z0-9._-]+$, got %q", where, t.Name))
		}
		if toolNames[t.Name] {
			errs = append(errs, errf("%s.name: duplicate tool %q", where, t.Name))
		}
		toolNames[t.Name] = true
		if t.MinVersion != "" && !semverPattern.MatchString(t.MinVersion) {
			errs = append(errs, errf("%s.minVersion: must be MAJOR.MINOR[.PATCH], got %q", where, t.MinVersion))
		}
	}

	files := map[string]bool{}
	for i, p := range r.Files {
		if !isRelativePath(p) {
			errs = append(errs, errf("files[%d]: must be a relative path without '..', got %q", i, p))
		}
		if files[p] {
			errs = append(errs, errf("files: duplicate entry %q", p))
		}
		files[p] = true
	}
	for i, p := range r.FileDigests {
		if !files[p] {
			errs = append(errs, errf("fileDigests[%d]: %q is not listed in files", i, p))
		}
	}

	sections := map[string]bool{}
	for i, s := range r.Compare.Sections {
		switch s {
		case SectionEnvironment, SectionRuntimes, SectionFiles, SectionVariables:
		default:
			errs = append(errs, errf("compare.sections[%d]: unknown section %q", i, s))
		}
		if sections[s] {
			errs = append(errs, errf("compare.sections: duplicate entry %q", s))
		}
		sections[s] = true
	}

	if r.ExpectedFingerprint != "" && !digestPattern.MatchString(r.ExpectedFingerprint) {
		errs = append(errs, errf("expectedFingerprint: must be \"sha256:<64 lowercase hex>\""))
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}
