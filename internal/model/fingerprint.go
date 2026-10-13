package model

import (
	"fmt"
	"regexp"
	"strings"
)

// Fingerprint is the environment fingerprint document (schema v1).
// Field semantics, normalization and hash inclusion are defined in
// docs/CONTRACTS.md §1 — those rules are enforced by Validate.
type Fingerprint struct {
	Schema      int         `json:"schema"`
	Tool        Tool        `json:"tool"`
	Environment Environment `json:"environment"`
	Runtimes    []Runtime   `json:"runtimes,omitempty"`
	Files       []FileEntry `json:"files,omitempty"`
	Variables   []Variable  `json:"variables,omitempty"`
	Meta        Meta        `json:"meta"`
	Fingerprint string      `json:"fingerprint"`
}

// Tool identifies the producer of the fingerprint. Excluded from the hash:
// fingerprints must be reproducible across tool versions.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"` // semver MAJOR.MINOR.PATCH, no leading "v"
}

// Profile values for Environment.Profile.
const (
	ProfileLocal     = "local"
	ProfileContainer = "container"
	ProfileCI        = "ci"
	ProfileUnknown   = "unknown"
)

type Environment struct {
	Profile   string `json:"profile"`
	OS        string `json:"os"`   // GOOS vocabulary, lowercase
	Arch      string `json:"arch"` // GOARCH vocabulary, lowercase
	Container bool   `json:"container"`
	CI        bool   `json:"ci"`
}

type Runtime struct {
	Name    string `json:"name"`             // lowercase, ^[a-z0-9._-]+$
	Version string `json:"version"`          // normalized MAJOR.MINOR[.PATCH]
	Raw     string `json:"raw,omitempty"`    // volatile, never hashed
	Source  string `json:"source,omitempty"` // e.g. "go version", volatile, never hashed
}

// FileKind values for FileEntry.Kind.
const (
	FileKindConfig   = "config"
	FileKindLockfile = "lockfile"
)

type FileEntry struct {
	Path    string `json:"path"` // relative, '/' separators, no '..' or absolute
	Kind    string `json:"kind"`
	Present bool   `json:"present"`
	Digest  string `json:"digest,omitempty"` // "sha256:<64 hex>", only if requested
}

// Variable describes one declared configuration variable. Values of sensitive
// variables are never stored (see Variable.Sensitive and Validate).
type Variable struct {
	Key       string `json:"key"`
	State     string `json:"state"` // StatePresent | StateAbsent
	Sensitive bool   `json:"sensitive"`
	Compare   string `json:"compare"`         // ComparePresence | CompareValue
	Value     string `json:"value,omitempty"` // forbidden when Sensitive
}

const (
	StatePresent = "present"
	StateAbsent  = "absent"

	ComparePresence = "presence"
	CompareValue    = "value"
)

type Meta struct {
	HashAlgorithm string `json:"hashAlgorithm"`
}

var (
	namePattern   = regexp.MustCompile(`^[a-z0-9._-]+$`)
	envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	semverPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	semverTool    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
)

// checkSchema reports a compatibility error when the document schema is not
// the one supported by this build (docs/CONTRACTS.md §4).
func checkSchema(schema int) error {
	switch {
	case schema == SchemaVersion:
		return nil
	case schema > SchemaVersion:
		return fmt.Errorf("incompatible schema version %d: document was produced by a newer envfingerprint; please upgrade (supported: %d)", schema, SchemaVersion)
	default:
		return fmt.Errorf("incompatible schema version %d (supported: %d)", schema, SchemaVersion)
	}
}

// isRelativePath enforces the normalization rule for file paths: relative,
// no '..', no POSIX absolute paths, no Windows drive letters or UNC.
func isRelativePath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || regexpWindowsAbs.MatchString(p) {
		return false
	}
	for _, seg := range splitPath(p) {
		if seg == ".." {
			return false
		}
	}
	return true
}

var regexpWindowsAbs = regexp.MustCompile(`^([A-Za-z]:[\\/]|\\\\)`)

func splitPath(p string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(p); i++ {
		if i == len(p) || p[i] == '/' || p[i] == '\\' {
			out = append(out, p[start:i])
			start = i + 1
		}
	}
	return out
}

// LoadFingerprint decodes a fingerprint document. Tolerant: unknown fields are
// ignored. Use ValidateFingerprint afterwards; pass strict=true (e.g. for
// --strict) to also reject unknown fields at decode time.
func LoadFingerprint(data []byte, strict bool) (*Fingerprint, error) {
	var f Fingerprint
	if err := decodeJSON(data, &f, strict); err != nil {
		return nil, err
	}
	return &f, nil
}

// Validate checks every rule of the fingerprint contract. It returns all
// problems found, or nil. A fingerprint with an empty Fingerprint field is
// valid only as an intermediate value before hashing; callers producing final
// documents must fill it.
func (f *Fingerprint) Validate() error {
	var errs Errors

	if err := checkSchema(f.Schema); err != nil {
		errs = append(errs, errf("schema: %v", err))
	}
	if f.Tool.Name != "envfingerprint" {
		errs = append(errs, errf("tool.name: must be \"envfingerprint\", got %q", f.Tool.Name))
	}
	if !semverTool.MatchString(f.Tool.Version) {
		errs = append(errs, errf("tool.version: must be MAJOR.MINOR.PATCH semver without \"v\" prefix, got %q", f.Tool.Version))
	}

	switch f.Environment.Profile {
	case ProfileLocal, ProfileContainer, ProfileCI, ProfileUnknown:
	default:
		errs = append(errs, errf("environment.profile: unknown value %q", f.Environment.Profile))
	}
	if !namePattern.MatchString(f.Environment.OS) {
		errs = append(errs, errf("environment.os: must be lowercase (GOOS vocabulary), got %q", f.Environment.OS))
	}
	if !namePattern.MatchString(f.Environment.Arch) {
		errs = append(errs, errf("environment.arch: must be lowercase (GOARCH vocabulary), got %q", f.Environment.Arch))
	}

	for i, rt := range f.Runtimes {
		where := errf("runtimes[%d]", i)
		if !namePattern.MatchString(rt.Name) {
			errs = append(errs, errf("%s.name: must match ^[a-z0-9._-]+$, got %q", where, rt.Name))
		}
		if !semverPattern.MatchString(rt.Version) {
			errs = append(errs, errf("%s.version: must be normalized MAJOR.MINOR[.PATCH], got %q (raw output belongs in .raw)", where, rt.Version))
		}
	}

	for i, fe := range f.Files {
		where := errf("files[%d]", i)
		if !isRelativePath(fe.Path) {
			errs = append(errs, errf("%s.path: must be a relative path without '..', got %q", where, fe.Path))
		}
		if fe.Kind != FileKindConfig && fe.Kind != FileKindLockfile {
			errs = append(errs, errf("%s.kind: must be %q or %q, got %q", where, FileKindConfig, FileKindLockfile, fe.Kind))
		}
		if fe.Digest != "" && !digestPattern.MatchString(fe.Digest) {
			errs = append(errs, errf("%s.digest: must be \"sha256:<64 lowercase hex>\", got %q", where, fe.Digest))
		}
	}

	for i, v := range f.Variables {
		where := errf("variables[%d]", i)
		if !envKeyPattern.MatchString(v.Key) {
			errs = append(errs, errf("%s.key: invalid environment variable name %q", where, v.Key))
		}
		if v.State != StatePresent && v.State != StateAbsent {
			errs = append(errs, errf("%s.state: must be %q or %q, got %q", where, StatePresent, StateAbsent, v.State))
		}
		if v.Compare != ComparePresence && v.Compare != CompareValue {
			errs = append(errs, errf("%s.compare: must be %q or %q, got %q", where, ComparePresence, CompareValue, v.Compare))
		}
		if v.Sensitive && v.Compare == CompareValue {
			errs = append(errs, errf("%s: sensitive variable %q cannot have compare=value", where, v.Key))
		}
		if v.Sensitive && v.Value != "" {
			errs = append(errs, errf("%s: value of sensitive variable %q must never be recorded", where, v.Key))
		}
		if v.State == StateAbsent && v.Value != "" {
			errs = append(errs, errf("%s: value present for absent variable %q", where, v.Key))
		}
	}

	if f.Meta.HashAlgorithm != HashAlgorithm {
		errs = append(errs, errf("meta.hashAlgorithm: must be %q, got %q", HashAlgorithm, f.Meta.HashAlgorithm))
	}
	if f.Fingerprint != "" && !digestPattern.MatchString(f.Fingerprint) {
		errs = append(errs, errf("fingerprint: must be empty or \"sha256:<64 lowercase hex>\", got %q", f.Fingerprint))
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}
