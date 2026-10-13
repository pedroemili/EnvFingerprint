// Package fingerprint implements the reproducible SHA-256 hash of an
// environment fingerprint ("sha256-canonical-json-v1"):
//
//  1. Projection: only the fields marked "En hash" in docs/CONTRACTS.md §1
//     are selected. Volatile/metadata fields (schema, tool.*, meta.*,
//     runtimes[].raw/source, variables[].compare, the fingerprint itself and
//     any unknown JSON fields) never participate, by construction.
//  2. Canonicalization: the projection is serialized as canonical JSON —
//     keys sorted by byte order, no whitespace, no HTML escaping, UTF-8.
//     Arrays are defensively sorted by their natural key. Absent, empty and
//     null collections/optional fields produce the identical canonical byte
//     stream (they are omitted), so hashes are comparable across producers
//     and marshallers.
//  3. Domain separation: the SHA-256 input is
//     "sha256-canonical-json-v1\n" + canonicalJSON, so the digest cannot be
//     confused with a hash of other data.
//
// No semantic value normalization happens here (versions/paths are already
// normalized by collectors and enforced by model.Validate); collapsing
// values would hide real differences. Secrets never enter the input:
// variables carry values only when compare=value, which model.Validate
// forbids for sensitive variables, and this package re-checks that rule.
//
// What the hash guarantees: two fingerprints produce the same hash iff their
// hash-selected fields are equal under the rules above. What it does NOT
// guarantee: that two environments are identical (out-of-hash metadata and
// not-collected facts may differ), nor any integrity/provenance property
// (the hash is not a signature).
package fingerprint

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/envfingerprint/envfingerprint/internal/model"
)

// Policy selects which sections participate in the hash. DefaultPolicy
// (nil Sections) includes every hashable section and is what `scan` stamps
// into the document's fingerprint field. Check/compare may use a subset,
// derived from rules.compare.sections, producing a comparison hash that is
// intentionally distinct from the document hash.
type Policy struct {
	Sections map[string]bool // keys: model.Section* constants; nil = all
}

// DefaultPolicy hashes every section.
var DefaultPolicy = Policy{}

func (p Policy) includes(section string) bool {
	if p.Sections == nil {
		return true
	}
	return p.Sections[section]
}

// Compute returns "sha256:<64 hex>" for the hash-selected fields of fp.
// fp must satisfy the contract (validation is run inside); the fingerprint
// field itself is ignored, so recomputation of a loaded document is stable.
func Compute(fp *model.Fingerprint, policy Policy) (string, error) {
	if fp == nil {
		return "", fmt.Errorf("fingerprint: documento nulo")
	}
	if err := fp.Validate(); err != nil {
		return "", fmt.Errorf("no se puede hashear una huella inválida: %w", err)
	}
	canonical, err := canonicalJSON(fp, policy)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(model.HashAlgorithm+"\n"), canonical...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Apply computes the policy hash and stamps it into fp.Fingerprint.
func Apply(fp *model.Fingerprint, policy Policy) error {
	h, err := Compute(fp, policy)
	if err != nil {
		return err
	}
	fp.Fingerprint = h
	return nil
}

// canonicalJSON builds the canonical byte representation of the projection.
// It never touches the document's own JSON: ordering and omission are
// enforced here regardless of how the document was produced.
func canonicalJSON(fp *model.Fingerprint, policy Policy) ([]byte, error) {
	proj := map[string]any{}

	if policy.includes(model.SectionEnvironment) {
		e := fp.Environment
		proj["environment"] = map[string]any{
			"profile":   e.Profile,
			"os":        e.OS,
			"arch":      e.Arch,
			"container": e.Container,
			"ci":        e.CI,
		}
	}

	if policy.includes(model.SectionRuntimes) && len(fp.Runtimes) > 0 {
		rts := append([]model.Runtime{}, fp.Runtimes...)
		sort.Slice(rts, func(i, j int) bool { return rts[i].Name < rts[j].Name })
		var out []any
		for _, rt := range rts {
			out = append(out, map[string]any{
				"name":    rt.Name,
				"version": rt.Version,
			})
		}
		proj["runtimes"] = out
	}

	if policy.includes(model.SectionFiles) && len(fp.Files) > 0 {
		fes := append([]model.FileEntry{}, fp.Files...)
		sort.Slice(fes, func(i, j int) bool { return fes[i].Path < fes[j].Path })
		var out []any
		for _, fe := range fes {
			m := map[string]any{
				"path":    fe.Path,
				"kind":    fe.Kind,
				"present": fe.Present,
			}
			if fe.Digest != "" {
				m["digest"] = fe.Digest
			}
			out = append(out, m)
		}
		proj["files"] = out
	}

	if policy.includes(model.SectionVariables) && len(fp.Variables) > 0 {
		vs := append([]model.Variable{}, fp.Variables...)
		sort.Slice(vs, func(i, j int) bool { return vs[i].Key < vs[j].Key })
		var out []any
		for _, v := range vs {
			if v.Sensitive && v.Value != "" {
				return nil, fmt.Errorf("la variable sensible %s no puede entrar en el hash", v.Key)
			}
			m := map[string]any{
				"key":       v.Key,
				"state":     v.State,
				"sensitive": v.Sensitive,
			}
			// The compare policy is metadata about comparison, not about the
			// environment; only the value (when explicitly allowed) enters.
			if v.Compare == model.CompareValue && v.Value != "" {
				m["value"] = v.Value
			}
			out = append(out, m)
		}
		proj["variables"] = out
	}

	// Go's encoding/json serializes maps with keys sorted by byte order —
	// exactly the key-ordering rule of our canonical form. HTML escaping is
	// disabled so values like "a>b" hash to their literal bytes.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(proj); err != nil {
		return nil, fmt.Errorf("no se pudo canonicalizar: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
