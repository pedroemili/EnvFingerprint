// Package model defines the public JSON data contracts of EnvFingerprint
// (fingerprint, rules, diff) and their authoritative validation.
//
// The JSON schemas in docs/schemas are advisory (editors, external CI); the
// functions here are the ones the CLI enforces. See docs/CONTRACTS.md.
package model

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// SchemaVersion is the only schema version this build can read and write.
const SchemaVersion = 1

// HashAlgorithm identifies the canonicalization+hash recipe. Any change to
// which fields participate in the fingerprint hash must change this value.
const HashAlgorithm = "sha256-canonical-json-v1"

// Errors is a list of validation problems, joined into a single error.
type Errors []string

func (e Errors) Error() string { return "validation failed:\n  - " + joinLines(e) }

func joinLines(e Errors) string {
	out := make([]string, len(e))
	for i, s := range e {
		out[i] = strings.ReplaceAll(s, "\n", " ")
	}
	return strings.Join(out, "\n  - ")
}

func errf(format string, args ...any) string { return fmt.Sprintf(format, args...) }

// decodeJSON decodes data into v. In tolerant mode unknown fields are ignored
// (forward compatibility, see docs/CONTRACTS.md §4); in strict mode they are
// rejected. Trailing garbage is always an error.
func decodeJSON(data []byte, v any, strict bool) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	// Reject trailing content after the top-level value.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("invalid JSON: unexpected content after top-level value")
	}
	return nil
}
