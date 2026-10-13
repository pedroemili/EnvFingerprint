// Package redact is EnvFingerprint's security boundary for sensitive data.
//
// Principles (see docs/SECURITY.md):
//
//  1. Minimum collection: the collector only reads explicitly declared
//     variables; it is the first and strongest barrier.
//  2. Classification: a variable is sensitive if it matches
//     model.DefaultSensitivePatterns (PASSWORD, TOKEN, SECRET, API_KEY,
//     PRIVATE_KEY, connection strings — conservative suffix globs), a project
//     pattern (variables.sensitivePatterns), or an explicit project name
//     (variables.sensitive).
//  3. Defense in depth: Scrub is applied to every fingerprint right before
//     hashing/serialization, forcibly removing any value from a sensitive
//     variable even if some earlier layer misbehaved.
//
// We never store, hash or compare secret values: a plain hash of a low-entropy
// secret is a dictionary-attack oracle. Presence is all that is recorded.
// Nothing is uploaded or shared automatically; all output stays local.
package redact

import (
	"github.com/envfingerprint/envfingerprint/internal/model"
)

// Classifier decides whether a variable name is sensitive.
type Classifier struct {
	exact map[string]bool // variables.sensitive (explicit names)
	extra []string        // variables.sensitivePatterns (globs)
}

// NewClassifier builds a classifier from project rules.
func NewClassifier(v model.VariableRules) Classifier {
	c := Classifier{exact: make(map[string]bool, len(v.Sensitive))}
	for _, name := range v.Sensitive {
		c.exact[name] = true
	}
	c.extra = append([]string{}, v.SensitivePatterns...)
	return c
}

// Sensitive reports whether key must be treated as secret.
func (c Classifier) Sensitive(key string) bool {
	return c.exact[key] || model.IsSensitive(key, c.extra)
}

// Scrub returns a copy of fp where every sensitive variable is presence-only
// (value removed, compare forced to presence). It reports the keys it had to
// fix — a non-empty list means an upstream layer violated the contract,
// which callers should surface as a diagnostic.
//
// Scan must run Scrub after collection and before hashing/serialization.
func (c Classifier) Scrub(fp *model.Fingerprint) (clean *model.Fingerprint, fixed []string) {
	out := *fp
	out.Variables = make([]model.Variable, len(fp.Variables))
	copy(out.Variables, fp.Variables)
	for i, v := range out.Variables {
		if c.Sensitive(v.Key) {
			if v.Value != "" || v.Compare == model.CompareValue || !v.Sensitive {
				fixed = append(fixed, v.Key)
			}
			out.Variables[i].Sensitive = true
			out.Variables[i].Compare = model.ComparePresence
			out.Variables[i].Value = ""
		}
	}
	return &out, fixed
}
