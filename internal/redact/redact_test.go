package redact

import (
	"testing"

	"github.com/envfingerprint/envfingerprint/internal/model"
)

func rules(names, patterns []string) model.VariableRules {
	return model.VariableRules{Sensitive: names, SensitivePatterns: patterns}
}

func TestClassifierDefaultPatterns(t *testing.T) {
	c := NewClassifier(model.VariableRules{})
	sensitive := []string{
		"DB_PASSWORD", "PASSWORD", "GITHUB_TOKEN", "TOKEN", "AWS_SECRET",
		"SECRET", "STRIPE_API_KEY", "API_KEY", "PRIVATE_KEY", "MY_PRIVATE_KEY",
		"DATABASE_URL", "REDIS_URI", "AMQP_DSN", "MASTER_PASS", "OAUTH_CREDENTIALS",
	}
	for _, k := range sensitive {
		if !c.Sensitive(k) {
			t.Errorf("%q debe clasificarse como sensible por defecto", k)
		}
	}
	not := []string{"NODE_ENV", "PATH_STYLE", "CACHE_DIR", "GOFLAGS"}
	for _, k := range not {
		if c.Sensitive(k) {
			t.Errorf("%q NO debe clasificarse como sensible por defecto", k)
		}
	}
}

// Limitation, tested on purpose: a key whose name does not match any pattern
// is NOT sensitive unless the project declares it explicitly.
func TestClassifierUnknownNamesNeedExplicitDeclaration(t *testing.T) {
	c := NewClassifier(model.VariableRules{})
	if c.Sensitive("X_WEIRD_CREDZ") {
		t.Fatal("nombre desconocido no puede ser sensible por magia")
	}
	c2 := NewClassifier(rules([]string{"X_WEIRD_CREDZ"}, nil))
	if !c2.Sensitive("X_WEIRD_CREDZ") {
		t.Fatal("nombre declarado explícitamente debe ser sensible")
	}
	c3 := NewClassifier(rules(nil, []string{"ACME_*"}))
	if !c3.Sensitive("ACME_SIGNING_MATERIAL") {
		t.Fatal("patrón del proyecto debe aplicar")
	}
}

func TestScrubForcesPresenceOnly(t *testing.T) {
	fp := &model.Fingerprint{
		Variables: []model.Variable{
			// Misconfigured upstream: sensitive key carrying a value.
			{Key: "DB_PASSWORD", State: model.StatePresent, Sensitive: false, Compare: model.CompareValue, Value: "s3cr3t-inyectado"},
			// Explicitly declared name, not matching any pattern.
			{Key: "X_WEIRD_CREDZ", State: model.StatePresent, Sensitive: false, Compare: model.CompareValue, Value: "p4ss"},
			// Legit non-sensitive value passes through.
			{Key: "NODE_ENV", State: model.StatePresent, Sensitive: false, Compare: model.CompareValue, Value: "production"},
			{Key: "ABSENT_ONE", State: model.StateAbsent, Sensitive: false, Compare: model.ComparePresence},
		},
	}
	clean, fixed := NewClassifier(rules([]string{"X_WEIRD_CREDZ"}, nil)).Scrub(fp)

	for _, v := range clean.Variables {
		switch v.Key {
		case "DB_PASSWORD", "X_WEIRD_CREDZ":
			if v.Value != "" || v.Compare != model.ComparePresence || !v.Sensitive {
				t.Errorf("%s no quedó saneada: %+v", v.Key, v)
			}
		case "NODE_ENV":
			if v.Value != "production" || v.Compare != model.CompareValue {
				t.Errorf("NODE_ENV no sensible debe conservar valor: %+v", v)
			}
		case "ABSENT_ONE":
			if v.State != model.StateAbsent || v.Value != "" {
				t.Errorf("variable ausente mal saneada: %+v", v)
			}
		}
	}
	if len(fixed) != 2 {
		t.Errorf("fixed = %v, esperaba 2 entradas", fixed)
	}
	// Scrub must not mutate the input.
	if fp.Variables[0].Value != "s3cr3t-inyectado" {
		t.Error("Scrub mutó el documento original")
	}
}

func TestScrubCleanDocumentReportsNothing(t *testing.T) {
	fp := &model.Fingerprint{
		Variables: []model.Variable{
			{Key: "DB_PASSWORD", State: model.StatePresent, Sensitive: true, Compare: model.ComparePresence},
		},
	}
	_, fixed := NewClassifier(model.VariableRules{}).Scrub(fp)
	if len(fixed) != 0 {
		t.Errorf("fixed = %v, esperaba vacío", fixed)
	}
}
