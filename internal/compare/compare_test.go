package compare

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/envfingerprint/envfingerprint/internal/model"
)

func loadFixture(t *testing.T, name string) *model.Fingerprint {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	fp, err := model.LoadFingerprint(data, false)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return fp
}

func loadRulesFixture(t *testing.T) *model.Rules {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := model.LoadRules(data, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	return r
}

func byPath(d *model.DiffResult) map[string]model.Change {
	m := map[string]model.Change{}
	for _, c := range d.Changes {
		m[c.Path] = c
	}
	return m
}

func TestCompareFixturesLocalVsCI(t *testing.T) {
	diff, err := Compare(loadFixture(t, "fingerprint.local.json"), loadFixture(t, "fingerprint.ci.json"), loadRulesFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if !diff.Compatible {
		t.Fatal("fixtures must be mutually compatible")
	}
	if diff.Equal {
		t.Fatal("fixtures differ; equal must be false")
	}
	if err := diff.Validate(); err != nil {
		t.Fatalf("diff no válido: %v", err)
	}

	ch := byPath(diff)

	// Inocuous-looking environment differences → info, never error.
	for _, p := range []string{"environment.profile", "environment.os", "environment.arch", "environment.container", "environment.ci"} {
		c, ok := ch[p]
		if !ok {
			t.Fatalf("falta cambio %s", p)
		}
		if c.Severity != model.SeverityInfo {
			t.Errorf("%s: severity=%s, want info (sin reglas que lo eleven)", p, c.Severity)
		}
	}

	// Runtime version difference → warning with versions.
	node := ch["runtimes[node].version"]
	if node.Kind != model.ChangeModified || node.A != "20.11.0" || node.B != "20.19.0" || node.Severity != model.SeverityWarning {
		t.Errorf("node: %+v", node)
	}

	// Runtime declared in rules but present only on one side → error.
	py := ch["runtimes[python]"]
	if py.Severity != model.SeverityError || py.Rule != "tools" {
		t.Errorf("python: %+v (rules declaran python y falta en CI)", py)
	}

	// Required variable absent on one side → error with grounded advice.
	db := ch["variables[DATABASE_URL].state"]
	if db.Severity != model.SeverityError || db.Rule != "variables.required" {
		t.Errorf("DATABASE_URL: %+v", db)
	}
	if !strings.Contains(db.Advice, "no puede determinarse") {
		t.Errorf("el advice no debe inventar causas: %q", db.Advice)
	}
	// Sensitive: values must never appear anywhere in the diff.
	raw, _ := json.Marshal(diff)
	if strings.Contains(string(raw), "postgres") || strings.Contains(string(raw), "Cl4ve") {
		t.Errorf("valor sensible en la salida: %s", raw)
	}

	// Value difference of a non-sensitive compareValues variable.
	mode := ch["variables[CFG_MODE].value"]
	if mode.Kind != model.ChangeModified || mode.A != "development" || mode.B != "production" {
		t.Errorf("CFG_MODE: %+v", mode)
	}

	// Incomplete data: files only declared in local → added/removed info.
	goMod := ch["files[go.mod]"]
	if goMod.Kind != model.ChangeRemoved || goMod.Severity != model.SeverityInfo {
		t.Errorf("files[go.mod]: %+v", goMod)
	}
	foundDigestNote := false
	for _, c := range diff.Changes {
		if c.Path == "files[go.sum].digest" {
			foundDigestNote = true
		}
	}
	if foundDigestNote {
		t.Error("digest solo disponible en un lado no debe ser una 'diferencia de contenido'")
	}
}

func TestCompareWithoutRulesNoFalseErrors(t *testing.T) {
	diff, err := Compare(loadFixture(t, "fingerprint.local.json"), loadFixture(t, "fingerprint.ci.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range diff.Changes {
		if c.Severity == model.SeverityError {
			t.Errorf("sin reglas ninguna diferencia debe ser error: %+v", c)
		}
	}
}

func TestCompareIdenticalFingerprints(t *testing.T) {
	a := loadFixture(t, "fingerprint.local.json")
	diff, err := Compare(a, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !diff.Equal || len(diff.Changes) != 0 {
		t.Errorf("misma huella debe ser igual: %+v", diff)
	}
}

func TestCompareIncompatibleSchema(t *testing.T) {
	diff, err := Compare(loadFixture(t, "fingerprint.local.json"), loadFixture(t, "fingerprint.schema2.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Compatible {
		t.Fatal("schema 2 debe ser incompatible")
	}
	if diff.Equal {
		t.Fatal("incomparable no puede ser igual")
	}
	found := false
	for _, c := range diff.Changes {
		if c.Path == "schema" && c.Severity == model.SeverityError {
			found = true
		}
	}
	if !found {
		t.Errorf("debe reportar el cambio de esquema como error: %+v", diff.Changes)
	}
}

func TestCompareInvalidDocumentFails(t *testing.T) {
	a := loadFixture(t, "fingerprint.local.json")
	b := loadFixture(t, "fingerprint.local.json")
	b.Variables = []model.Variable{{Key: "DB_PASSWORD", State: model.StatePresent, Sensitive: true, Compare: model.ComparePresence, Value: "leaked"}}
	if _, err := Compare(a, b, nil); err == nil {
		t.Fatal("una huella con secreto en claro debe ser rechazada, no comparada")
	}
}

func TestCompareDeterministicOrder(t *testing.T) {
	a := loadFixture(t, "fingerprint.local.json")
	b := loadFixture(t, "fingerprint.ci.json")
	r := loadRulesFixture(t)
	var first string
	for i := 0; i < 20; i++ {
		diff, err := Compare(a, b, r)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(diff)
		if err != nil {
			t.Fatal(err)
		}
		if first == "" {
			first = string(data)
		} else if string(data) != first {
			t.Fatalf("iteración %d difiere", i)
		}
	}
}

func TestCompareUnknownWhenValueNotComparable(t *testing.T) {
	a := loadFixture(t, "fingerprint.local.json")
	b := loadFixture(t, "fingerprint.ci.json")
	// Both present, but only one allows value comparison.
	b.Variables[0].Compare = model.ComparePresence
	b.Variables[0].Value = ""
	diff, err := Compare(a, b, nil)
	if err != nil {
		t.Fatal(err)
	}
	ch := byPath(diff)
	c, ok := ch["variables[CFG_MODE]"]
	if !ok || c.Kind != model.ChangeUnknown || c.Severity != model.SeverityInfo {
		t.Fatalf("esperaba unknown/info: %+v", c)
	}
	if c.A != "" || c.B != "" {
		t.Errorf("unknown no debe insinuar valores: %+v", c)
	}
	if diff.Equal {
		// equal=false aquí por las diferencias de entorno, no por el unknown;
		// verificado por el test de huellas idénticas.
		t.Error("no debería ser Equal con las diferencias de entorno del fixture")
	}
}

func TestCompareMinVersionViolationIsError(t *testing.T) {
	a := loadFixture(t, "fingerprint.local.json")
	b := loadFixture(t, "fingerprint.ci.json")
	r := loadRulesFixture(t)
	r.Tools[0].MinVersion = "21.0.0" // now both sides violate
	diff, err := Compare(a, b, r)
	if err != nil {
		t.Fatal(err)
	}
	node := byPath(diff)["runtimes[node].version"]
	if node.Severity != model.SeverityError || node.Rule != "tools[node].minVersion" {
		t.Errorf("node: %+v", node)
	}
	if node.Advice == "" {
		t.Error("violar minVersion debe dar una recomendación concreta")
	}
}
