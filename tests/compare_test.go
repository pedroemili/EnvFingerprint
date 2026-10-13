package tests

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/envfingerprint/envfingerprint/internal/cli"
	"github.com/envfingerprint/envfingerprint/internal/model"
)

const (
	fixLocal = "fixtures/fingerprint.local.json"
	fixCI    = "fixtures/fingerprint.ci.json"
	fixNew   = "fixtures/fingerprint.schema2.json"
	fixRules = "fixtures/rules.json"
)

func TestCompareEndToEnd(t *testing.T) {
	code, stdout, stderr := invoke("compare", "--rules", fixRules, fixLocal, fixCI)
	if code != cli.ExitOK {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	assertNoLeak(t, "compare stdout", stdout)
	if !strings.Contains(stdout, "[error] variables[DATABASE_URL].state") {
		t.Errorf("debe marcar la variable requerida ausente como error:\n%s", stdout)
	}
	if !strings.Contains(stdout, "regla: variables.required") {
		t.Errorf("debe citar la regla:\n%s", stdout)
	}
	if !strings.Contains(stdout, "~ [warning] runtimes[node].version") {
		t.Errorf("debe marcar la diferencia de versión de node:\n%s", stdout)
	}
}

func TestCompareJSONAndExitCodes(t *testing.T) {
	code, stdout, _ := invoke("compare", "--json", "--exit-code", fixLocal, fixCI)
	if code != cli.ExitViolation {
		t.Fatalf("exit=%d, want 1 (hay diferencias)", code)
	}
	var d model.DiffResult
	if err := json.Unmarshal([]byte(stdout), &d); err != nil {
		t.Fatalf("stdout no es JSON: %v", err)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("diff inválido: %v", err)
	}
	if d.Equal {
		t.Error("fixtures distintos deben dar equal=false")
	}

	// Identical inputs → exit 0.
	code, _, _ = invoke("compare", "--exit-code", fixLocal, fixLocal)
	if code != cli.ExitOK {
		t.Fatalf("exit=%d, want 0", code)
	}

	// Incompatible schemas → exit 2 even with --exit-code? Yes: comparison
	// cannot be trusted.
	code, stdout, _ = invoke("compare", "--json", "--exit-code", fixLocal, fixNew)
	if code != cli.ExitUsage {
		t.Fatalf("exit=%d, want 2", code)
	}
	var d2 model.DiffResult
	if err := json.Unmarshal([]byte(stdout), &d2); err != nil {
		t.Fatalf("stdout no es JSON: %v", err)
	}
	if d2.Compatible {
		t.Error("schema 2 debe ser incompatible")
	}

	// Invalid JSON input → error mentioning the file, exit 2.
	code, _, stderr := invoke("compare", fixLocal, "no-existe.json")
	if code != cli.ExitUsage || !strings.Contains(stderr, "no-existe.json") {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
}
