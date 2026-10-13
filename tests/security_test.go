package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/envfingerprint/envfingerprint/internal/cli"
	"github.com/envfingerprint/envfingerprint/internal/model"
)

// Security audit: fictitious secrets of many shapes must never leak into the
// fingerprint JSON, stderr/logs, error messages or the dry-run preview.
// The secrets exist ONLY in t.Setenv; if any byte sequence appears in any
// output, the test fails.

var auditSecrets = map[string]string{
	"DB_PASSWORD":   "s3cr3t-Aug-2026!",
	"API_TOKEN":     "ghp_FICTICIO_AbCdEf0123456789",
	"PRIVATE_KEY":   "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBg-ficticio\n-----END PRIVATE KEY-----",
	"DATABASE_URL":  "postgres://admin:Cl4veSup3rSecreta@db.internal:5432/app",
	"CUSTOM_CREDZ":  "credenciales-con-nombre-raro-0000",
	"EMPTY_SECRET":  "",
	"MISSING_TOKEN": "", // unset below
}

func auditProject(t *testing.T) (dir string, outputs []string) {
	t.Helper()
	dir = t.TempDir()
	writeFile(t, dir, ".envfingerprint.json", `{
	  "schema": 1,
	  "variables": {
	    "required": ["DB_PASSWORD", "API_TOKEN", "PRIVATE_KEY", "DATABASE_URL", "CUSTOM_CREDZ", "EMPTY_SECRET", "MISSING_TOKEN", "CFG_MODE"],
	    "compareValues": ["CFG_MODE"],
	    "sensitive": ["CUSTOM_CREDZ"]
	  },
	  "tools": [{"name": "go"}],
	  "files": ["go.mod"]
	}`)
	writeFile(t, dir, "go.mod", "module example.com/fake\n\ngo 1.22\n")
	return dir, nil
}

func setAuditEnv(t *testing.T) {
	for k, v := range auditSecrets {
		if k == "MISSING_TOKEN" {
			os.Unsetenv(k)
			continue
		}
		t.Setenv(k, v)
	}
	t.Setenv("CFG_MODE", "demo")
}

func assertNoLeak(t *testing.T, label, text string) {
	t.Helper()
	for key, secret := range auditSecrets {
		if secret == "" {
			continue
		}
		if strings.Contains(text, secret) {
			t.Errorf("FUGA en %s: contiene el secreto de %s", label, key)
		}
		// Also check distinguishing fragments (URL user/pass, key body).
		for _, frag := range []string{"Cl4veSup3rSecreta", "MIIEvgIBADANBg-ficticio", "FICTICIO_AbCd"} {
			if strings.Contains(text, frag) {
				t.Errorf("FUGA en %s: contiene fragmento %q", label, frag)
			}
		}
	}
}

func TestAuditScanLeaksNothing(t *testing.T) {
	dir, _ := auditProject(t)
	setAuditEnv(t)
	chdir(t, dir)

	out := filepath.Join(dir, "fp.json")
	code, stdout, stderr := invoke("scan", "--out", out)
	if code != cli.ExitOK {
		t.Fatalf("scan exit=%d stderr=%q", code, stderr)
	}
	assertNoLeak(t, "stderr", stderr)
	assertNoLeak(t, "stdout", stdout)

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	assertNoLeak(t, "huella JSON", string(data))

	fp, err := model.LoadFingerprint(data, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := fp.Validate(); err != nil {
		t.Fatal(err)
	}
	vars := map[string]model.Variable{}
	for _, v := range fp.Variables {
		vars[v.Key] = v
		if v.Sensitive && v.Value != "" {
			t.Errorf("variable sensible con valor: %+v", v)
		}
	}
	// Explicitly declared sensitive name wins over pattern miss.
	if !vars["CUSTOM_CREDZ"].Sensitive {
		t.Error("CUSTOM_CREDZ debía marcarse sensible por declaración explícita")
	}
	// Empty-but-present sensitive variable: presence only, no panic.
	if got := vars["EMPTY_SECRET"]; got.State != model.StatePresent || got.Value != "" {
		t.Errorf("EMPTY_SECRET: %+v", got)
	}
	if got := vars["MISSING_TOKEN"]; got.State != model.StateAbsent {
		t.Errorf("MISSING_TOKEN: %+v", got)
	}
	// Non-sensitive compareValues keep their value.
	if vars["CFG_MODE"].Value != "demo" {
		t.Errorf("CFG_MODE: %+v", vars["CFG_MODE"])
	}
}

func TestAuditDryRunRevealsNothing(t *testing.T) {
	dir, _ := auditProject(t)
	setAuditEnv(t)
	chdir(t, dir)

	code, stdout, stderr := invoke("scan", "--dry-run")
	if code != cli.ExitOK {
		t.Fatalf("dry-run exit=%d stderr=%q", code, stderr)
	}
	assertNoLeak(t, "dry-run stdout", stdout)
	assertNoLeak(t, "dry-run stderr", stderr)
	for _, expect := range []string{
		"vista previa",
		"DB_PASSWORD [SENSIBLE: solo presencia, nunca valor]",
		"CUSTOM_CREDZ [SENSIBLE: solo presencia, nunca valor]",
		"CFG_MODE [no sensible: se registrará y comparará el valor]",
	} {
		if !strings.Contains(stdout, expect) {
			t.Errorf("dry-run debe contener %q; salida:\n%s", expect, stdout)
		}
	}
	// Dry run must not create any file.
	if _, err := os.Stat(filepath.Join(dir, "fp.json")); !os.IsNotExist(err) {
		t.Error("dry-run no debe escribir archivos")
	}
}

func TestAuditErrorsLeakNothing(t *testing.T) {
	dir, _ := auditProject(t)
	setAuditEnv(t)
	chdir(t, dir)

	// Malformed rules file.
	writeFile(t, dir, "bad.json", `{ not json`)
	code, _, stderr := invoke("scan", "--rules", "bad.json")
	if code != cli.ExitUsage {
		t.Fatalf("exit=%d", code)
	}
	assertNoLeak(t, "error de reglas", stderr)

	// Illegal config: sensitive variable in compareValues. The error names the
	// KEY, never values (values live only in env here).
	writeFile(t, dir, "illegal.json", `{"schema":1,"variables":{"compareValues":["DB_PASSWORD"]}}`)
	code, _, stderr = invoke("scan", "--rules", "illegal.json")
	if code != cli.ExitUsage || !strings.Contains(stderr, "nunca puede registrarse") {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	assertNoLeak(t, "error de validación", stderr)

	// Missing explicitly requested rules file.
	code, _, stderr = invoke("scan", "--rules", "no-existo.json")
	if code != cli.ExitUsage {
		t.Fatalf("exit=%d", code)
	}
	assertNoLeak(t, "error de archivo", stderr)
}
