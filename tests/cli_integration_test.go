// Package tests holds integration tests that exercise the CLI surface the way
// end users and CI invoke it (argument lists in, exit code and streams out).
package tests

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/envfingerprint/envfingerprint/internal/cli"
	"github.com/envfingerprint/envfingerprint/internal/model"
)

func invoke(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := cli.Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestVersionFlagEndToEnd(t *testing.T) {
	code, out, _ := invoke("--version")
	if code != 0 || !strings.Contains(out, "0.1.0") {
		t.Fatalf("unexpected: code=%d out=%q", code, out)
	}
}

func TestPendingCommandsEndToEnd(t *testing.T) {
	// Commands whose engines are pending report it explicitly instead of
	// silently doing nothing.
	steps := [][]string{
		{"compare", "--exit-code", "fp-a.json", "fp-b.json"},
		{"check", "--rules", "rules.json"},
		{"report", "--format", "md", "fp.json"},
	}
	for _, args := range steps {
		code, _, errOut := invoke(args...)
		if code != cli.ExitUsage || !strings.Contains(errOut, "pendiente de implementación") {
			t.Errorf("%v: code=%d stderr=%q, want explicit pending message", args, code, errOut)
		}
	}
}

// chdir for Go 1.23 (t.Chdir requires 1.24).
func chdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
}

// TestScanEndToEnd runs a real scan inside a synthetic project: no runtime
// installed on the host is required, because scan tolerates missing tools.
func TestScanEndToEnd(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/fake\n\ngo 1.22\n")
	writeFile(t, dir, "go.sum", "example.com/dep v1.0.0 h1:abc=\n")
	writeFile(t, dir, "docker-compose.yml", "services: {}\n")
	writeFile(t, dir, ".envfingerprint.json", `{
	  "schema": 1,
	  "variables": {
	    "required": ["CFG_PROVIDER", "DB_TOKEN"],
	    "compareValues": ["CFG_PROVIDER"]
	  },
	  "tools": [{"name": "go"}, {"name": "node"}, {"name": "python"}, {"name": "dotnet"}],
	  "files": ["go.mod", "go.sum", "docker-compose.yml"],
	  "fileDigests": ["go.sum"]
	}`)

	t.Setenv("CFG_PROVIDER", "google-ficticio")
	t.Setenv("DB_TOKEN", "mkFicticio123") // sensitive: must never appear in output
	os.Unsetenv("CI")                     // ensure profile is local

	chdir(t, dir)
	out := filepath.Join(dir, "fp.json")
	code, stdout, stderr := invoke("scan", "--out", out)
	if code != cli.ExitOK {
		t.Fatalf("scan exit=%d stderr=%q", code, stderr)
	}
	if !strings.Contains(stdout, "huella escrita") {
		t.Fatalf("unexpected stdout: %q", stdout)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("mkFicticio123")) {
		t.Fatal("¡secreto filtrado en la huella!")
	}

	fp, err := model.LoadFingerprint(data, true)
	if err != nil {
		t.Fatalf("huella no parseable: %v", err)
	}
	if err := fp.Validate(); err != nil {
		t.Fatalf("huella no válida: %v", err)
	}
	if fp.Environment.OS != runtime.GOOS || fp.Environment.Arch != runtime.GOARCH {
		t.Errorf("os/arch inesperados: %+v", fp.Environment)
	}
	if fp.Environment.Profile != model.ProfileLocal {
		t.Errorf("profile = %q, want local (CI unset)", fp.Environment.Profile)
	}

	// File indicators.
	files := map[string]model.FileEntry{}
	for _, f := range fp.Files {
		files[f.Path] = f
	}
	for _, p := range []string{"go.mod", "go.sum", "docker-compose.yml"} {
		if !files[p].Present {
			t.Errorf("files[%s].present = false, want true", p)
		}
	}
	if !strings.HasPrefix(files["go.sum"].Digest, "sha256:") {
		t.Errorf("go.sum debe tener digest (fileDigests): %+v", files["go.sum"])
	}

	// Variables: presence-only for the sensitive one, value for the other.
	vars := map[string]model.Variable{}
	for _, v := range fp.Variables {
		vars[v.Key] = v
	}
	if got := vars["DB_TOKEN"]; !got.Sensitive || got.State != model.StatePresent || got.Value != "" {
		t.Errorf("DB_TOKEN mal recolectada: %+v", got)
	}
	if got := vars["CFG_PROVIDER"]; got.Value != "google-ficticio" || got.Compare != model.CompareValue {
		t.Errorf("CFG_PROVIDER mal recolectada: %+v", got)
	}

	// Audit: every collected runtime version must be normalized.
	for _, rt := range fp.Runtimes {
		if strings.HasPrefix(rt.Version, "v") || strings.Contains(rt.Version, " ") {
			t.Errorf("versión no normalizada: %+v", rt)
		}
	}
	if fp.Fingerprint == "" || !strings.HasPrefix(fp.Fingerprint, "sha256:") {
		t.Errorf("la huella debe llevar hash sha256: %q", fp.Fingerprint)
	}

	// Regression: a second scan in the same environment must reproduce the
	// exact same hash (determinism end-to-end via the CLI).
	out2 := filepath.Join(dir, "fp2.json")
	if code, _, errOut := invoke("scan", "--out", out2); code != cli.ExitOK {
		t.Fatalf("segundo scan: exit=%d stderr=%q", code, errOut)
	}
	data2, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := model.LoadFingerprint(data2, true)
	if err != nil {
		t.Fatal(err)
	}
	if fp2.Fingerprint != fp.Fingerprint {
		t.Errorf("scan no determinista:\n  %s\n  %s", fp.Fingerprint, fp2.Fingerprint)
	}
}

// TestScanStdout writes to stdout when --out is absent.
func TestScanStdout(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	code, stdout, _ := invoke("scan")
	if code != cli.ExitOK {
		t.Fatalf("exit=%d", code)
	}
	var fp model.Fingerprint
	if err := json.Unmarshal([]byte(stdout), &fp); err != nil {
		t.Fatalf("stdout no es JSON válido: %v\n%s", err, stdout)
	}
	if fp.Schema != model.SchemaVersion {
		t.Fatalf("schema=%d", fp.Schema)
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
