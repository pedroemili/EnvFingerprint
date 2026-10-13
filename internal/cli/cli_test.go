package cli

import (
	"bytes"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (code int, out, errOut string) {
	t.Helper()
	var o, e bytes.Buffer
	code = Run(args, &o, &e)
	return code, o.String(), e.String()
}

func TestHelp(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"help"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			code, out, errOut := run(t, args...)
			if code != ExitOK {
				t.Fatalf("exit = %d, want %d", code, ExitOK)
			}
			if errOut != "" {
				t.Fatalf("stderr not empty: %q", errOut)
			}
			for _, cmd := range []string{"scan", "compare", "check", "report"} {
				if !strings.Contains(out, cmd) {
					t.Errorf("help should describe command %q", cmd)
				}
			}
			for _, ec := range []string{"0", "1", "2"} {
				if !strings.Contains(out, "Códigos de salida") || !strings.Contains(out, ec) {
					t.Errorf("help should document exit code %s", ec)
				}
			}
		})
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := run(t, "--version")
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "envfingerprint "+Version) {
		t.Fatalf("version output %q does not contain embedded version %q", out, Version)
	}
}

func TestNoArgsIsUsageError(t *testing.T) {
	code, _, errOut := run(t)
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errOut, "falta un comando") {
		t.Fatalf("expected clear usage error, got %q", errOut)
	}
}

func TestUnknownCommand(t *testing.T) {
	code, _, errOut := run(t, "frobnicate")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errOut, `comando desconocido "frobnicate"`) {
		t.Fatalf("unexpected error: %q", errOut)
	}
}

func TestPendingCommandsDoNotFpretend(t *testing.T) {
	cases := map[string][]string{
		"check":  {"check"},
		"report": {"report", "a.json"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, out, errOut := run(t, args...)
			if code != ExitUsage {
				t.Fatalf("exit = %d, want %d (pending must not report success)", code, ExitUsage)
			}
			if out != "" {
				t.Fatalf("pending command must not write to stdout, got %q", out)
			}
			if !strings.Contains(errOut, "pendiente de implementación") {
				t.Fatalf("pending message missing, got %q", errOut)
			}
		})
	}
}

func TestUsageErrors(t *testing.T) {
	cases := map[string]struct {
		args    []string
		wantMsg string
	}{
		"scan extra positional":   {[]string{"scan", "file.json"}, "no acepta argumentos posicionales"},
		"compare missing args":    {[]string{"compare", "a.json"}, "requiere exactamente 2"},
		"compare no args":         {[]string{"compare"}, "requiere exactamente 2"},
		"check extra positional":  {[]string{"check", "x"}, "no acepta argumentos posicionales"},
		"report missing input":    {[]string{"report"}, "requiere exactamente 1"},
		"report bad format":       {[]string{"report", "--format", "pdf", "a.json"}, "--format debe ser md o txt"},
		"unknown flag":            {[]string{"scan", "--nope"}, "scan"},
		"unknown flag on compare": {[]string{"compare", "--nope", "a", "b"}, "compare"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			code, _, errOut := run(t, tc.args...)
			if code != ExitUsage {
				t.Fatalf("exit = %d, want %d; stderr=%q", code, ExitUsage, errOut)
			}
			if !strings.Contains(errOut, tc.wantMsg) {
				t.Fatalf("error %q should contain %q", errOut, tc.wantMsg)
			}
		})
	}
}

func TestCommandHelp(t *testing.T) {
	for _, cmd := range []string{"scan", "compare", "check", "report"} {
		t.Run(cmd, func(t *testing.T) {
			code, out, _ := run(t, cmd, "--help")
			if code != ExitOK {
				t.Fatalf("exit = %d", code)
			}
			if !strings.Contains(out, "Uso: envfingerprint "+cmd) {
				t.Fatalf("usage line missing: %q", out)
			}
		})
	}
}

func TestScanFlagsParse(t *testing.T) {
	// Unknown rule file given explicitly is a hard error (exit 2) with a
	// clear message — flags parsed fine, so this is not a usage error.
	code, _, errOut := run(t, "scan", "--rules", "custom.json", "--out", "fp.json")
	if code != ExitUsage || !strings.Contains(errOut, `no se pudo leer las reglas`) {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
}

func TestCompareFlagsParse(t *testing.T) {
	// Flags parse fine; the failure must be a file error, not a flag error.
	code, _, errOut := run(t, "compare", "--json", "--exit-code", "a.json", "b.json")
	if code != ExitUsage || !strings.Contains(errOut, "no se pudo leer la huella") {
		t.Fatalf("exit=%d stderr=%q", code, errOut)
	}
}
