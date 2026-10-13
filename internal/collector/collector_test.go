package collector

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/envfingerprint/envfingerprint/internal/model"
	"github.com/envfingerprint/envfingerprint/internal/redact"
)

// --- Fakes ---

type fakeEnv map[string]string

func (e fakeEnv) Lookup(key string) (string, bool) { v, ok := e[key]; return v, ok }

type fakeProc map[string]string // "go version" -> output; missing key = not installed

func (p fakeProc) Run(ctx context.Context, name string, args ...string) (string, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	out, ok := p[key]
	if !ok {
		return "", fmt.Errorf("%s: %w", name, ErrNotInstalled)
	}
	if out == "__FAIL__" {
		return "", fmt.Errorf("%s: exit status 1: %w", name, ErrExecution)
	}
	if out == "__TIMEOUT__" {
		return "", fmt.Errorf("%s: %w", name, ErrTimeout)
	}
	return out, nil
}

type fakeFS struct {
	files map[string][]byte // rel path -> content
	abs   map[string]bool
}

func (f fakeFS) Exists(rel string) (bool, error) {
	_, ok := f.files[rel]
	return ok, nil
}

func (f fakeFS) Read(rel string, limit int64) ([]byte, error) {
	b, ok := f.files[rel]
	if !ok {
		return nil, fmt.Errorf("no existe: %s", rel)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("demasiado grande")
	}
	return b, nil
}

func (f fakeFS) ExistsAbs(abs string) bool { return f.abs[abs] }

// --- System collector ---

func TestSystemCollectorProfiles(t *testing.T) {
	cases := map[string]struct {
		env         fakeEnv
		abs         map[string]bool
		wantProfile string
		wantCI      bool
		wantCont    bool
	}{
		"local":             {fakeEnv{}, nil, model.ProfileLocal, false, false},
		"ci github":         {fakeEnv{"CI": "true", "GITHUB_ACTIONS": "true"}, nil, model.ProfileCI, true, false},
		"ci false is local": {fakeEnv{"CI": "false"}, nil, model.ProfileLocal, false, false},
		"container wins over ci": {
			fakeEnv{"CI": "true"}, map[string]bool{"/.dockerenv": true},
			model.ProfileContainer, true, true,
		},
		"container env var": {fakeEnv{"container": "docker"}, nil, model.ProfileContainer, false, true},
		"containerenv file": {fakeEnv{}, map[string]bool{"/run/.containerenv": true}, model.ProfileContainer, false, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := systemCollector{env: tc.env, fs: fakeFS{abs: tc.abs}}
			env, diags := c.Collect()
			if diags != nil {
				t.Fatalf("diags: %v", diags)
			}
			if env.Profile != tc.wantProfile || env.CI != tc.wantCI || env.Container != tc.wantCont {
				t.Errorf("got %+v, want profile=%s ci=%v container=%v",
					env, tc.wantProfile, tc.wantCI, tc.wantCont)
			}
		})
	}
}

// --- Tools collector ---

func TestToolsCollectorOutcomes(t *testing.T) {
	proc := fakeProc{
		"go version":        "go version go1.23.2 linux/amd64\n",
		"node --version":    "v20.9.0",
		"python3 --version": "Python 3.12.1",
		// python (without 3) not present: fallback path unexercised
		// dotnet absent entirely
	}
	c := toolsCollector{proc: proc, specs: DefaultToolSpecs}
	rts, diags := c.Collect(context.Background())

	byName := map[string]model.Runtime{}
	for _, rt := range rts {
		byName[rt.Name] = rt
	}
	for name, want := range map[string]string{"go": "1.23.2", "node": "20.9.0", "python": "3.12.1"} {
		if byName[name].Version != want {
			t.Errorf("%s version = %q, want %q", name, byName[name].Version, want)
		}
		if byName[name].Raw == "" || byName[name].Source == "" {
			t.Errorf("%s debe conservar raw y source", name)
		}
	}
	if _, ok := byName["dotnet"]; ok {
		t.Error("dotnet está ausente del fake; no debe aparecer")
	}
	found := false
	for _, d := range diags {
		if d.Message == "dotnet: no instalado" {
			found = true
		}
	}
	if !found {
		t.Errorf("falta diagnóstico de dotnet no instalado: %v", diags)
	}
}

func TestToolsCollectorPythonFallback(t *testing.T) {
	proc := fakeProc{"python --version": "Python 3.9.7"}
	c := toolsCollector{proc: proc, specs: []ToolSpec{DefaultToolSpecs[2]}}
	rts, _ := c.Collect(context.Background())
	if len(rts) != 1 || rts[0].Version != "3.9.7" {
		t.Fatalf("fallback python3→python falló: %+v", rts)
	}
}

func TestToolsCollectorFailuresAreRecoverable(t *testing.T) {
	proc := fakeProc{
		"go version":        "go version go1.23.2 linux/amd64",
		"node --version":    "weird output", // unknown version
		"python3 --version": "__FAIL__",
		"python --version":  "__FAIL__",
		"dotnet --version":  "__TIMEOUT__",
	}
	c := toolsCollector{proc: proc, specs: DefaultToolSpecs}
	rts, diags := c.Collect(context.Background())

	// go survives; the others degrade to diagnostics.
	if len(rts) != 1 || rts[0].Name != "go" {
		t.Fatalf("solo go debía recolectarse: %+v", rts)
	}
	msgs := map[string]bool{}
	for _, d := range diags {
		msgs[d.Message] = true
	}
	for _, want := range []string{
		"node: versión desconocida (salida no reconocida)",
		"dotnet: dotnet: tiempo de ejecución agotado",
	} {
		if !msgs[want] {
			t.Errorf("falta diagnóstico %q en %v", want, msgs)
		}
	}
	if !msgs["python: python3: exit status 1: error de ejecución"] {
		t.Errorf("diagnóstico de python inesperado: %v", msgs)
	}
}

func TestToolsCollectorSelectsSpecs(t *testing.T) {
	specs := selectSpecs([]string{"node"})
	if len(specs) != 1 || specs[0].Name != "node" {
		t.Fatalf("selectSpecs: %+v", specs)
	}
	specs = selectSpecs([]string{"cobol"}) // unknown names are ignored
	if len(specs) != 0 {
		t.Fatalf("herramientas desconocidas deben ignorarse: %+v", specs)
	}
}

// --- Files collector ---

func TestFilesCollector(t *testing.T) {
	fs := fakeFS{files: map[string][]byte{
		"go.mod": []byte("module example.com/fake\n"),
		"go.sum": []byte("hash de prueba\n"),
	}}
	c := filesCollector{fs: fs, specs: []fileSpec{
		{path: "go.mod"}, {path: "go.sum", digest: true}, {path: "yarn.lock"},
	}}
	entries, diags := c.Collect()
	if diags != nil {
		t.Fatalf("diags: %v", diags)
	}
	byPath := map[string]model.FileEntry{}
	for _, e := range entries {
		byPath[e.Path] = e
	}
	if !byPath["go.mod"].Present || byPath["go.mod"].Kind != model.FileKindConfig {
		t.Errorf("go.mod: %+v", byPath["go.mod"])
	}
	sum := byPath["go.sum"]
	if !sum.Present || sum.Kind != model.FileKindLockfile {
		t.Errorf("go.sum: %+v", sum)
	}
	if len(sum.Digest) != len("sha256:")+64 {
		t.Errorf("digest mal formado: %q", sum.Digest)
	}
	if byPath["yarn.lock"].Present {
		t.Error("yarn.lock no existe en el fake")
	}
}

func TestFilesCollectorDefaultsCoverMVPEcosystems(t *testing.T) {
	// Go, npm, pip, poetry, cargo, docker, docker-compose deben estar cubiertos.
	want := []string{"go.mod", "go.sum", "package-lock.json", "requirements.txt",
		"Pipfile.lock", "poetry.lock", "Cargo.lock", "Dockerfile", "docker-compose.yml"}
	seen := map[string]bool{}
	for _, f := range DefaultFiles {
		seen[f.Path] = true
	}
	for _, p := range want {
		if !seen[p] {
			t.Errorf("DefaultFiles no cubre %s", p)
		}
	}
}

// --- Variables collector ---

func TestVariablesCollector(t *testing.T) {
	env := fakeEnv{
		"CFG_PROVIDER": "google",
		"DB_TOKEN":     "valor-secreto",
	}
	c := variablesCollector{
		env:        env,
		declared:   map[string]bool{"CFG_PROVIDER": true, "DB_TOKEN": true, "MISSING_ONE": true},
		compareSet: map[string]bool{"CFG_PROVIDER": true, "DB_TOKEN": true},
		classifier: redact.NewClassifier(model.VariableRules{}),
	}
	vars, diags := c.Collect()
	if diags != nil {
		t.Fatalf("diags: %v", diags)
	}
	byKey := map[string]model.Variable{}
	for _, v := range vars {
		byKey[v.Key] = v
	}

	if got := byKey["CFG_PROVIDER"]; got.State != model.StatePresent || got.Value != "google" || got.Compare != model.CompareValue {
		t.Errorf("CFG_PROVIDER: %+v", got)
	}
	// Defence in depth: sensitive var requested in compareValues → presence only.
	if got := byKey["DB_TOKEN"]; !got.Sensitive || got.Value != "" || got.Compare != model.ComparePresence {
		t.Errorf("DB_TOKEN debe ser solo-presencia: %+v", got)
	}
	if got := byKey["MISSING_ONE"]; got.State != model.StateAbsent {
		t.Errorf("MISSING_ONE: %+v", got)
	}
}

// --- Aggregate ---

func TestCollectProducesValidFingerprint(t *testing.T) {
	deps := Deps{
		Env:  fakeEnv{"CI": "true", "CFG_PROVIDER": "aws"},
		Proc: fakeProc{"go version": "go version go1.23.2 linux/amd64"},
		FS:   fakeFS{files: map[string][]byte{"go.mod": []byte("module x\n")}},
	}
	res, err := Collect(context.Background(), deps, Options{
		Variables: model.VariableRules{Required: []string{"CFG_PROVIDER"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fp := res.Fingerprint
	if fp.Environment.Profile != model.ProfileCI {
		t.Errorf("profile=%q", fp.Environment.Profile)
	}
	if len(fp.Runtimes) != 1 || fp.Runtimes[0].Name != "go" {
		t.Errorf("runtimes: %+v", fp.Runtimes)
	}
	// Sorted, deterministic output.
	for i := 1; i < len(fp.Files); i++ {
		if fp.Files[i-1].Path > fp.Files[i].Path {
			t.Error("files no ordenados")
		}
	}
	for i := 1; i < len(fp.Variables); i++ {
		if fp.Variables[i-1].Key > fp.Variables[i].Key {
			t.Error("variables no ordenadas")
		}
	}
	if err := fp.Validate(); err != nil {
		t.Errorf("huella inválida: %v", err)
	}
}

// --- Real (host) smoke test: tolerant of missing runtimes ---

func TestCollectOnHost(t *testing.T) {
	deps := RealDeps(t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := Collect(ctx, deps, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Fingerprint.Validate(); err != nil {
		t.Fatalf("huella del host inválida: %v", err)
	}
	_ = time.Second
}
