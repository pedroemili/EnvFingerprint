package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readTestdata(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return data
}

// --- Fingerprint: valid documents ---

func TestFingerprintValidExample(t *testing.T) {
	data := readTestdata(t, "fingerprint.ci.json")

	f, err := LoadFingerprint(data, false)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("valid example rejected: %v", err)
	}
	if f.Fingerprint == "" {
		t.Fatal("fingerprint field should be present in final document")
	}
}

func TestFingerprintIntermediateWithoutHashIsValid(t *testing.T) {
	f := &Fingerprint{
		Schema:      SchemaVersion,
		Tool:        Tool{Name: "envfingerprint", Version: "0.1.0"},
		Environment: Environment{Profile: ProfileLocal, OS: "linux", Arch: "amd64"},
		Meta:        Meta{HashAlgorithm: HashAlgorithm},
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("intermediate fingerprint should validate: %v", err)
	}
}

// --- Fingerprint: incorrect documents ---

func TestFingerprintInvalid(t *testing.T) {
	base := Fingerprint{
		Schema:      SchemaVersion,
		Tool:        Tool{Name: "envfingerprint", Version: "0.1.0"},
		Environment: Environment{Profile: ProfileCI, OS: "linux", Arch: "amd64"},
		Meta:        Meta{HashAlgorithm: HashAlgorithm},
		Fingerprint: "sha256:" + strings.Repeat("a", 64),
	}

	toolName := func(v string) Fingerprint { f := base; f.Tool.Name = v; return f }
	toolVersion := func(v string) Fingerprint { f := base; f.Tool.Version = v; return f }
	profile := func(v string) Fingerprint { f := base; f.Environment.Profile = v; return f }
	osUpper := func() Fingerprint { f := base; f.Environment.OS = "Linux"; return f }
	runtimeVersion := func(v string) Fingerprint {
		f := base
		f.Runtimes = []Runtime{{Name: "go", Version: v}}
		return f
	}
	filePath := func(p string) Fingerprint {
		f := base
		f.Files = []FileEntry{{Path: p, Kind: FileKindLockfile, Present: true}}
		return f
	}
	variable := func(v Variable) Fingerprint {
		f := base
		f.Variables = []Variable{v}
		return f
	}
	hashAlg := func(v string) Fingerprint { f := base; f.Meta.HashAlgorithm = v; return f }
	fp := func(v string) Fingerprint { f := base; f.Fingerprint = v; return f }

	bad := Variable{Key: "1BAD", State: StatePresent, Sensitive: false, Compare: ComparePresence}
	sensitiveWithValue := Variable{Key: "DB_PASSWORD", State: StatePresent, Sensitive: true, Compare: ComparePresence, Value: "s3cr3t"}
	sensitiveCompareValue := Variable{Key: "API_TOKEN", State: StatePresent, Sensitive: true, Compare: CompareValue}
	absentWithValue := Variable{Key: "NODE_ENV", State: StateAbsent, Sensitive: false, Compare: CompareValue, Value: "prod"}
	badState := Variable{Key: "NODE_ENV", State: "yes", Sensitive: false, Compare: ComparePresence}

	cases := map[string]Fingerprint{
		"tool name wrong":               toolName("other"),
		"tool version not semver":       toolVersion("v0.1.0"),
		"unknown profile":               profile("staging"),
		"os not lowercase":              osUpper(),
		"runtime version w/ v prefix":   runtimeVersion("v1.23.2"),
		"runtime version with raw text": runtimeVersion("go version go1.23.2 linux/amd64"),
		"absolute file path":            filePath("/etc/passwd"),
		"windows absolute path":         filePath(`C:\project\go.sum`),
		"path traversal":                filePath("../secret/go.sum"),
		"invalid variable key":          variable(bad),
		"sensitive value recorded":      variable(sensitiveWithValue),
		"sensitive compare=value":       variable(sensitiveCompareValue),
		"absent var with value":         variable(absentWithValue),
		"invalid state":                 variable(badState),
		"wrong hash algorithm id":       hashAlg("md5"),
		"fingerprint bad format":        fp("9b1c0f"),
	}

	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := doc.Validate(); err == nil {
				t.Fatal("expected validation error, got nil")
			}
		})
	}
}

// --- Fingerprint: schema compatibility ---

func TestFingerprintSchemaCompatibility(t *testing.T) {
	mk := func(schema int) Fingerprint {
		return Fingerprint{
			Schema:      schema,
			Tool:        Tool{Name: "envfingerprint", Version: "0.1.0"},
			Environment: Environment{Profile: ProfileLocal, OS: "linux", Arch: "amd64"},
			Meta:        Meta{HashAlgorithm: HashAlgorithm},
		}
	}

	current := mk(SchemaVersion)
	if err := current.Validate(); err != nil {
		t.Fatalf("current schema must validate: %v", err)
	}
	newer := mk(SchemaVersion + 1)
	err := newer.Validate()
	if err == nil || !strings.Contains(err.Error(), "incompatible schema version") {
		t.Fatalf("newer schema must be a clear incompatibility error, got: %v", err)
	}
	zero := mk(0)
	if err := zero.Validate(); err == nil {
		t.Fatal("schema 0 must be rejected")
	}
}

// --- Unknown fields: tolerant vs strict ---

func TestUnknownFieldsTolerantAndStrict(t *testing.T) {
	doc := `{
	  "schema":1,
	  "tool":{"name":"envfingerprint","version":"0.1.0"},
	  "environment":{"profile":"local","os":"linux","arch":"amd64","container":false,"ci":false},
	  "meta":{"hashAlgorithm":"sha256-canonical-json-v1"},
	  "fingerprint":"",
	  "futureField":{"any":"thing"}
	}`

	f, err := LoadFingerprint([]byte(doc), false)
	if err != nil {
		t.Fatalf("tolerant load must ignore unknown fields: %v", err)
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("tolerantly loaded doc must still validate: %v", err)
	}
	if _, err := LoadFingerprint([]byte(doc), true); err == nil {
		t.Fatal("strict load must reject unknown fields")
	}
}

func TestTrailingGarbageRejected(t *testing.T) {
	doc := `{"schema":1} {"extra":true}`
	if _, err := LoadFingerprint([]byte(doc), false); err == nil {
		t.Fatal("trailing content must be rejected")
	}
}

// --- Rules ---

func TestRulesValidExample(t *testing.T) {
	data := readTestdata(t, "envfingerprint.json")
	r, err := LoadRules(data, false)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("valid rules example rejected: %v", err)
	}
}

func TestRulesInvalid(t *testing.T) {
	ok := Rules{
		Schema: SchemaVersion,
		Variables: VariableRules{
			Required:          []string{"DATABASE_URL"},
			SensitivePatterns: []string{"*_API_TOKEN"},
		},
		Tools: []ToolRule{{Name: "go", MinVersion: "1.22.0"}},
		Files: []string{"go.mod"},
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("baseline rules must be valid: %v", err)
	}

	mutate := func(m func(*Rules)) Rules {
		r := ok
		m(&r)
		return r
	}

	cases := map[string]Rules{
		"sensitive var in compareValues": mutate(func(r *Rules) {
			r.Variables.CompareValues = []string{"DATABASE_URL"}
		}),
		"duplicate required var": mutate(func(r *Rules) {
			r.Variables.Required = []string{"A", "A"}
		}),
		"bad minVersion": mutate(func(r *Rules) {
			r.Tools[0].MinVersion = "go1.22"
		}),
		"fileDigests not in files": mutate(func(r *Rules) {
			r.FileDigests = []string{"go.sum"}
		}),
		"absolute file in rules": mutate(func(r *Rules) {
			r.Files = []string{"/etc/hosts"}
		}),
		"unknown compare section": mutate(func(r *Rules) {
			r.Compare.Sections = []string{"network"}
		}),
		"bad expectedFingerprint": mutate(func(r *Rules) {
			r.ExpectedFingerprint = "sha256:xyz"
		}),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := doc.Validate(); err == nil {
				t.Fatal("expected validation error, got nil")
			}
		})
	}
}

func TestRulesSchemaCompatibility(t *testing.T) {
	r := Rules{Schema: SchemaVersion + 5}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "incompatible schema") {
		t.Fatalf("expected incompatibility error, got %v", err)
	}
}

func TestIsSensitiveDefaultsAndExtra(t *testing.T) {
	if !IsSensitive("GITHUB_TOKEN", nil) {
		t.Fatal("default pattern *_TOKEN should match")
	}
	if IsSensitive("NODE_ENV", nil) {
		t.Fatal("NODE_ENV must not be sensitive by default")
	}
	if !IsSensitive("MY_API_TOKEN", []string{"MY_*"}) {
		t.Fatal("extra pattern should match")
	}
	// Invalid glob in extra patterns must not crash nor match everything.
	if IsSensitive("ANYTHING", []string{"["}) {
		t.Fatal("invalid glob must not match")
	}
}

// --- Diff result ---

func TestDiffValidExample(t *testing.T) {
	data := readTestdata(t, "diff.local-vs-ci.json")
	d, err := LoadDiff(data, false)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("valid diff example rejected: %v", err)
	}
}

func TestDiffInvalid(t *testing.T) {
	ok := DiffResult{
		Schema:     SchemaVersion,
		Compatible: true,
		Notes:      []string{},
		Changes: []Change{{Path: "environment.os", Kind: ChangeModified, Severity: SeverityInfo,
			Description: "el sistema operativo difiere", A: "linux", B: "darwin"}},
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("baseline diff must be valid: %v", err)
	}

	badKind := ok
	badKind.Changes = []Change{{Path: "x", Kind: "tweaked"}}
	if err := badKind.Validate(); err == nil {
		t.Fatal("unknown change kind must be rejected")
	}

	badNewer := ok
	badNewer.Schema = SchemaVersion + 1
	if err := badNewer.Validate(); err == nil {
		t.Fatal("newer schema must be rejected")
	}
}

// --- JSON schemas are syntactically valid JSON ---

func TestSchemaFilesParse(t *testing.T) {
	for _, name := range []string{"fingerprint.schema.json", "rules.schema.json", "diff.schema.json"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "schemas", name))
		if err != nil {
			t.Fatalf("read schema %s: %v", name, err)
		}
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatalf("%s is not valid JSON: %v", name, err)
		}
	}
}
