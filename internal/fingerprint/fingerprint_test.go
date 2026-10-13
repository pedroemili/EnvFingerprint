package fingerprint

import (
	"strings"
	"testing"

	"github.com/envfingerprint/envfingerprint/internal/model"
)

func baseFingerprint() *model.Fingerprint {
	return &model.Fingerprint{
		Schema: model.SchemaVersion,
		Tool:   model.Tool{Name: "envfingerprint", Version: "0.1.0"},
		Environment: model.Environment{
			Profile: model.ProfileCI, OS: "linux", Arch: "amd64",
			Container: false, CI: true,
		},
		Runtimes: []model.Runtime{
			{Name: "go", Version: "1.23.2", Raw: "go version go1.23.2 linux/amd64", Source: "go version"},
			{Name: "node", Version: "20.9.0", Raw: "v20.9.0", Source: "node --version"},
		},
		Files: []model.FileEntry{
			{Path: "go.sum", Kind: model.FileKindLockfile, Present: true},
			{Path: "go.mod", Kind: model.FileKindConfig, Present: true},
		},
		Variables: []model.Variable{
			{Key: "NODE_ENV", State: model.StatePresent, Sensitive: false, Compare: model.CompareValue, Value: "production"},
			{Key: "DB_TOKEN", State: model.StatePresent, Sensitive: true, Compare: model.ComparePresence},
		},
		Meta: model.Meta{HashAlgorithm: model.HashAlgorithm},
	}
}

func mustCompute(t *testing.T, fp *model.Fingerprint, p Policy) string {
	t.Helper()
	h, err := Compute(fp, p)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	return h
}

func TestHashOrderIndependent(t *testing.T) {
	a := baseFingerprint()
	// Same data, collections in opposite order and different tool metadata.
	b := baseFingerprint()
	b.Runtimes = []model.Runtime{b.Runtimes[1], b.Runtimes[0]}
	b.Files = []model.FileEntry{b.Files[1], b.Files[0]}
	b.Variables = []model.Variable{b.Variables[1], b.Variables[0]}
	b.Tool.Version = "9.9.9"

	if ha, hb := mustCompute(t, a, DefaultPolicy), mustCompute(t, b, DefaultPolicy); ha != hb {
		t.Errorf("hashes differ for equivalent data:\n  %s\n  %s", ha, hb)
	}
}

func TestHashChangesWithRelevantField(t *testing.T) {
	a := baseFingerprint()
	b := baseFingerprint()
	b.Environment.OS = "darwin"
	if mustCompute(t, a, DefaultPolicy) == mustCompute(t, b, DefaultPolicy) {
		t.Error("os change must alter the hash")
	}

	c := baseFingerprint()
	c.Variables[0].Value = "staging"
	if mustCompute(t, a, DefaultPolicy) == mustCompute(t, c, DefaultPolicy) {
		t.Error("value change of a compareValue variable must alter the hash")
	}

	d := baseFingerprint()
	d.Variables[1].State = model.StateAbsent // sensitive: presence matters
	if mustCompute(t, a, DefaultPolicy) == mustCompute(t, d, DefaultPolicy) {
		t.Error("presence change of a sensitive variable must alter the hash")
	}
}

func TestHashStableAcrossExcludedFields(t *testing.T) {
	a := baseFingerprint()
	b := baseFingerprint()
	// Pure metadata/volatile field changes; hash-selected fields identical.
	b.Tool.Version = "1.2.3"
	b.Runtimes[0].Raw = "totally different raw output"
	b.Runtimes[0].Source = "another source"
	b.Fingerprint = "sha256:" + strings.Repeat("f", 64)

	if mustCompute(t, a, DefaultPolicy) != mustCompute(t, b, DefaultPolicy) {
		t.Error("excluded/volatile fields must not alter the main hash")
	}
}

func TestAbsentEmptyNullAreEquivalent(t *testing.T) {
	empty := baseFingerprint()
	empty.Runtimes = nil
	empty.Files = nil
	empty.Variables = nil

	withEmpty := baseFingerprint()
	withEmpty.Runtimes = []model.Runtime{}
	withEmpty.Files = []model.FileEntry{}
	withEmpty.Variables = []model.Variable{}

	if mustCompute(t, empty, DefaultPolicy) != mustCompute(t, withEmpty, DefaultPolicy) {
		t.Error("absent and empty sections must hash identically")
	}

	// FileEntry without digest vs with empty digest: same.
	f1 := baseFingerprint()
	f2 := baseFingerprint()
	f1.Files[0].Digest = ""
	f2.Files[0].Digest = ""
	f1.Files = f1.Files[:1]
	f2.Files = f2.Files[:1]
	f2.Files[0].Digest = ""
	if mustCompute(t, f1, DefaultPolicy) != mustCompute(t, f2, DefaultPolicy) {
		t.Error("absent/empty optional field must hash identically")
	}
}

func TestNullCollectionsTreatedAsAbsent(t *testing.T) {
	// A JSON document with explicit nulls deserializes to nil slices.
	doc := `{
	  "schema":1,
	  "tool":{"name":"envfingerprint","version":"0.1.0"},
	  "environment":{"profile":"local","os":"linux","arch":"amd64","container":false,"ci":false},
	  "runtimes": null,
	  "files": null,
	  "variables": null,
	  "meta":{"hashAlgorithm":"sha256-canonical-json-v1"},
	  "fingerprint":"",
	  "unknownField": {"ignored": true}
	}`
	fp, err := model.LoadFingerprint([]byte(doc), false)
	if err != nil {
		t.Fatal(err)
	}
	h1 := mustCompute(t, fp, DefaultPolicy)

	plain := &model.Fingerprint{
		Schema:      model.SchemaVersion,
		Tool:        model.Tool{Name: "envfingerprint", Version: "0.1.0"},
		Environment: model.Environment{Profile: model.ProfileLocal, OS: "linux", Arch: "amd64"},
		Meta:        model.Meta{HashAlgorithm: model.HashAlgorithm},
	}
	h2 := mustCompute(t, plain, DefaultPolicy)
	if h1 != h2 {
		t.Errorf("null/absent collections and unknown fields must not change the hash:\n%s\n%s", h1, h2)
	}
}

func TestInvalidInputFails(t *testing.T) {
	if _, err := Compute(nil, DefaultPolicy); err == nil {
		t.Error("nil document must fail")
	}
	bad := baseFingerprint()
	bad.Schema = model.SchemaVersion + 1
	if _, err := Compute(bad, DefaultPolicy); err == nil {
		t.Error("incompatible schema must fail")
	}
	bad2 := baseFingerprint()
	bad2.Variables = append(bad2.Variables, model.Variable{
		Key: "API_TOKEN", State: model.StatePresent, Sensitive: true,
		Compare: model.ComparePresence, Value: "leak",
	})
	if _, err := Compute(bad2, DefaultPolicy); err == nil {
		t.Error("sensitive variable with value must fail")
	}
	bad3 := baseFingerprint()
	bad3.Environment.OS = "Linux"
	if _, err := Compute(bad3, DefaultPolicy); err == nil {
		t.Error("non-normalized data must fail")
	}
}

func TestDeterministicAcrossRuns(t *testing.T) {
	fp := baseFingerprint()
	first := mustCompute(t, fp, DefaultPolicy)
	for i := 0; i < 100; i++ {
		if got := mustCompute(t, fp, DefaultPolicy); got != first {
			t.Fatalf("run %d: %s != %s", i, got, first)
		}
	}
}

func TestPolicySections(t *testing.T) {
	a := baseFingerprint()
	b := baseFingerprint()
	b.Files = []model.FileEntry{{Path: "yarn.lock", Kind: model.FileKindLockfile, Present: true}}

	full := DefaultPolicy
	if mustCompute(t, a, full) == mustCompute(t, b, full) {
		t.Fatal("files differ; full-policy hashes must differ")
	}

	noFiles := Policy{Sections: map[string]bool{
		model.SectionEnvironment: true, model.SectionRuntimes: true, model.SectionVariables: true,
	}}
	if mustCompute(t, a, noFiles) != mustCompute(t, b, noFiles) {
		t.Fatal("files excluded from policy: hashes must be equal")
	}
}

func TestApplyStampsAndIsStableOnReload(t *testing.T) {
	fp := baseFingerprint()
	if err := Apply(fp, DefaultPolicy); err != nil {
		t.Fatal(err)
	}
	if fp.Fingerprint == "" {
		t.Fatal("fingerprint not stamped")
	}
	// Recomputing over the stamped document must yield the same hash.
	if got := mustCompute(t, fp, DefaultPolicy); got != fp.Fingerprint {
		t.Errorf("recompute over stamped doc: %s != %s", got, fp.Fingerprint)
	}
}

// Golden regression: the canonical recipe must never change silently. If this
// test fails intentionally (new hash algorithm), bump meta.hashAlgorithm and
// the schema version per docs/CONTRACTS.md §4.
func TestGoldenHash(t *testing.T) {
	const want = "sha256:3dc96a952d7d221c9384e78f282470ac1624b93ec3c54f5467cb61fa072d6e37"
	got := mustCompute(t, baseFingerprint(), DefaultPolicy)
	if got != want {
		t.Fatalf("canonical hash changed: got %s want %s", got, want)
	}
}
