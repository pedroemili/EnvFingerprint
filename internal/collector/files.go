package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/envfingerprint/envfingerprint/internal/model"
)

// DefaultFiles: fixed list of project files whose presence is recorded when
// the project rules do not declare their own list. No globbing, no traversal.
var DefaultFiles = []struct {
	Path string
	Kind string
}{
	{"go.mod", model.FileKindConfig},
	{"go.sum", model.FileKindLockfile},
	{"package.json", model.FileKindConfig},
	{"package-lock.json", model.FileKindLockfile},
	{"yarn.lock", model.FileKindLockfile},
	{"pnpm-lock.yaml", model.FileKindLockfile},
	{"requirements.txt", model.FileKindConfig},
	{"Pipfile.lock", model.FileKindLockfile},
	{"poetry.lock", model.FileKindLockfile},
	{"Cargo.toml", model.FileKindConfig},
	{"Cargo.lock", model.FileKindLockfile},
	{"Dockerfile", model.FileKindConfig},
	{"docker-compose.yml", model.FileKindConfig},
	{"docker-compose.yaml", model.FileKindConfig},
	{".dockerignore", model.FileKindConfig},
}

// DefaultFilePaths returns the fixed default list of project files.
func DefaultFilePaths() []string {
	var out []string
	for _, f := range DefaultFiles {
		out = append(out, f.Path)
	}
	return out
}

// maxDigestFileSize bounds files read for content digests (rules.fileDigests).
const maxDigestFileSize = 10 << 20

// fileSpec is one file to probe: path relative to the project root.
type fileSpec struct {
	path   string
	digest bool
}

// filesCollector records presence indicators (and optional content digests)
// for a fixed list of project files.
type filesCollector struct {
	fs    FS
	specs []fileSpec
}

func (c filesCollector) Name() string { return "files" }

func (c filesCollector) Collect() ([]model.FileEntry, []Diagnostic) {
	var entries []model.FileEntry
	var diags []Diagnostic

	for _, spec := range c.specs {
		entry := model.FileEntry{
			Path: spec.path,
			Kind: fileKind(spec.path),
		}
		present, err := c.fs.Exists(spec.path)
		if err != nil {
			diags = append(diags, Diagnostic{Collector: "files", Message: fmt.Sprintf("%s: %v", spec.path, err)})
			continue
		}
		entry.Present = present
		if present && spec.digest {
			content, err := c.fs.Read(spec.path, maxDigestFileSize)
			if err != nil {
				diags = append(diags, Diagnostic{Collector: "files", Message: fmt.Sprintf("%s: sin digest: %v", spec.path, err)})
			} else {
				sum := sha256.Sum256(content)
				entry.Digest = "sha256:" + hex.EncodeToString(sum[:])
			}
		}
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, diags
}

func fileKind(path string) string {
	switch path {
	case "go.sum", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
		"Pipfile.lock", "poetry.lock", "Cargo.lock":
		return model.FileKindLockfile
	default:
		return model.FileKindConfig
	}
}
