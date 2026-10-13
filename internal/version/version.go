// Package version holds the tool version, a single source of truth shared by
// the CLI (--version) and collected fingerprints (tool.version). Keeping it in
// its own package avoids an import cycle between cli and collector.
//
// Overridable at build time:
//
//	go build -ldflags "-X github.com/envfingerprint/envfingerprint/internal/version.Version=1.2.3"
package version

// Version is semver MAJOR.MINOR.PATCH without the "v" prefix (contract rule
// for tool.version).
var Version = "0.1.0"
