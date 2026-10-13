package main

import (
	"testing"

	"github.com/envfingerprint/envfingerprint/internal/cli"
)

// TestEntryPointWiring verifies that the binary's run() delegates to the CLI
// and propagates its exit code (main itself calls os.Exit and is covered here
// through run).
func TestEntryPointWiring(t *testing.T) {
	if got := run([]string{"--version"}); got != cli.ExitOK {
		t.Fatalf("run(--version) = %d, want %d", got, cli.ExitOK)
	}
	if got := run([]string{"no-existo"}); got != cli.ExitUsage {
		t.Fatalf("run(bad) = %d, want %d", got, cli.ExitUsage)
	}
}
