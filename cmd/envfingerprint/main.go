// Command envfingerprint is the entry point of the CLI. All behavior lives in
// internal/cli so it can be tested without spawning a process.
package main

import (
	"os"

	"github.com/envfingerprint/envfingerprint/internal/cli"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run exists so cmd tests can exercise the entry point's wiring.
func run(args []string) int {
	return cli.Run(args, os.Stdout, os.Stderr)
}
