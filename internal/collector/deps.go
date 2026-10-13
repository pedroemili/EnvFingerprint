// Package collector gathers environment facts for `envfingerprint scan`.
//
// Facts are produced by four independent collectors (system, tools, files,
// variables) wired through small interfaces (Env, Proc, FS) so each one is
// unit-testable without touching the host. A collector may fail without
// destroying other collectors' results: failures become Diagnostics and the
// corresponding section is simply absent or degraded.
//
// Safety policy (enforced here):
//   - external commands run without a shell, with a timeout and bounded
//     output; command lines are hardcoded in tool specs, never taken from
//     project configuration;
//   - file access is restricted to a fixed list of relative paths under the
//     project root; no filesystem traversal, no .env files;
//   - only explicitly declared environment variables are read;
//   - no personal paths, usernames or hostnames are collected.
package collector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Diagnostic is a recoverable, non-fatal problem observed while collecting.
// Diagnostics go to stderr; they never abort the scan.
type Diagnostic struct {
	Collector string // e.g. "tools"
	Message   string // human readable, never contains secret values
}

func (d Diagnostic) String() string { return d.Collector + ": " + d.Message }

// Sentinel errors so callers can distinguish not-installed, unknown-version,
// timeout and execution failures.
var (
	ErrNotInstalled = errors.New("herramienta no instalada")
	ErrTimeout      = errors.New("tiempo de ejecución agotado")
	ErrExecution    = errors.New("error de ejecución")
)

// Env abstracts environment variable lookup (os.LookupEnv in production).
type Env interface {
	Lookup(key string) (string, bool)
}

type osEnv struct{}

func (osEnv) Lookup(key string) (string, bool) { return os.LookupEnv(key) }

// Proc runs a command and returns its standard output.
type Proc interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// DefaultProcTimeout bounds every external command.
const DefaultProcTimeout = 5 * time.Second

// maxProcOutput caps captured stdout; excess bytes are discarded.
const maxProcOutput = 64 << 10

type execProc struct{ timeout time.Duration }

func (p execProc) Run(ctx context.Context, name string, args ...string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, ErrNotInstalled)
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stderr = io.Discard // stderr may echo command context; never needed here
	var buf limitedBuffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("%s: %w", name, ErrTimeout)
		}
		if ctx.Err() != nil {
			return "", fmt.Errorf("%s: %w", name, ctx.Err())
		}
		return "", fmt.Errorf("%s: %v: %w", name, err, ErrExecution)
	}
	return buf.String(), nil
}

// limitedBuffer keeps at most maxProcOutput bytes.
type limitedBuffer struct{ b strings.Builder }

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.b.Len() < maxProcOutput {
		n := maxProcOutput - l.b.Len()
		if n > len(p) {
			n = len(p)
		}
		l.b.Write(p[:n])
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string { return l.b.String() }

// FS abstracts read access under the project root.
type FS interface {
	// Exists reports whether the project-relative file exists. rel must be a
	// relative path without ".."; invalid paths report not-exists.
	Exists(rel string) (bool, error)
	// Read reads the project-relative file, refusing files larger than
	// limit bytes. Used only for content digests of declared files.
	Read(rel string, limit int64) ([]byte, error)
	// ExistsAbs probes an absolute, well-known platform path (e.g.
	// "/.dockerenv"). Only the system collector uses it, with hardcoded paths.
	ExistsAbs(abs string) bool
}

type osFS struct{ root string }

func validRelPath(rel string) (string, bool) {
	if rel == "" || filepath.IsAbs(rel) {
		return "", false
	}
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", false
	}
	return clean, true
}

func (f osFS) join(rel string) (string, bool) {
	clean, ok := validRelPath(rel)
	if !ok {
		return "", false
	}
	return filepath.Join(f.root, clean), true
}

func (f osFS) Exists(rel string) (bool, error) {
	full, ok := f.join(rel)
	if !ok {
		return false, fmt.Errorf("ruta no permitida (relativa a proyecto): %q", rel)
	}
	_, err := os.Stat(full)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (f osFS) Read(rel string, limit int64) ([]byte, error) {
	full, ok := f.join(rel)
	if !ok {
		return nil, fmt.Errorf("ruta no permitida (relativa a proyecto): %q", rel)
	}
	fh, err := os.Open(full)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("archivo demasiado grande para digest (%d > %d bytes)", st.Size(), limit)
	}
	return io.ReadAll(fh)
}

func (osFS) ExistsAbs(abs string) bool {
	_, err := os.Stat(abs)
	return err == nil
}

// Deps bundles the production or fake dependencies of all collectors.
type Deps struct {
	Env  Env
	Proc Proc
	FS   FS
}

// RealDeps wires the collectors to the current process and project directory.
func RealDeps(projectRoot string) Deps {
	return Deps{
		Env:  osEnv{},
		Proc: execProc{timeout: DefaultProcTimeout},
		FS:   osFS{root: projectRoot},
	}
}
