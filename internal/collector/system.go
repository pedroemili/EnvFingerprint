package collector

import (
	"runtime"

	"github.com/envfingerprint/envfingerprint/internal/model"
)

// systemCollector fills model.Environment. It never fails hard: its data comes
// from the Go runtime plus well-known probes, all best-effort.
type systemCollector struct {
	env Env
	fs  FS
}

func (c systemCollector) Name() string { return "system" }

// ciEnvKeys: presence of any of these marks a CI environment.
var ciEnvKeys = []string{
	"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "JENKINS_URL",
	"BUILDKITE", "TF_BUILD", "TEAMCITY_VERSION", "TRAVIS",
}

func (c systemCollector) Collect() (model.Environment, []Diagnostic) {
	env := model.Environment{
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		CI:        c.inCI(),
		Container: c.inContainer(),
	}
	switch {
	case env.Container:
		// A container inside CI is still "container": the profile answers
		// "what shape is my runtime", and container-ness is the most
		// actionable difference. ci stays visible in the ci flag.
		env.Profile = model.ProfileContainer
	case env.CI:
		env.Profile = model.ProfileCI
	default:
		env.Profile = model.ProfileLocal
	}
	return env, nil
}

func (c systemCollector) inCI() bool {
	for _, key := range ciEnvKeys {
		if v, ok := c.env.Lookup(key); ok && v != "" && v != "false" {
			return true
		}
	}
	return false
}

// inContainer is a documented heuristic: presence of /.dockerenv or
// /run/.containerenv, or the "container" env variable. On Windows always false
// (no well-known probe exists); a Linux container under WSL reports Linux.
func (c systemCollector) inContainer() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	if _, ok := c.env.Lookup("container"); ok {
		return true
	}
	return c.fs.ExistsAbs("/.dockerenv") || c.fs.ExistsAbs("/run/.containerenv")
}
