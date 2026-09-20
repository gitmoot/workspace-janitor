// Package config resolves where workspace-janitor keeps its configuration,
// state, and cache, and loads the YAML policy file with strict validation.
//
// Every lookup goes through an injected environment function. No code path in
// this package reads the process environment implicitly, so tests can run
// against a fixture home with no chance of touching the operator's real one.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// AppName is the directory name used under the XDG base directories.
const AppName = "workspace-janitor"

// Environment variable names honoured during path resolution.
const (
	EnvConfigDir = "JANITOR_CONFIG_DIR"
	EnvStateDir  = "JANITOR_STATE_DIR"
	EnvCacheDir  = "JANITOR_CACHE_DIR"
	EnvPolicy    = "JANITOR_POLICY"

	EnvXDGConfigHome = "XDG_CONFIG_HOME"
	EnvXDGStateHome  = "XDG_STATE_HOME"
	EnvXDGCacheHome  = "XDG_CACHE_HOME"
	EnvHome          = "HOME"
)

// Lookup resolves an environment variable. It mirrors os.LookupEnv.
type Lookup func(key string) (string, bool)

// SystemLookup reads the real process environment.
func SystemLookup() Lookup { return os.LookupEnv }

// MapLookup reads a fixed map, for tests and for explicit sandboxes.
func MapLookup(env map[string]string) Lookup {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

// Overrides are explicit command-line overrides. Empty fields fall through to
// the environment and then to the XDG defaults.
type Overrides struct {
	ConfigDir  string
	StateDir   string
	CacheDir   string
	PolicyFile string
}

// Origin explains where a resolved path came from, so `status` and `doctor`
// can prove which home a run is using.
type Origin string

const (
	OriginFlag    Origin = "flag"
	OriginEnv     Origin = "env"
	OriginXDG     Origin = "xdg"
	OriginDefault Origin = "default"
	OriginDerived Origin = "derived"
)

// PathOrigins records the origin of each independently resolvable path.
type PathOrigins struct {
	ConfigDir  Origin `json:"config_dir"`
	StateDir   Origin `json:"state_dir"`
	CacheDir   Origin `json:"cache_dir"`
	PolicyFile Origin `json:"policy_file"`
}

// Paths is the fully resolved set of locations for one run.
type Paths struct {
	Home          string      `json:"home"`
	ConfigDir     string      `json:"config_dir"`
	StateDir      string      `json:"state_dir"`
	CacheDir      string      `json:"cache_dir"`
	PolicyFile    string      `json:"policy_file"`
	DatabaseFile  string      `json:"database_file"`
	QuarantineDir string      `json:"quarantine_dir"`
	Origins       PathOrigins `json:"origins"`
}

// DirMode is the permission used for every directory this tool creates. State
// may reference sensitive locations, so it is owner-only.
const DirMode os.FileMode = 0o700

// ResolvePaths computes the locations for one run from explicit overrides and
// the given environment.
//
// Precedence per path: flag, then JANITOR_* variable, then the matching XDG
// base directory, then $HOME. HOME is only required for paths that are not
// otherwise resolved; a fully overridden run needs no home at all.
func ResolvePaths(lookup Lookup, overrides Overrides) (Paths, error) {
	if lookup == nil {
		return Paths{}, fmt.Errorf("config: environment lookup must not be nil")
	}
	var errs core.FieldErrors
	home, homeOK := envValue(lookup, EnvHome)
	if homeOK && !filepath.IsAbs(home) {
		errs.Add(EnvHome, "must be an absolute path, got %q", home)
		homeOK = false
	}

	resolve := func(field string, override string, envKey string, xdgKey string, xdgSuffix string, homeSuffix ...string) (string, Origin) {
		if v := strings.TrimSpace(override); v != "" {
			return checkAbs(&errs, field, v), OriginFlag
		}
		if v, ok := envValue(lookup, envKey); ok {
			return checkAbs(&errs, envKey, v), OriginEnv
		}
		if v, ok := envValue(lookup, xdgKey); ok {
			return checkAbs(&errs, xdgKey, filepath.Join(v, xdgSuffix)), OriginXDG
		}
		if !homeOK {
			errs.Add(field, "cannot be resolved: set --%s, %s, %s, or %s", field, envKey, xdgKey, EnvHome)
			return "", OriginDefault
		}
		return filepath.Join(append([]string{home}, homeSuffix...)...), OriginDefault
	}

	p := Paths{Home: home}
	p.ConfigDir, p.Origins.ConfigDir = resolve("config-dir", overrides.ConfigDir, EnvConfigDir, EnvXDGConfigHome, AppName, ".config", AppName)
	p.StateDir, p.Origins.StateDir = resolve("state-dir", overrides.StateDir, EnvStateDir, EnvXDGStateHome, AppName, ".local", "state", AppName)
	p.CacheDir, p.Origins.CacheDir = resolve("cache-dir", overrides.CacheDir, EnvCacheDir, EnvXDGCacheHome, AppName, ".cache", AppName)

	switch {
	case strings.TrimSpace(overrides.PolicyFile) != "":
		p.PolicyFile = checkAbs(&errs, "policy", strings.TrimSpace(overrides.PolicyFile))
		p.Origins.PolicyFile = OriginFlag
	default:
		if v, ok := envValue(lookup, EnvPolicy); ok {
			p.PolicyFile = checkAbs(&errs, EnvPolicy, v)
			p.Origins.PolicyFile = OriginEnv
		} else if p.ConfigDir != "" {
			p.PolicyFile = filepath.Join(p.ConfigDir, "policy.yaml")
			p.Origins.PolicyFile = OriginDerived
		}
	}
	if p.StateDir != "" {
		p.DatabaseFile = filepath.Join(p.StateDir, "janitor.db")
		p.QuarantineDir = filepath.Join(p.StateDir, "quarantine")
	}
	if err := errs.ErrorOrNil(); err != nil {
		return Paths{}, &Error{Scope: "paths", Errors: errs.Sorted()}
	}
	return p, nil
}

// EnsureDirs creates the config, state, and cache directories with owner-only
// permissions. It is idempotent.
func EnsureDirs(p Paths) error {
	for _, dir := range []string{p.ConfigDir, p.StateDir, p.CacheDir} {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, DirMode); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	return nil
}

// ExpandPath expands a leading "~" against home and cleans the result.
// "~user" is rejected: resolving another account's home is never implicit.
func ExpandPath(p, home string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("path must not be empty")
	}
	switch {
	case p == "~":
		if home == "" {
			return "", fmt.Errorf("cannot expand %q: no home directory is configured", p)
		}
		return filepath.Clean(home), nil
	case strings.HasPrefix(p, "~/"):
		if home == "" {
			return "", fmt.Errorf("cannot expand %q: no home directory is configured", p)
		}
		return filepath.Join(home, p[2:]), nil
	case strings.HasPrefix(p, "~"):
		return "", fmt.Errorf("cannot expand %q: only ~ and ~/ are supported", p)
	}
	return filepath.Clean(p), nil
}

func envValue(lookup Lookup, key string) (string, bool) {
	raw, ok := lookup(key)
	if !ok {
		return "", false
	}
	v := strings.TrimSpace(raw)
	return v, v != ""
}

func checkAbs(errs *core.FieldErrors, field, value string) string {
	clean := filepath.Clean(value)
	if !filepath.IsAbs(clean) {
		errs.Add(field, "must be an absolute path, got %q", value)
		return ""
	}
	return clean
}
