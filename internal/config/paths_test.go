package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// fixtureEnv returns an environment rooted at a fixture home. No test in this
// package ever reads the real process environment.
func fixtureEnv(home string, extra map[string]string) Lookup {
	env := map[string]string{EnvHome: home}
	for k, v := range extra {
		env[k] = v
	}
	return MapLookup(env)
}

func TestResolvePathsUsesXDGDefaultsUnderHome(t *testing.T) {
	home := t.TempDir()
	paths, err := ResolvePaths(fixtureEnv(home, nil), Overrides{})
	if err != nil {
		t.Fatalf("ResolvePaths: %v", err)
	}
	want := map[string]string{
		"config": filepath.Join(home, ".config", AppName),
		"state":  filepath.Join(home, ".local", "state", AppName),
		"cache":  filepath.Join(home, ".cache", AppName),
		"policy": filepath.Join(home, ".config", AppName, "policy.yaml"),
		"db":     filepath.Join(home, ".local", "state", AppName, "janitor.db"),
	}
	got := map[string]string{
		"config": paths.ConfigDir,
		"state":  paths.StateDir,
		"cache":  paths.CacheDir,
		"policy": paths.PolicyFile,
		"db":     paths.DatabaseFile,
	}
	for key, expected := range want {
		if got[key] != expected {
			t.Errorf("%s = %q, want %q", key, got[key], expected)
		}
	}
	if paths.Origins.ConfigDir != OriginDefault {
		t.Errorf("config origin = %q, want %q", paths.Origins.ConfigDir, OriginDefault)
	}
}

func TestResolvePathsPrecedence(t *testing.T) {
	home := t.TempDir()
	xdg := t.TempDir()
	janitorEnv := t.TempDir()
	flagDir := t.TempDir()

	env := fixtureEnv(home, map[string]string{
		EnvXDGConfigHome: xdg,
		EnvConfigDir:     janitorEnv,
	})

	withEnvOnly, err := ResolvePaths(env, Overrides{})
	if err != nil {
		t.Fatalf("ResolvePaths: %v", err)
	}
	if withEnvOnly.ConfigDir != janitorEnv {
		t.Errorf("JANITOR_CONFIG_DIR must win over XDG_CONFIG_HOME: got %q", withEnvOnly.ConfigDir)
	}
	if withEnvOnly.Origins.ConfigDir != OriginEnv {
		t.Errorf("origin = %q, want %q", withEnvOnly.Origins.ConfigDir, OriginEnv)
	}

	withFlag, err := ResolvePaths(env, Overrides{ConfigDir: flagDir})
	if err != nil {
		t.Fatalf("ResolvePaths: %v", err)
	}
	if withFlag.ConfigDir != flagDir {
		t.Errorf("flag must win over environment: got %q", withFlag.ConfigDir)
	}
	if withFlag.Origins.ConfigDir != OriginFlag {
		t.Errorf("origin = %q, want %q", withFlag.Origins.ConfigDir, OriginFlag)
	}

	xdgOnly, err := ResolvePaths(fixtureEnv(home, map[string]string{EnvXDGStateHome: xdg}), Overrides{})
	if err != nil {
		t.Fatalf("ResolvePaths: %v", err)
	}
	if want := filepath.Join(xdg, AppName); xdgOnly.StateDir != want {
		t.Errorf("state dir = %q, want %q", xdgOnly.StateDir, want)
	}
	if xdgOnly.Origins.StateDir != OriginXDG {
		t.Errorf("origin = %q, want %q", xdgOnly.Origins.StateDir, OriginXDG)
	}
}

func TestResolvePathsWithoutHomeFailsPerPath(t *testing.T) {
	_, err := ResolvePaths(MapLookup(map[string]string{}), Overrides{})
	if err == nil {
		t.Fatal("expected an error when no home and no overrides are available")
	}
	var cfgErr *Error
	if !asConfigError(err, &cfgErr) {
		t.Fatalf("error type = %T, want *config.Error", err)
	}
	fields := map[string]bool{}
	for _, fe := range cfgErr.Fields() {
		fields[fe.Field] = true
	}
	for _, want := range []string{"config-dir", "state-dir", "cache-dir"} {
		if !fields[want] {
			t.Errorf("missing field error for %q; got %v", want, cfgErr.Fields())
		}
	}
}

func TestResolvePathsFullyOverriddenNeedsNoHome(t *testing.T) {
	dir := t.TempDir()
	paths, err := ResolvePaths(MapLookup(map[string]string{}), Overrides{
		ConfigDir: filepath.Join(dir, "config"),
		StateDir:  filepath.Join(dir, "state"),
		CacheDir:  filepath.Join(dir, "cache"),
	})
	if err != nil {
		t.Fatalf("ResolvePaths: %v", err)
	}
	if paths.Home != "" {
		t.Errorf("home = %q, want empty", paths.Home)
	}
	if paths.PolicyFile != filepath.Join(dir, "config", "policy.yaml") {
		t.Errorf("policy file = %q", paths.PolicyFile)
	}
}

func TestResolvePathsRejectsRelativeOverride(t *testing.T) {
	_, err := ResolvePaths(fixtureEnv(t.TempDir(), nil), Overrides{StateDir: "relative/state"})
	if err == nil {
		t.Fatal("expected a relative state directory to be rejected")
	}
	if !strings.Contains(err.Error(), "must be an absolute path") {
		t.Errorf("error = %v, want an absolute-path complaint", err)
	}
}

func TestExpandPath(t *testing.T) {
	home := "/home/fixture"
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "~", want: home},
		{in: "~/repos", want: "/home/fixture/repos"},
		{in: "/absolute/path/", want: "/absolute/path"},
		{in: "~other/repos", wantErr: true},
		{in: "   ", wantErr: true},
	}
	for _, tc := range cases {
		got, err := ExpandPath(tc.in, home)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ExpandPath(%q) = %q, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ExpandPath(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ExpandPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExpandPathWithoutHomeFails(t *testing.T) {
	if _, err := ExpandPath("~/repos", ""); err == nil {
		t.Fatal("expected ~ expansion without a home to fail")
	}
}

func asConfigError(err error, target **Error) bool {
	cfgErr, ok := err.(*Error)
	if ok {
		*target = cfgErr
	}
	return ok
}
