package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

func fixturePaths(t *testing.T) Paths {
	t.Helper()
	home := t.TempDir()
	paths, err := ResolvePaths(fixtureEnv(home, nil), Overrides{})
	if err != nil {
		t.Fatalf("ResolvePaths: %v", err)
	}
	return paths
}

func parse(t *testing.T, paths Paths, document string) (Policy, error) {
	t.Helper()
	return ParsePolicy([]byte(document), paths, filepath.Join(paths.ConfigDir, "policy.yaml"))
}

func TestParsePolicyRejectsUnknownField(t *testing.T) {
	paths := fixturePaths(t)
	_, err := parse(t, paths, "version: 1\nroots:\n  - path: /repos\njev:\n  colour: blue\n")
	if err == nil {
		t.Fatal("expected an unknown field to be rejected")
	}
	cfgErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("error type = %T, want *config.Error", err)
	}
	fields := cfgErr.Fields()
	if len(fields) != 1 || fields[0].Field != "colour" {
		t.Fatalf("fields = %v, want one error for \"colour\"", fields)
	}
	if !strings.Contains(fields[0].Message, "unknown field") {
		t.Errorf("message = %q, want it to name the unknown field", fields[0].Message)
	}
}

func TestParsePolicyReportsEveryInvalidField(t *testing.T) {
	paths := fixturePaths(t)
	_, err := parse(t, paths, strings.Join([]string{
		"version: 2",
		"roots:",
		"  - path: relative/path",
		"    max_depth: -1",
		"  - path: /repos",
		"  - path: /repos",
		"retention:",
		"  default: 45d",
		"jev:",
		"  enabled: true",
		"",
	}, "\n"))
	if err == nil {
		t.Fatal("expected validation to fail")
	}
	cfgErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("error type = %T, want *config.Error", err)
	}
	want := []string{
		"version",
		"roots[0].path",
		"roots[0].max_depth",
		"roots[2].path",
		"retention.default",
		"jev.model",
	}
	got := map[string]string{}
	for _, fe := range cfgErr.Fields() {
		got[fe.Field] = fe.Message
	}
	for _, field := range want {
		if _, ok := got[field]; !ok {
			t.Errorf("missing field error for %q; got %v", field, cfgErr.Fields())
		}
	}
	if !strings.Contains(got["roots[2].path"], "duplicates") {
		t.Errorf("duplicate root message = %q", got["roots[2].path"])
	}
}

// An explicitly written zero must fail validation. Silently replacing it with
// a default would disable a bound the operator believed they had set.
func TestParsePolicyKeepsExplicitZeroValues(t *testing.T) {
	paths := fixturePaths(t)
	_, err := parse(t, paths, "roots:\n  - path: /repos\njev:\n  max_batch: 0\nlimits:\n  git_timeout: 0s\n  max_entries: 0\n")
	if err == nil {
		t.Fatal("expected explicit zero values to be rejected")
	}
	message := err.Error()
	for _, want := range []string{"jev.max_batch", "limits.git_timeout", "limits.max_entries"} {
		if !strings.Contains(message, want) {
			t.Errorf("error %q does not mention %q", message, want)
		}
	}
}

func TestParsePolicyAppliesDefaultsForOmittedKeys(t *testing.T) {
	paths := fixturePaths(t)
	policy, err := parse(t, paths, "roots:\n  - path: ~/repos\n    max_depth: 3\n")
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if policy.Version != PolicyVersion {
		t.Errorf("version = %d, want %d", policy.Version, PolicyVersion)
	}
	if policy.Limits.GitTimeout.Duration() != 5*time.Second {
		t.Errorf("git timeout = %s, want 5s", policy.Limits.GitTimeout)
	}
	if policy.Jev.Enabled {
		t.Error("jev must default to disabled")
	}
	if policy.Retention.Default != core.Retention30Days {
		t.Errorf("retention default = %q, want 30d", policy.Retention.Default)
	}
	if policy.Retention.QuarantineDir != paths.QuarantineDir {
		t.Errorf("quarantine dir = %q, want %q", policy.Retention.QuarantineDir, paths.QuarantineDir)
	}
	want := filepath.Join(paths.Home, "repos")
	if len(policy.Roots) != 1 || policy.Roots[0].Path != want {
		t.Fatalf("roots = %+v, want a single expanded root %q", policy.Roots, want)
	}
	if !policy.FromFile {
		t.Error("FromFile must be true for a parsed document")
	}
}

// Built-in protections are additive: a document listing its own protected
// paths must not silently drop the credential patterns shipped by default.
func TestParsePolicyKeepsBuiltinProtections(t *testing.T) {
	paths := fixturePaths(t)
	policy, err := parse(t, paths, "roots:\n  - path: /repos\nprotect:\n  paths:\n    - /srv/data\n  name_patterns:\n    - \"*.tar\"\n")
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if !contains(policy.Protect.Paths, "/srv/data") {
		t.Errorf("declared protected path missing: %v", policy.Protect.Paths)
	}
	if !contains(policy.Protect.Paths, filepath.Join(paths.Home, ".ssh")) {
		t.Errorf("built-in protected path missing: %v", policy.Protect.Paths)
	}
	if !contains(policy.Protect.NamePatterns, "*.tar") || !contains(policy.Protect.NamePatterns, "*.pem") {
		t.Errorf("name patterns = %v, want both declared and built-in entries", policy.Protect.NamePatterns)
	}
}

func TestParsePolicyRejectsEmptyAndMultiDocument(t *testing.T) {
	paths := fixturePaths(t)
	if _, err := parse(t, paths, ""); err == nil {
		t.Error("expected an empty policy file to be rejected")
	}
	_, err := parse(t, paths, "roots:\n  - path: /repos\n---\nroots:\n  - path: /other\n")
	if err == nil {
		t.Fatal("expected a multi-document policy file to be rejected")
	}
	if !strings.Contains(err.Error(), "exactly one YAML document") {
		t.Errorf("error = %v, want a single-document complaint", err)
	}
}

func TestParsePolicyRejectsBadDuration(t *testing.T) {
	paths := fixturePaths(t)
	_, err := parse(t, paths, "roots:\n  - path: /repos\nlimits:\n  git_timeout: soon\n")
	if err == nil {
		t.Fatal("expected an invalid duration to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid duration") {
		t.Errorf("error = %v, want an invalid duration complaint", err)
	}
}

func TestLoadPolicyWithoutFileUsesDefaults(t *testing.T) {
	paths := fixturePaths(t)
	policy, err := LoadPolicy(paths)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if policy.FromFile {
		t.Error("FromFile must be false when no policy file exists")
	}
	if !strings.Contains(policy.Source, "built-in defaults") {
		t.Errorf("source = %q, want it to name the built-in defaults", policy.Source)
	}
	if len(policy.Roots) != 1 || policy.Roots[0].Path != paths.Home {
		t.Errorf("default roots = %+v, want the fixture home", policy.Roots)
	}
}

// A present but broken file must fail. Falling back to defaults would run
// with protections the operator never approved.
func TestLoadPolicyNeverFallsBackForBrokenFile(t *testing.T) {
	paths := fixturePaths(t)
	if err := os.MkdirAll(paths.ConfigDir, DirMode); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(paths.PolicyFile, []byte("roots: [oops\n"), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if _, err := LoadPolicy(paths); err == nil {
		t.Fatal("expected a broken policy file to fail rather than fall back to defaults")
	}
}

func TestLoadPolicyReadsFile(t *testing.T) {
	paths := fixturePaths(t)
	if err := os.MkdirAll(paths.ConfigDir, DirMode); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	document := "version: 1\nroots:\n  - path: /repos\ncaches:\n  - name: go-build\n    path: ~/.cache/go-build\n"
	if err := os.WriteFile(paths.PolicyFile, []byte(document), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	policy, err := LoadPolicy(paths)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if policy.Source != paths.PolicyFile {
		t.Errorf("source = %q, want %q", policy.Source, paths.PolicyFile)
	}
	if len(policy.Caches) != 1 {
		t.Fatalf("caches = %+v, want one rule", policy.Caches)
	}
	cache := policy.Caches[0]
	if cache.Path != filepath.Join(paths.Home, ".cache", "go-build") {
		t.Errorf("cache path = %q, want the expanded home path", cache.Path)
	}
	if cache.Action != core.ActionInvestigate {
		t.Errorf("cache action = %q, want the conservative default %q", cache.Action, core.ActionInvestigate)
	}
	if cache.Retention != core.Retention30Days {
		t.Errorf("cache retention = %q, want the policy default", cache.Retention)
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// The documented example must stay loadable: a rename or a removed field
// would otherwise leave operators copying a policy the tool rejects.
func TestExamplePolicyDocumentIsValid(t *testing.T) {
	paths := fixturePaths(t)
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "policy.example.yaml"))
	if err != nil {
		t.Fatalf("read example policy: %v", err)
	}
	policy, err := ParsePolicy(data, paths, "docs/policy.example.yaml")
	if err != nil {
		t.Fatalf("documented example policy does not load: %v", err)
	}
	if len(policy.Roots) == 0 || len(policy.Caches) == 0 {
		t.Errorf("example policy lost its roots or cache rules: %+v", policy)
	}
}

// The quarantine directory is where apply moves things. Wherever the policy
// puts it, it must be protected, or a scan root containing it could propose
// acting on the tool's own staging area.
func TestParsePolicyProtectsConfiguredQuarantineDir(t *testing.T) {
	paths := fixturePaths(t)
	policy, err := parse(t, paths, "roots:\n  - path: /srv\nretention:\n  quarantine_dir: /srv/quarantine\n")
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if policy.Retention.QuarantineDir != "/srv/quarantine" {
		t.Fatalf("quarantine dir = %q", policy.Retention.QuarantineDir)
	}
	if !contains(policy.Protect.Paths, "/srv/quarantine") {
		t.Errorf("configured quarantine directory is unprotected: %v", policy.Protect.Paths)
	}
}

func TestDefaultPolicyProtectsStateAndQuarantine(t *testing.T) {
	paths := fixturePaths(t)
	policy := DefaultPolicy(paths)
	for _, want := range []string{paths.StateDir, paths.QuarantineDir} {
		if !contains(policy.Protect.Paths, want) {
			t.Errorf("default protections missing %q: %v", want, policy.Protect.Paths)
		}
	}
}

// With no home, the defaults have no root to derive. The failure must say
// what to do rather than complain about an empty list the operator never
// wrote.
func TestLoadPolicyWithoutHomeDemandsAPolicyFile(t *testing.T) {
	dir := t.TempDir()
	paths, err := ResolvePaths(MapLookup(map[string]string{}), Overrides{
		ConfigDir: filepath.Join(dir, "config"),
		StateDir:  filepath.Join(dir, "state"),
		CacheDir:  filepath.Join(dir, "cache"),
	})
	if err != nil {
		t.Fatalf("ResolvePaths: %v", err)
	}
	_, err = LoadPolicy(paths)
	if err == nil {
		t.Fatal("expected a run with no home and no policy file to fail")
	}
	message := err.Error()
	for _, want := range []string{paths.PolicyFile, EnvHome, "at least one root"} {
		if !strings.Contains(message, want) {
			t.Errorf("error %q does not mention %q", message, want)
		}
	}

	// With a policy file declaring a root, the same no-home run works.
	if err := EnsureDirs(paths); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	if err := os.WriteFile(paths.PolicyFile, []byte("roots:\n  - path: /srv/work\n"), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	policy, err := LoadPolicy(paths)
	if err != nil {
		t.Fatalf("LoadPolicy with an explicit policy and no home: %v", err)
	}
	if len(policy.Roots) != 1 || policy.Roots[0].Path != "/srv/work" {
		t.Errorf("roots = %+v", policy.Roots)
	}
}

func TestEnsureDirsCreatesQuarantine(t *testing.T) {
	paths := fixturePaths(t)
	if err := EnsureDirs(paths); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	for _, dir := range []string{paths.ConfigDir, paths.StateDir, paths.CacheDir, paths.QuarantineDir} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Errorf("stat %s: %v", dir, err)
			continue
		}
		if perm := info.Mode().Perm(); perm != DirMode.Perm() {
			t.Errorf("%s mode = %o, want %o", dir, perm, DirMode.Perm())
		}
	}
}

// Project markers are detected with one lstat each, so a glob could never
// match. Accepting one and silently ignoring it would be worse than an
// error: the operator would believe a classification rule is in force.
func TestProjectMarkerGlobsAreRejected(t *testing.T) {
	paths := fixturePaths(t)
	_, err := parse(t, paths, strings.Join([]string{
		"roots:",
		"  - path: /repos",
		"classification:",
		"  project_markers:",
		"    - \"*.csproj\"",
		"    - go.mod",
		"    - sub/dir.mod",
		"    - \".\"",
		"    - \"..\"",
		"",
	}, "\n"))
	if err == nil {
		t.Fatal("expected a glob in project_markers to be rejected")
	}
	message := err.Error()
	// "." lstats the directory itself and ".." its parent, so either would
	// mark every scanned directory as a project.
	for _, want := range []string{
		"project_markers[0]", "literal file name",
		"project_markers[2]", "project_markers[3]", "project_markers[4]",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("error %q does not mention %q", message, want)
		}
	}

	// Literal markers remain valid, and the other lists still take globs.
	if _, err := parse(t, paths, strings.Join([]string{
		"roots:",
		"  - path: /repos",
		"classification:",
		"  project_markers: [go.mod, .git]",
		"  cache_names: [\"*-cache\"]",
		"",
	}, "\n")); err != nil {
		t.Errorf("literal markers and glob cache names must be accepted: %v", err)
	}
}
