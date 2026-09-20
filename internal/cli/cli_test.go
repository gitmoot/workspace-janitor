package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

// fixture is an isolated home for one CLI test. Every run resolves its paths
// from this map alone: the CLI never reads the process environment, so a test
// cannot reach the operator's real configuration or state.
type fixture struct {
	home string
	env  map[string]string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	home := t.TempDir()
	return &fixture{home: home, env: map[string]string{config.EnvHome: home}}
}

func (f *fixture) writePolicy(t *testing.T, document string) string {
	t.Helper()
	dir := filepath.Join(f.home, ".config", config.AppName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func (f *fixture) run(t *testing.T, args ...string) (stdout, stderr string, code ExitCode) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(context.Background(), Options{
		Args:   args,
		Stdout: &out,
		Stderr: &errOut,
		Lookup: config.MapLookup(f.env),
	})
	return out.String(), errOut.String(), code
}

func TestHelpExposesIntendedCommandTree(t *testing.T) {
	f := newFixture(t)
	stdout, _, code := f.run(t, "--help")
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d", code, ExitOK)
	}
	for _, name := range []string{"scan", "plan", "explain", "apply", "restore", "status", "policy", "doctor", "version"} {
		if !strings.Contains(stdout, "janitor "+name) {
			t.Errorf("help does not list %q:\n%s", name, stdout)
		}
	}
	for _, flagName := range []string{"--config-dir", "--state-dir", "--cache-dir", "--policy", "--format"} {
		if !strings.Contains(stdout, flagName) {
			t.Errorf("help does not document %q", flagName)
		}
	}
	// Commands this build cannot perform must say so in help.
	if !strings.Contains(stdout, "not implemented: issue #4") {
		t.Errorf("help does not mark apply as unimplemented:\n%s", stdout)
	}
	if strings.Contains(stdout, "janitor scan [flags] [root...]  Inventory configured roots and collect safety evidence  (not implemented") {
		t.Errorf("scan is implemented and must not be marked otherwise:\n%s", stdout)
	}

	policyHelp, _, code := f.run(t, "help", "policy")
	if code != ExitOK {
		t.Fatalf("help policy exit = %d", code)
	}
	if !strings.Contains(policyHelp, "janitor policy check") {
		t.Errorf("policy help does not list the check subcommand:\n%s", policyHelp)
	}
}

// Commands in the contract that this build cannot perform must fail loudly
// with their own exit code, print nothing to stdout, and name their issue.
func TestUnimplementedCommandsFailWithoutFakingSuccess(t *testing.T) {
	cases := []struct {
		args     []string
		tracking string
	}{
		{[]string{"plan"}, "issue #7"},
		{[]string{"explain", "/repos/app"}, "issue #7"},
		{[]string{"apply", "--plan", "plan-1", "--confirm"}, "issue #4"},
		{[]string{"restore", "receipt-1", "--confirm"}, "issue #4"},
	}
	for _, tc := range cases {
		f := newFixture(t)
		stdout, stderr, code := f.run(t, tc.args...)
		if code != ExitNotImplemented {
			t.Errorf("%v exit = %d, want %d", tc.args, code, ExitNotImplemented)
		}
		if stdout != "" {
			t.Errorf("%v wrote to stdout: %q", tc.args, stdout)
		}
		if !strings.Contains(stderr, "not implemented") || !strings.Contains(stderr, tc.tracking) {
			t.Errorf("%v stderr = %q, want a clear failure naming %s", tc.args, stderr, tc.tracking)
		}
	}
}

func TestStatusReportsFixturePathsAndDoesNotCreateState(t *testing.T) {
	f := newFixture(t)
	stdout, stderr, code := f.run(t, "status")
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, f.home) {
		t.Errorf("status does not report the fixture home:\n%s", stdout)
	}
	if !strings.Contains(stdout, "not initialized") {
		t.Errorf("status must say the store is uninitialized:\n%s", stdout)
	}
	dbPath := filepath.Join(f.home, ".local", "state", config.AppName, "janitor.db")
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Errorf("status created state at %s (err = %v); reporting must not mutate", dbPath, err)
	}
}

func TestDoctorInitializesStoreAndStatusThenReportsIt(t *testing.T) {
	f := newFixture(t)
	stdout, stderr, code := f.run(t, "doctor")
	if code != ExitOK {
		t.Fatalf("doctor exit = %d, stdout = %s, stderr = %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "healthy") {
		t.Errorf("doctor output = %s", stdout)
	}
	dbPath := filepath.Join(f.home, ".local", "state", config.AppName, "janitor.db")
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("doctor did not create the store: %v", err)
	}

	statusOut, _, code := f.run(t, "status")
	if code != ExitOK {
		t.Fatalf("status exit = %d", code)
	}
	if !strings.Contains(statusOut, fmt.Sprintf("schema %d", store.SchemaVersion())) {
		t.Errorf("status does not report the schema version:\n%s", statusOut)
	}
}

func TestDoctorJSONReportsEveryCheck(t *testing.T) {
	f := newFixture(t)
	stdout, _, code := f.run(t, "--format", "json", "doctor")
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	var doc struct {
		SchemaVersion int    `json:"schema_version"`
		Kind          string `json:"kind"`
		Data          struct {
			Healthy bool `json:"healthy"`
			Checks  []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"checks"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("doctor JSON is not valid: %v\n%s", err, stdout)
	}
	if doc.SchemaVersion != 1 || doc.Kind != "doctor" {
		t.Errorf("envelope = %+v", doc)
	}
	if !doc.Data.Healthy {
		t.Errorf("fixture install should be healthy: %s", stdout)
	}
	names := map[string]string{}
	for _, check := range doc.Data.Checks {
		names[check.Name] = check.Status
	}
	for _, want := range []string{"config-dir", "state-dir", "cache-dir", "policy", "store", "static-build"} {
		if _, ok := names[want]; !ok {
			t.Errorf("doctor did not report check %q: %v", want, names)
		}
	}
}

func TestPolicyCheckAcceptsValidFileAndRejectsInvalid(t *testing.T) {
	f := newFixture(t)
	f.writePolicy(t, "version: 1\nroots:\n  - path: ~/repos\n    max_depth: 2\n")
	stdout, stderr, code := f.run(t, "policy", "check")
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "policy is valid") {
		t.Errorf("stdout = %s", stdout)
	}
	if !strings.Contains(stdout, filepath.Join(f.home, "repos")) {
		t.Errorf("effective policy should show the expanded root:\n%s", stdout)
	}

	f.writePolicy(t, "version: 1\nroots:\n  - path: relative\nrentention:\n  default: 30d\n")
	stdout, stderr, code = f.run(t, "policy", "check")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d (usage)", code, ExitUsage)
	}
	if stdout != "" {
		t.Errorf("invalid policy wrote to stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "rentention") {
		t.Errorf("stderr must name the unknown field:\n%s", stderr)
	}
}

// Every command that reads configuration must fail on an invalid policy
// rather than quietly continuing with defaults.
func TestCommandsFailOnInvalidPolicy(t *testing.T) {
	for _, args := range [][]string{{"status"}, {"doctor"}, {"policy", "check"}} {
		f := newFixture(t)
		f.writePolicy(t, "version: 9\nroots: []\n")
		_, stderr, code := f.run(t, args...)
		if args[0] == "doctor" {
			// doctor reports check failures and exits with ExitError.
			if code != ExitError {
				t.Errorf("doctor exit = %d, want %d", code, ExitError)
			}
			continue
		}
		if code != ExitUsage {
			t.Errorf("%v exit = %d, want %d", args, code, ExitUsage)
		}
		if !strings.Contains(stderr, "invalid configuration") {
			t.Errorf("%v stderr = %q", args, stderr)
		}
	}
}

func TestJSONOutputIsDeterministic(t *testing.T) {
	f := newFixture(t)
	f.writePolicy(t, "version: 1\nroots:\n  - path: /repos\n")
	for _, args := range [][]string{
		{"--format", "json", "policy", "check"},
		{"--format", "json", "version"},
	} {
		first, _, code := f.run(t, args...)
		if code != ExitOK {
			t.Fatalf("%v exit = %d", args, code)
		}
		second, _, _ := f.run(t, args...)
		if first != second {
			t.Errorf("%v output is not deterministic:\n%s\n---\n%s", args, first, second)
		}
		if !strings.HasSuffix(first, "\n") {
			t.Errorf("%v output must end with a newline", args)
		}
		var envelope map[string]any
		if err := json.Unmarshal([]byte(first), &envelope); err != nil {
			t.Fatalf("%v output is not valid JSON: %v", args, err)
		}
		if envelope["schema_version"] != float64(1) {
			t.Errorf("%v envelope = %v, want schema_version 1", args, envelope)
		}
	}
}

// The global flags must work in either position so a run cannot silently use
// text output when JSON was requested after the command name.
func TestGlobalFlagsAcceptedAfterCommand(t *testing.T) {
	f := newFixture(t)
	stdout, stderr, code := f.run(t, "version", "--format", "json")
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
	if !strings.HasPrefix(stdout, "{") {
		t.Errorf("stdout = %q, want JSON", stdout)
	}
}

func TestOverrideFlagsRedirectAllState(t *testing.T) {
	f := newFixture(t)
	root := t.TempDir()
	configDir := filepath.Join(root, "cfg")
	stateDir := filepath.Join(root, "state")
	cacheDir := filepath.Join(root, "cache")
	_, stderr, code := f.run(t, "--config-dir", configDir, "--state-dir", stateDir, "--cache-dir", cacheDir, "doctor")
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "janitor.db")); err != nil {
		t.Errorf("state was not written to the override directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.home, ".local", "state", config.AppName)); !os.IsNotExist(err) {
		t.Errorf("overridden run still touched the home state directory (err = %v)", err)
	}
}

// With no home and no overrides the CLI must fail with field-level guidance
// rather than guessing a directory.
func TestMissingHomeFailsWithFieldErrors(t *testing.T) {
	f := &fixture{home: "", env: map[string]string{}}
	_, stderr, code := f.run(t, "status")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	for _, want := range []string{"config-dir", "state-dir", "cache-dir", "HOME"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want it to mention %q", stderr, want)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	f := newFixture(t)
	cases := [][]string{
		{"frobnicate"},
		{"status", "extra"},
		{"policy"},
		{"--format", "toml", "version"},
		{"--unknown-flag"},
		{},
	}
	for _, args := range cases {
		stdout, stderr, code := f.run(t, args...)
		if code != ExitUsage {
			t.Errorf("%v exit = %d, want %d", args, code, ExitUsage)
		}
		if stdout != "" {
			t.Errorf("%v wrote to stdout: %q", args, stdout)
		}
		if stderr == "" {
			t.Errorf("%v produced no diagnostic", args)
		}
	}
}

func TestVersionFlagAndCommandAgree(t *testing.T) {
	f := newFixture(t)
	flagOut, _, code := f.run(t, "--version")
	if code != ExitOK {
		t.Fatalf("--version exit = %d", code)
	}
	commandOut, _, code := f.run(t, "version")
	if code != ExitOK {
		t.Fatalf("version exit = %d", code)
	}
	if flagOut != commandOut {
		t.Errorf("--version = %q, version = %q", flagOut, commandOut)
	}
	wantVersions := fmt.Sprintf("contract=%d schema=%d", core.ContractVersion, store.SchemaVersion())
	if !strings.Contains(flagOut, wantVersions) {
		t.Errorf("version output = %q, want it to carry %q", flagOut, wantVersions)
	}
}

// A run with every path overridden and no home is a supported configuration.
// It must work end to end when a policy file supplies a root, and fail with
// actionable guidance when none exists.
func TestFullyOverriddenRunWithoutHome(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	overrides := []string{
		"--config-dir", configDir,
		"--state-dir", filepath.Join(dir, "state"),
		"--cache-dir", filepath.Join(dir, "cache"),
	}
	f := &fixture{env: map[string]string{}}

	_, stderr, code := f.run(t, append(append([]string{}, overrides...), "status")...)
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	for _, want := range []string{"roots", "policy.yaml", config.EnvHome} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr %q does not mention %q", stderr, want)
		}
	}

	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "policy.yaml"), []byte("roots:\n  - path: /srv/work\n"), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	stdout, stderr, code := f.run(t, append(append([]string{}, overrides...), "status")...)
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "/srv/work") && !strings.Contains(stdout, "1 root(s)") {
		t.Errorf("status does not reflect the explicit policy:\n%s", stdout)
	}
}

// doctor must prove the mutation boundary is usable, not just the three XDG
// directories. A healthy verdict with no quarantine directory would be false.
func TestDoctorPreparesQuarantineDirectory(t *testing.T) {
	f := newFixture(t)
	custom := filepath.Join(t.TempDir(), "custom-quarantine")
	f.writePolicy(t, "roots:\n  - path: /repos\nretention:\n  quarantine_dir: "+custom+"\n")

	stdout, stderr, code := f.run(t, "doctor")
	if code != ExitOK {
		t.Fatalf("exit = %d, stdout = %s, stderr = %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "quarantine-dir") || !strings.Contains(stdout, custom) {
		t.Errorf("doctor does not check the configured quarantine directory:\n%s", stdout)
	}
	if _, err := os.Stat(custom); err != nil {
		t.Errorf("doctor reported healthy without creating %s: %v", custom, err)
	}
}

// Version metadata must agree across the envelope and the store statistics:
// contradictory numbers make a consumer guess which one is real.
func TestStatusJSONVersionsAgree(t *testing.T) {
	f := newFixture(t)
	if _, _, code := f.run(t, "doctor"); code != ExitOK {
		t.Fatalf("doctor exit = %d", code)
	}
	stdout, _, code := f.run(t, "--format", "json", "status")
	if code != ExitOK {
		t.Fatalf("status exit = %d", code)
	}
	var doc struct {
		SchemaVersion int `json:"schema_version"`
		Data          struct {
			ContractVersion int `json:"contract_version"`
			Store           struct {
				ExpectedSchemaVersion int `json:"expected_schema_version"`
				Stats                 struct {
					SchemaVersion   int `json:"schema_version"`
					ContractVersion int `json:"contract_version"`
				} `json:"stats"`
			} `json:"store"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("status JSON is not valid: %v\n%s", err, stdout)
	}
	if doc.Data.Store.Stats.ContractVersion != doc.Data.ContractVersion {
		t.Errorf("store stats contract version = %d, want %d",
			doc.Data.Store.Stats.ContractVersion, doc.Data.ContractVersion)
	}
	if doc.Data.Store.Stats.SchemaVersion != doc.Data.Store.ExpectedSchemaVersion {
		t.Errorf("store schema version = %d, want %d",
			doc.Data.Store.Stats.SchemaVersion, doc.Data.Store.ExpectedSchemaVersion)
	}
}
