//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

// fleetStateFixture is an archive_only state root holding a versioned work
// folder tree, run through the real `janitor archive --categories` command.
type fleetStateFixture struct {
	*categoryFixture
	state, mac string
}

func newFleetStateFixture(t *testing.T) *fleetStateFixture {
	t.Helper()
	x := &fleetStateFixture{categoryFixture: newCategoryFixture(t)}
	x.state = filepath.Join(x.home, "fleet-state")
	x.mac = filepath.Join(x.state, "mac-service")
	if err := os.MkdirAll(x.mac, 0o700); err != nil {
		t.Fatal(err)
	}
	return x
}

func (x *fleetStateFixture) folder(t *testing.T, path string, idle time.Duration, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(path, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	backdate(t, path, idle)
}

func (x *fleetStateFixture) policy(t *testing.T) {
	t.Helper()
	dest := func(name string) string {
		return fmt.Sprintf("  - name: %s\n    kind: %%s\n    roots: [%%s]\n    idle: %%s\n    archive:\n      directory: %s\n      expect_mount_source: \"\"\n      expect_fstype: \"\"\n    local_retention: none\n    max_items_per_cycle: 50\n", name, x.archive)
	}
	x.writePolicy(t, fmt.Sprintf(`roots:
  - path: %s
    max_depth: 1
    archive_only: true
  - path: %s
    max_depth: 1
    archive_only: true
collectors:
  deep_size: true
  git: true
  processes: true
  services: true
  proc_root: %s
  systemd_dirs: [%s]
  cron_paths: []
  pm2_dumps: []
protect:
  paths: [%s]
  name_patterns: ["*.env", "*passw*", "*token*", "*secret*"]
retention:
  default: none
  delete_enabled: true
prevention:
  min_free_bytes: 0
  min_free_percent: 0
limits:
  command_timeout: 30s
workspace_archive_categories:
`+dest("state-idle")+dest("mac-admin")+`    match: admin-v*-work
    keep_newest: 3
`, x.state, x.mac, x.proc, x.services, x.archive,
		"root_scratch", x.state, "14d",
		"versioned_work", x.mac, "1d"))
}

func (x *fleetStateFixture) item(t *testing.T, report categoryArchiveReport, path string) categoryArchiveItem {
	t.Helper()
	for _, item := range report.Items {
		if item.Path == path {
			return item
		}
	}
	t.Fatalf("%s missing from report: %+v", path, report.Items)
	return categoryArchiveItem{}
}

// Mac admin work folders beyond the 3 newest versions are archived; every
// folder of the 3 newest versions, including variants, stays local.
func TestVersionedWorkKeepsTheNewestVersions(t *testing.T) {
	x := newFleetStateFixture(t)
	for _, name := range []string{"admin-v0116-work", "admin-v0116-reset-r5-work", "admin-v0127-work",
		"admin-v0128-work", "admin-v0129-work", "admin-v0130-work", "admin-v0130-retry-work"} {
		x.folder(t, filepath.Join(x.mac, name), 3*24*time.Hour, map[string]string{"log.txt": name})
	}
	x.folder(t, filepath.Join(x.mac, "enrollment-work"), 30*24*time.Hour, map[string]string{"log.txt": "x"})
	x.policy(t)
	report := x.categories(t, true)
	for _, name := range []string{"admin-v0116-work", "admin-v0116-reset-r5-work", "admin-v0127-work"} {
		if item := x.item(t, report, filepath.Join(x.mac, name)); item.Status != categoryWouldArchive {
			t.Errorf("%s not proposed for archive: %+v", name, item)
		}
	}
	for _, name := range []string{"admin-v0128-work", "admin-v0129-work", "admin-v0130-work", "admin-v0130-retry-work"} {
		item := x.item(t, report, filepath.Join(x.mac, name))
		if item.Status != categoryRefused || !strings.Contains(strings.Join(item.Reasons, ";"), "newest versions") {
			t.Errorf("%s of a kept version not kept: %+v", name, item)
		}
	}
	// Non-matching folders in the versioned root fall under no category.
	if item := x.item(t, report, filepath.Join(x.mac, "enrollment-work")); item.Status != categoryRefused {
		t.Errorf("non-matching folder proposed: %+v", item)
	}
	archived := x.categories(t, false)
	if item := x.item(t, archived, filepath.Join(x.mac, "admin-v0127-work")); item.Status != categoryArchived || item.Binding == nil {
		t.Fatalf("old version not archived: %+v", item)
	}
}

// Top-level state folders idle 14 days are archived; a folder that is in use
// or holds credential material stays put, untouched, and is reported.
func TestArchiveOnlyRootArchivesIdleAndKeepsProtectedItems(t *testing.T) {
	x := newFleetStateFixture(t)
	idle, recent := filepath.Join(x.state, "old-incident"), filepath.Join(x.state, "this-week")
	live := filepath.Join(x.state, "old-but-open")
	x.folder(t, idle, 20*24*time.Hour, map[string]string{"notes.md": "done"})
	x.folder(t, recent, 2*24*time.Hour, map[string]string{"notes.md": "active"})
	// One folder per credential kind the owner named: private key, *.token,
	// .env file, password file. Each sits below the top level.
	secrets := map[string]string{}
	for name, file := range map[string]string{"run-a": "ssh/id_ed25519", "run-b": "auth/api.token",
		"run-c": "deploy/prod.env", "run-d": "notes/passwords.txt"} {
		path := filepath.Join(x.state, name)
		if err := os.MkdirAll(filepath.Join(path, filepath.Dir(file)), 0o700); err != nil {
			t.Fatal(err)
		}
		x.folder(t, path, 20*24*time.Hour, map[string]string{filepath.Join(filepath.Dir(file), filepath.Base(file)): "secret"})
		secrets[path] = "secret-like"
	}
	x.folder(t, live, 20*24*time.Hour, map[string]string{"run.log": "log"})
	pid := filepath.Join(x.proc, "4242")
	if err := os.MkdirAll(filepath.Join(pid, "fd"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pid, "cmdline"), []byte("/usr/bin/tail\x00-f\x00"+filepath.Join(live, "run.log")+"\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(live, filepath.Join(pid, "cwd")); err != nil {
		t.Fatal(err)
	}
	x.policy(t)
	report := x.categories(t, false)
	if item := x.item(t, report, idle); item.Status != categoryArchived {
		t.Fatalf("idle state folder not archived: %+v", item)
	}
	refused := map[string]string{recent: "changed", live: "active_process"}
	for path, why := range secrets {
		refused[path] = why
	}
	for path, why := range refused {
		item := x.item(t, report, path)
		if item.Status != categoryRefused || !strings.Contains(strings.Join(item.Reasons, ";"), why) {
			t.Errorf("%s: want refused for %q, got %+v", path, why, item)
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("refused item moved: %v", err)
		}
	}
	entries, err := os.ReadDir(x.archive)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "run-") {
			t.Fatalf("credential folder was copied off-host: %s", entry.Name())
		}
	}
}

// archive_only blocks every ordinary cleanup rule, and lifts only for an
// exact verified category archive: then plan proposes quarantine.
func TestArchiveOnlyRootBlocksOrdinaryCleanupUntilArchived(t *testing.T) {
	x := newFleetStateFixture(t)
	idle := filepath.Join(x.state, "old-run")
	x.folder(t, idle, 20*24*time.Hour, map[string]string{"out.txt": "ok"})
	// An ordinary cache rule that would quarantine the folder on sight.
	cache := filepath.Join(x.state, "old-cache")
	x.folder(t, cache, 20*24*time.Hour, map[string]string{"blob": "cached"})
	x.policy(t)
	s, err := os.ReadFile(filepath.Join(x.home, ".config", "workspace-janitor", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	x.writePolicy(t, strings.Replace(string(s), "retention:\n", "caches:\n  - name: state-cache\n    path: "+cache+"\n    action: quarantine\n    retention: none\nretention:\n", 1))
	x.source = idle
	if _, action := x.action(t, cache); action.Kind == core.ActionQuarantine || action.Kind == core.ActionDeleteCandidate {
		t.Fatalf("cache rule acted on an archive_only entry: %+v", action)
	}
	if _, action := x.action(t, idle); action.Kind == core.ActionQuarantine || action.Kind == core.ActionDeleteCandidate {
		t.Fatalf("archive_only entry proposed for cleanup before archiving: %+v", action)
	}
	x.categories(t, false)
	if _, action := x.action(t, idle); action.Kind != core.ActionQuarantine {
		t.Fatalf("exactly archived entry not proposed for quarantine: %+v", action)
	}
}

// Review #147 P1: an ordinary ancestor root listed before a nested
// archive_only root must not let an ordinary rule act inside it, whether
// the nested root or every configured root is scanned.
func TestArchiveOnlyHoldsUnderAnOverlappingOrdinaryRoot(t *testing.T) {
	x := newFleetStateFixture(t)
	cache := filepath.Join(x.mac, "old-cache")
	x.folder(t, cache, 20*24*time.Hour, map[string]string{"blob": "cached"})
	x.writePolicy(t, fmt.Sprintf(`roots:
  - path: %s
    max_depth: 2
  - path: %s
    max_depth: 1
    archive_only: true
collectors:
  deep_size: true
  git: false
  processes: false
  services: false
caches:
  - name: nested-cache
    path: %s
    action: quarantine
    retention: none
prevention:
  min_free_bytes: 0
  min_free_percent: 0
`, x.state, x.mac, cache))
	for _, scan := range [][]string{{"scan", x.mac}, {"scan"}} {
		if out, stderr, code := x.run(t, scan...); code != ExitOK {
			t.Fatalf("%v: %d %s %s", scan, code, out, stderr)
		}
		out, stderr, code := x.run(t, "--format", "json", "plan", "--no-jev")
		if code != ExitOK {
			t.Fatalf("plan: %d %s %s", code, out, stderr)
		}
		var doc struct {
			Data struct {
				Plan core.Plan `json:"plan"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatal(err)
		}
		for _, action := range doc.Data.Plan.Actions {
			if action.Path == cache && (action.Kind == core.ActionQuarantine || action.Kind == core.ActionDeleteCandidate) {
				t.Fatalf("after %v an ordinary rule proposed %s inside an archive_only root", scan, action.Kind)
			}
		}
	}
}

// Review #147 P1: a standing cache trim may not overlap an archive_only root.
func TestCacheTrimInsideArchiveOnlyRootIsRejected(t *testing.T) {
	x := newFleetStateFixture(t)
	cache := filepath.Join(x.state, "go-build")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	x.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\n    archive_only: true\nprevention:\n  min_free_percent: 0\n  cache_trims:\n    - kind: go-build\n      path: %s\n      binary: /usr/local/go/bin/go\n      max_bytes: 1\n", x.state, cache))
	out, stderr, code := x.run(t, "cycle")
	if code == ExitOK || !strings.Contains(stderr, "archive_only") {
		t.Fatalf("trim inside archive_only root accepted: %d %s %s", code, out, stderr)
	}
}

// Review #147 P2: a version archived while it was old must lose quarantine
// authority once it becomes one of the newest kept versions.
func TestVersionThatBecomesKeptLosesExpiryAuthority(t *testing.T) {
	x := newFleetStateFixture(t)
	for _, name := range []string{"admin-v0001-work", "admin-v0002-work", "admin-v0003-work"} {
		x.folder(t, filepath.Join(x.mac, name), 3*24*time.Hour, map[string]string{"log.txt": name})
	}
	x.policy(t)
	setKeep := func(n int) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(x.home, ".config", "workspace-janitor", "policy.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		s := string(raw)
		for _, k := range []string{"keep_newest: 1\n", "keep_newest: 3\n"} {
			s = strings.Replace(s, k, fmt.Sprintf("keep_newest: %d\n", n), 1)
		}
		x.writePolicy(t, s)
	}
	setKeep(1)
	report := x.categories(t, false)
	old := filepath.Join(x.mac, "admin-v0001-work")
	if item := x.item(t, report, old); item.Status != categoryArchived {
		t.Fatalf("old version not archived under keep_newest 1: %+v", item)
	}
	setKeep(3)
	x.source = old
	if _, action := x.action(t, old); action.Kind == core.ActionQuarantine || action.Kind == core.ActionDeleteCandidate {
		t.Fatalf("a now-kept version kept quarantine authority: %+v", action)
	}
}

// Review #147 round 2 P2: a version archived and then quarantined (its
// source gone) must lose expiry authority once it ranks among the newest.
func TestQuarantinedVersionThatBecomesKeptLosesExpiryAuthority(t *testing.T) {
	x := newFleetStateFixture(t)
	for _, name := range []string{"admin-v0001-work", "admin-v0002-work", "admin-v0003-work"} {
		x.folder(t, filepath.Join(x.mac, name), 3*24*time.Hour, map[string]string{"log.txt": name})
	}
	x.policy(t)
	policyFile := filepath.Join(x.home, ".config", "workspace-janitor", "policy.yaml")
	setKeep := func(n int) {
		t.Helper()
		raw, err := os.ReadFile(policyFile)
		if err != nil {
			t.Fatal(err)
		}
		s := string(raw)
		for _, k := range []string{"keep_newest: 1\n", "keep_newest: 3\n"} {
			s = strings.Replace(s, k, fmt.Sprintf("keep_newest: %d\n", n), 1)
		}
		x.writePolicy(t, s)
	}
	setKeep(1)
	old := filepath.Join(x.mac, "admin-v0001-work")
	if item := x.item(t, x.categories(t, false), old); item.Status != categoryArchived {
		t.Fatalf("old version not archived under keep_newest 1: %+v", item)
	}
	// Quarantine moved the source away.
	if err := os.Rename(old, filepath.Join(x.home, "quarantined-v0001")); err != nil {
		t.Fatal(err)
	}
	setKeep(3)
	e := &env{opts: &globalOpts{format: "json"}, stdout: io.Discard, stderr: io.Discard, lookup: config.MapLookup(x.env)}
	paths, err := e.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := e.loadPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	active, err := withCategoryArchives(context.Background(), paths, policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range active.WorkspaceArchives {
		if rule.Path == old && rule.LocalExpiryEnabled {
			t.Fatal("a quarantined version now among the 3 newest kept expiry authority")
		}
	}
}

// Live 2026-11-04: 155 verified category archives each needed ~0.6 s to bind,
// the collector missed its 60 s command timeout, and a missed deadline drops
// the whole result, so no item was ever bound and nothing could be freed,
// scan after scan. Binding must stop at its budget and publish what it bound.
func TestSlowArchiveBindingStillBindsSomeItemsEachScan(t *testing.T) {
	x := newFleetStateFixture(t)
	var folders []string
	for i := range 5 {
		path := filepath.Join(x.state, fmt.Sprintf("old-%d", i))
		x.folder(t, path, 20*24*time.Hour, map[string]string{"log.txt": path})
		folders = append(folders, path)
	}
	x.policy(t)
	policyFile := filepath.Join(x.home, ".config", "workspace-janitor", "policy.yaml")
	raw, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatal(err)
	}
	x.writePolicy(t, strings.Replace(string(raw), "command_timeout: 30s", "command_timeout: 3s", 1))
	report := x.categories(t, false)
	for _, path := range folders {
		if item := x.item(t, report, path); item.Status != categoryArchived {
			t.Fatalf("%s not archived: %+v", path, item)
		}
	}
	collect.BeforeWorkspaceArchiveBind = func() { time.Sleep(700 * time.Millisecond) }
	defer func() { collect.BeforeWorkspaceArchiveBind = nil }()
	x.data(t, "scan")
	var plan core.Plan
	field(t, x.data(t, "plan", "--no-jev"), "plan", &plan)
	bound := 0
	for _, action := range plan.Actions {
		if !slices.Contains(folders, action.Path) {
			continue
		}
		if action.Kind == core.ActionQuarantine {
			bound++
		}
		for _, reason := range action.Reasons {
			if strings.Contains(reason, "collector_failure") {
				t.Fatalf("%s: binding result lost to the collector deadline: %v", action.Path, action.Reasons)
			}
		}
	}
	if bound == 0 || bound == len(folders) {
		t.Fatalf("want some but not all of %d slow bindings bound within the budget, got %d", len(folders), bound)
	}
}

// Review #154 P2: with the state root walked to depth 2, every Mac work
// folder is listed twice (once per root). A deferred later copy must not
// erase an earlier copy's binding.
func TestSlowArchiveBindingSurvivesOverlappingRoots(t *testing.T) {
	x := newFleetStateFixture(t)
	var archived []string
	for v := 1; v <= 8; v++ {
		path := filepath.Join(x.mac, fmt.Sprintf("admin-v%04d-work", v))
		x.folder(t, path, 3*24*time.Hour, map[string]string{"log.txt": path})
		if v <= 5 {
			archived = append(archived, path)
		}
	}
	x.policy(t)
	policyFile := filepath.Join(x.home, ".config", "workspace-janitor", "policy.yaml")
	raw, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatal(err)
	}
	overlapping := strings.Replace(string(raw), "command_timeout: 30s", "command_timeout: 3s", 1)
	overlapping = strings.Replace(overlapping, "max_depth: 1", "max_depth: 2", 1)
	x.writePolicy(t, overlapping)
	report := x.categories(t, false)
	for _, path := range archived {
		if item := x.item(t, report, path); item.Status != categoryArchived {
			t.Fatalf("%s not archived: %+v", path, item)
		}
	}
	collect.BeforeWorkspaceArchiveBind = func() { time.Sleep(700 * time.Millisecond) }
	defer func() { collect.BeforeWorkspaceArchiveBind = nil }()
	x.data(t, "scan")
	var plan core.Plan
	field(t, x.data(t, "plan", "--no-jev"), "plan", &plan)
	bound := map[string]bool{}
	for _, action := range plan.Actions {
		if slices.Contains(archived, action.Path) && action.Kind == core.ActionQuarantine {
			bound[action.Path] = true
		}
	}
	if len(bound) == 0 {
		t.Fatalf("no binding survived duplicate listing under overlapping roots")
	}
}

// Live 2026-11-04: quarantining one archived state folder re-observed its
// whole parent and fully re-verified every sibling's archive, so 60 actions
// made no progress in an hour. Revalidation must bind only its target.
func TestQuarantineRevalidationBindsOnlyItsTarget(t *testing.T) {
	x := newFleetStateFixture(t)
	var folders []string
	for i := range 4 {
		path := filepath.Join(x.state, fmt.Sprintf("old-%d", i))
		x.folder(t, path, 20*24*time.Hour, map[string]string{"log.txt": path})
		folders = append(folders, path)
	}
	x.policy(t)
	report := x.categories(t, false)
	for _, path := range folders {
		if item := x.item(t, report, path); item.Status != categoryArchived {
			t.Fatalf("%s not archived: %+v", path, item)
		}
	}
	x.source = folders[0]
	plan, action := x.action(t, folders[0])
	if action.Kind != core.ActionQuarantine {
		t.Fatalf("archived folder not proposed for quarantine: %+v", action)
	}
	x.data(t, "plan", "--plan", plan.ID, "--approve", action.ID, "--no-jev")
	binds := 0
	collect.BeforeWorkspaceArchiveBind = func() { binds++ }
	defer func() { collect.BeforeWorkspaceArchiveBind = nil }()
	x.data(t, "apply", "--quarantine", "--action", action.ID, "--dry-run=false", "--confirm")
	if _, err := os.Lstat(folders[0]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target not quarantined: %v", err)
	}
	if binds > 2 {
		t.Fatalf("revalidating one target bound %d archives; its %d siblings must not be re-verified", binds, len(folders)-1)
	}
}

// Live 2026-11-05: an idle state folder holding gitmoot's remote_exec
// binaries was archived and quarantined although gitmoot's config.toml named
// a file inside it. Every path held in a value of a configured config file
// is in use, however it is quoted or escaped; a path named only in a comment
// is not; a config file that does not parse leaves nothing safe to remove.
func TestConfigFileReferenceKeepsAnIdleFolderLocal(t *testing.T) {
	x := newFleetStateFixture(t)
	plain := filepath.Join(x.state, "sandboxd-omp")
	spaced := filepath.Join(x.state, "service bundle")
	hashed := filepath.Join(x.state, "used#current")
	semi := filepath.Join(x.state, "used;current")
	escaped := filepath.Join(x.state, "escaped-slash")
	mentioned := filepath.Join(x.state, "old-notes")
	for _, path := range []string{plain, spaced, hashed, semi, escaped, mentioned} {
		x.folder(t, path, 20*24*time.Hour, map[string]string{"file": "data"})
	}
	configDir := filepath.Join(x.home, ".gitmoot")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	escapedValue := strings.Replace(filepath.Join(escaped, "file"), "/", `\u002f`, 1)
	body := fmt.Sprintf("[remote_exec.sandboxd]\nomp_linux_arm64_file = %q\nbundle = %q\nlist = [%q, %q]\nescaped = \"%s\"\n# Notes: %s/\n",
		filepath.Join(plain, "file"), filepath.Join(spaced, "file"), filepath.Join(hashed, "file"), filepath.Join(semi, "file"), escapedValue, mentioned)
	if err := os.WriteFile(filepath.Join(configDir, "config.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	x.policy(t)
	policyFile := filepath.Join(x.home, ".config", "workspace-janitor", "policy.yaml")
	raw, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatal(err)
	}
	// Written with ~, as documented: the list must be expanded like the others.
	x.writePolicy(t, strings.Replace(string(raw), "  pm2_dumps: []\n", "  pm2_dumps: []\n  config_files: [~/.gitmoot/config.toml]\n", 1))
	report := x.categories(t, false)
	for _, path := range []string{plain, spaced, hashed, semi, escaped} {
		item := x.item(t, report, path)
		if item.Status == categoryArchived || !strings.Contains(strings.Join(item.Reasons, " "), "service_reference") {
			t.Fatalf("%s is named in a config value but was not kept as a service reference: %+v", path, item)
		}
	}
	if got := x.item(t, report, mentioned); got.Status != categoryArchived {
		t.Fatalf("a path named only in a comment blocked archiving: %+v", got)
	}

	// An unparseable config file leaves its references unknown: a folder
	// may still be copied to its archive, but never removed locally.
	late := filepath.Join(x.state, "late-folder")
	x.folder(t, late, 20*24*time.Hour, map[string]string{"file": "data"})
	if got := x.item(t, x.categories(t, false), late); got.Status != categoryArchived {
		t.Fatalf("late folder not archived: %+v", got)
	}
	x.source = late
	plan, action := x.action(t, late)
	if action.Kind != core.ActionQuarantine {
		t.Fatalf("archived folder not proposed for quarantine: %+v", action)
	}
	x.data(t, "plan", "--plan", plan.ID, "--approve", action.ID, "--no-jev")
	if err := os.WriteFile(filepath.Join(configDir, "config.toml"), []byte("this is [not toml"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, _ = x.run(t, "apply", "--quarantine", "--action", action.ID, "--dry-run=false", "--confirm")
	if _, err := os.Stat(filepath.Join(late, "file")); err != nil {
		t.Fatalf("quarantined while a configured config file could not be parsed: %v", err)
	}
}

// Review #158 round 2 P1: every document of a YAML stream is a reference
// source, and a malformed later document is not silently skipped.
func TestConfigFileReferencesCoverEveryYAMLDocument(t *testing.T) {
	x := newFleetStateFixture(t)
	first := filepath.Join(x.state, "first-doc")
	second := filepath.Join(x.state, "second-doc")
	for _, path := range []string{first, second} {
		x.folder(t, path, 20*24*time.Hour, map[string]string{"file": "data"})
	}
	config := filepath.Join(x.home, "service.yaml")
	if err := os.WriteFile(config, []byte(fmt.Sprintf("a: %s\n---\nb: %s\n", first, second)), 0o600); err != nil {
		t.Fatal(err)
	}
	x.policy(t)
	policyFile := filepath.Join(x.home, ".config", "workspace-janitor", "policy.yaml")
	raw, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatal(err)
	}
	x.writePolicy(t, strings.Replace(string(raw), "  pm2_dumps: []\n", "  pm2_dumps: []\n  config_files: ["+config+"]\n", 1))
	report := x.categories(t, true)
	for _, path := range []string{first, second} {
		if item := x.item(t, report, path); !strings.Contains(strings.Join(item.Reasons, " "), "service_reference") {
			t.Fatalf("%s named in a YAML document was not kept: %+v", path, item)
		}
	}
	if err := os.WriteFile(config, []byte(fmt.Sprintf("a: %s\n---\nb: [unclosed\n", first)), 0o600); err != nil {
		t.Fatal(err)
	}
	var scan core.Scan
	field(t, x.data(t, "scan"), "scan", &scan)
	for _, report := range scan.Collectors {
		if report.Name == "services" && report.Status == core.CollectorRan {
			t.Fatalf("a malformed later YAML document left services complete: %+v", report)
		}
	}
}
