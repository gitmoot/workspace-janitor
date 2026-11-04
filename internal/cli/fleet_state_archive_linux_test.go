//go:build linux

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
