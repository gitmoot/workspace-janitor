//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/store"
	"github.com/gitmoot/workspace-janitor/internal/workspacearchive"
)

const categoryIdleAge = 60 * 24 * time.Hour

// categoryFixture is an isolated home whose single inventory root holds
// category candidates: the released scratch directory of the workspace
// archive fixture plus whatever a test adds. All three categories share the
// root and one protected archive directory outside it.
type categoryFixture struct {
	*workspaceArchiveFixture
	services, repos, remote string
	retention               string
	maxItems                int
	extra, prevention       string
	agents                  []collect.AgentSource
	files                   map[string][]byte
}

func newCategoryFixture(t *testing.T) *categoryFixture {
	t.Helper()
	x := &categoryFixture{workspaceArchiveFixture: newWorkspaceArchiveFixture(t), retention: "none", maxItems: 20, files: map[string][]byte{}}
	x.services = filepath.Join(x.home, "services")
	x.repos = filepath.Join(x.home, "repos")
	x.remote = filepath.Join(x.home, "remote.git")
	for _, dir := range []string{x.services, x.repos} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"README.md", "sub/data.txt"} {
		data, err := os.ReadFile(filepath.Join(x.source, name))
		if err != nil {
			t.Fatal(err)
		}
		x.files[name] = data
	}
	x.write(t)
	return x
}

func (x *categoryFixture) write(t *testing.T) {
	t.Helper()
	category := func(name, kind string) string {
		return fmt.Sprintf("  - name: %s\n    kind: %s\n    roots: [%s]\n    local_retention: %s\n    max_items_per_cycle: %d\n    archive:\n      directory: %s\n",
			name, kind, x.work, x.retention, x.maxItems, x.archive)
	}
	x.writePolicy(t, fmt.Sprintf(`roots:
  - path: %s
    max_depth: 1
protect:
  paths: [%s]
collectors:
  git: true
  processes: true
  services: true
  proc_root: %s
  systemd_dirs: [%s]
  cron_paths: []
  pm2_dumps: []
retention:
  default: none
  delete_enabled: true
prevention:
  min_free_bytes: 0
  min_free_percent: 0
%slimits:
  command_timeout: 30s
workspace_archive_categories:
%s%s%s%s`, x.work, x.archive, x.proc, x.services, x.prevention,
		category("scratch", "root_scratch"), category("merged", "merged_worktrees"), category("clones", "pushed_clones"), x.extra))
}

func (x *categoryFixture) paths(t *testing.T) config.Paths {
	t.Helper()
	paths, err := config.ResolvePaths(config.MapLookup(x.env), config.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

// runAgents runs the CLI with the fixture's registered-agent adapters.
func (x *categoryFixture) runAgents(t *testing.T, args ...string) (string, string, ExitCode) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(context.Background(), Options{Args: args, Stdout: &out, Stderr: &errOut, Lookup: config.MapLookup(x.env), AgentSources: x.agents})
	return out.String(), errOut.String(), code
}

func (x *categoryFixture) categories(t *testing.T, dryRun bool) categoryArchiveReport {
	t.Helper()
	args := []string{"--format", "json", "archive", "--categories"}
	if !dryRun {
		args = append(args, "--dry-run=false", "--confirm")
	}
	out, stderr, code := x.runAgents(t, args...)
	if code != ExitOK {
		t.Fatalf("%v: exit=%d stderr=%s stdout=%s", args, code, stderr, out)
	}
	var doc struct {
		Data categoryArchiveReport `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return doc.Data
}

func categoryItem(t *testing.T, report categoryArchiveReport, path string) categoryArchiveItem {
	t.Helper()
	for _, item := range report.Items {
		if item.Path == path {
			return item
		}
	}
	t.Fatalf("%s missing from the category report: %+v", path, report.Items)
	return categoryArchiveItem{}
}

func (x *categoryFixture) git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "HOME="+x.home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=Fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid", "GIT_COMMITTER_NAME=Fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git -C %s %v: %s %v", dir, args, out, err)
	}
}

// published creates, once, a main repository outside the root whose only
// commit is pushed to a bare remote.
func (x *categoryFixture) published(t *testing.T) string {
	t.Helper()
	main := filepath.Join(x.repos, "main")
	if _, err := os.Lstat(main); err == nil {
		return main
	}
	if err := os.MkdirAll(main, 0o700); err != nil {
		t.Fatal(err)
	}
	x.git(t, main, "init", "-q")
	if err := os.WriteFile(filepath.Join(main, "tracked"), []byte("published\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.git(t, main, "add", "tracked")
	x.git(t, main, "commit", "-qm", "published")
	x.git(t, x.home, "init", "--bare", "-q", x.remote)
	x.git(t, main, "remote", "add", "origin", x.remote)
	x.git(t, main, "push", "-q", "-u", "origin", "HEAD")
	return main
}

// clone makes a standalone checkout of the published remote inside the root.
// file:// avoids hard-linked objects.
func (x *categoryFixture) clone(t *testing.T, name string) string {
	t.Helper()
	x.published(t)
	path := filepath.Join(x.work, name)
	x.git(t, x.home, "clone", "-q", "file://"+x.remote, path)
	return path
}

// linked adds a linked worktree inside the root whose branch is pushed.
func (x *categoryFixture) linked(t *testing.T, name string) string {
	t.Helper()
	main := x.published(t)
	path := filepath.Join(x.work, name)
	x.git(t, main, "worktree", "add", "-q", "-b", name, path)
	x.git(t, path, "push", "-q", "-u", "origin", "HEAD")
	return path
}

func (x *categoryFixture) scratch(t *testing.T, name string, files map[string]string) string {
	t.Helper()
	path := filepath.Join(x.work, name)
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	for file, data := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(path, file)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, file), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// backdate moves every modification time in the tree (children before their
// parents, symlinks untouched) age into the past.
func backdate(t *testing.T, root string, age time.Duration) {
	t.Helper()
	when := time.Now().Add(-age)
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&fs.ModeSymlink == 0 {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := len(paths) - 1; i >= 0; i-- {
		if err := os.Chtimes(paths[i], when, when); err != nil {
			t.Fatal(err)
		}
	}
}

func (x *categoryFixture) action(t *testing.T, path string) (core.Plan, core.Action) {
	t.Helper()
	x.data(t, "scan")
	var plan core.Plan
	field(t, x.data(t, "plan", "--no-jev"), "plan", &plan)
	for _, action := range plan.Actions {
		if action.Path == path {
			return plan, action
		}
	}
	t.Fatalf("%s missing from plan: %+v", path, plan.Actions)
	return core.Plan{}, core.Action{}
}

func (x *categoryFixture) preserved(t *testing.T, root string) {
	t.Helper()
	for name, want := range x.files {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s/%s changed or vanished: %v", root, name, err)
		}
	}
}

func (x *categoryFixture) receipt(t *testing.T) core.CleanupItem {
	t.Helper()
	db, err := store.OpenExisting(context.Background(), x.paths(t).DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var found core.CleanupItem
	err = db.Read(context.Background(), func(tx *store.Tx) error {
		items, err := tx.CleanupItems(context.Background(), "")
		for _, item := range items {
			if item.Source == x.source {
				found = item
			}
		}
		return err
	})
	if err != nil || found.CleanupID == "" {
		t.Fatalf("quarantine receipt for %s absent: %v", x.source, err)
	}
	return found
}

// quarantine approves the proposed quarantine of the released directory and
// moves it.
func (x *categoryFixture) quarantine(t *testing.T) core.CleanupItem {
	t.Helper()
	plan, action := x.action(t, x.source)
	if action.Kind != core.ActionQuarantine {
		t.Fatalf("category-archived item not proposed for quarantine: %+v", action)
	}
	x.data(t, "plan", "--plan", plan.ID, "--approve", action.ID, "--no-jev")
	x.data(t, "apply", "--quarantine", "--action", action.ID, "--dry-run=false", "--confirm")
	if _, err := os.Lstat(x.source); !os.IsNotExist(err) {
		t.Fatalf("quarantine left the source in place: %v", err)
	}
	return x.receipt(t)
}

// recordBackdated archives the released directory exactly as a category run
// would, then backdates its manifest by age and records that receipt, so
// local retention can be exercised without waiting.
func (x *categoryFixture) recordBackdated(t *testing.T, age time.Duration) {
	t.Helper()
	ctx := context.Background()
	paths := x.paths(t)
	policy, err := config.LoadPolicy(paths)
	if err != nil {
		t.Fatal(err)
	}
	category, ok := policy.WorkspaceArchiveCategory("scratch")
	if !ok {
		t.Fatal("scratch category missing")
	}
	runID := "category-fixture"
	owner := config.CategoryOwnerPrefix + category.Name
	rule := categoryRule(category, categoryItemName(category.Name, x.source, runID), x.source, owner, owner+"@"+runID)
	m, binding, err := workspacearchive.Create(ctx, rule, workspacearchive.PolicyScope(policy, rule), func() error { return nil })
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	m.CreatedAt, m.VerifiedAt = m.CreatedAt.Add(-age), m.VerifiedAt.Add(-age)
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(binding.Manifest, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	db, err := store.Open(ctx, paths.DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = db.Write(ctx, func(tx *store.Tx) error {
		return tx.RecordCategoryArchive(ctx, store.CategoryArchive{
			Name: rule.Name, Category: category.Name, Kind: string(category.Kind), Path: x.source, Owner: owner, Release: rule.Release,
			RunID: runID, ArchiveDirectory: x.archive, Manifest: binding.Manifest, ManifestSHA256: hex.EncodeToString(sum[:]),
			ContentBytes: m.ContentBytes, Members: len(m.Members), CreatedAt: m.CreatedAt, RecordedAt: time.Now(),
		})
	})
	if err != nil {
		t.Fatal(err)
	}
}

type categoryAgents []collect.AgentRef

func (categoryAgents) Name() string { return "fixture-agents" }
func (a categoryAgents) ActiveDirectories(context.Context) ([]collect.AgentRef, error) {
	return a, nil
}

// Each kind selects its matching fixture; every non-matching or unsafe
// candidate is refused with its reason; the dry run writes nothing.
func TestCategoryArchiveDryRunSelectsEachKindAndRefusesUnsafeItems(t *testing.T) {
	x := newCategoryFixture(t)
	idle := map[string]string{"README.md": "idle\n"}
	clone := x.clone(t, "clone")
	dirty := x.clone(t, "dirty-clone")
	if err := os.WriteFile(filepath.Join(dirty, "tracked"), []byte("uncommitted edit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stashed := x.clone(t, "stash-clone")
	if err := os.WriteFile(filepath.Join(stashed, "tracked"), []byte("stashed edit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.git(t, stashed, "stash", "-q")
	unpushed := x.clone(t, "unpushed-clone")
	if err := os.WriteFile(filepath.Join(unpushed, "tracked"), []byte("local only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.git(t, unpushed, "commit", "-qam", "local only")
	linked := x.linked(t, "linked")
	secret := x.scratch(t, "secret", map[string]string{"README.md": "idle\n", ".env": "TOKEN=fixture\n"})
	kept := x.scratch(t, "kept", idle)
	live := x.scratch(t, "live", idle)
	registered := x.scratch(t, "registered", idle)
	dependent := x.scratch(t, "dependent", map[string]string{"sub/data": "idle\n"})
	for _, path := range []string{x.source, clone, dirty, stashed, unpushed, linked, secret, kept, live, registered, dependent} {
		backdate(t, path, categoryIdleAge)
	}
	recent := x.scratch(t, "recent", idle)
	link := filepath.Join(x.work, "uses-dependent")
	if err := os.Symlink(filepath.Join(dependent, "sub"), link); err != nil {
		t.Fatal(err)
	}
	pid := filepath.Join(x.proc, "424242")
	if err := os.MkdirAll(pid, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pid, "comm"), []byte("editor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(live, filepath.Join(pid, "cwd")); err != nil {
		t.Fatal(err)
	}
	x.agents = []collect.AgentSource{categoryAgents{{Agent: "seat-z", Path: registered, Detail: "fixture registration"}}}
	x.extra = fmt.Sprintf("workspace_archive_keep:\n  - path: %s\n    owner: seat-b\n    reference: keep-msg-1\n", kept)
	x.write(t)

	report := x.categories(t, true)
	if !report.DryRun || report.Status != "preview" || report.Archived != 0 {
		t.Fatalf("dry run report = %+v", report)
	}
	for path, kind := range map[string]string{x.source: "root_scratch", clone: "pushed_clones", linked: "merged_worktrees"} {
		item := categoryItem(t, report, path)
		if item.Status != categoryWouldArchive || item.Kind != kind || !item.SizeKnown || item.SizeBytes <= 0 || item.IdleFor == "" || item.NewestModifiedAt == nil || item.Name == "" {
			t.Errorf("%s not selected as %s: %+v", path, kind, item)
		}
	}
	for path, fragment := range map[string]string{
		recent:     "idle",
		dirty:      "uncommitted",
		stashed:    "stash",
		unpushed:   "remote-tracking",
		secret:     ".env",
		kept:       "KEEP",
		live:       "",
		registered: "",
		dependent:  "",
		link:       "directories",
	} {
		item := categoryItem(t, report, path)
		reasons := strings.Join(item.Reasons, "\n")
		if item.Status != categoryRefused || len(item.Reasons) == 0 || !strings.Contains(reasons, fragment) {
			t.Errorf("%s not refused for %q: %+v", path, fragment, item)
		}
	}
	if entries, err := os.ReadDir(x.archive); err != nil || len(entries) != 0 {
		t.Fatalf("dry run wrote %d archive entries: %v", len(entries), err)
	}
	if _, err := os.Stat(x.paths(t).DatabaseFile); !os.IsNotExist(err) {
		t.Fatalf("dry run created Janitor state: %v", err)
	}
}

func TestCategoryArchiveHonorsMaxItemsPerCycle(t *testing.T) {
	x := newCategoryFixture(t)
	x.maxItems = 2
	x.write(t)
	paths := []string{x.source}
	for _, name := range []string{"scratch-a", "scratch-b"} {
		paths = append(paths, x.scratch(t, name, map[string]string{"README.md": name + "\n"}))
	}
	for _, path := range paths {
		backdate(t, path, categoryIdleAge)
	}
	count := func(report categoryArchiveReport) (archived, would, deferred, already int) {
		return report.Archived, report.WouldArchive, report.Deferred, report.AlreadyArchived
	}
	if archived, would, deferred, _ := count(x.categories(t, true)); archived != 0 || would != 2 || deferred != 1 {
		t.Fatalf("dry run archived=%d would=%d deferred=%d, want 0/2/1", archived, would, deferred)
	}
	if archived, _, deferred, _ := count(x.categories(t, false)); archived != 2 || deferred != 1 {
		t.Fatalf("first run archived=%d deferred=%d, want 2/1", archived, deferred)
	}
	if archived, _, deferred, already := count(x.categories(t, false)); archived != 1 || deferred != 0 || already != 2 {
		t.Fatalf("second run archived=%d deferred=%d already=%d, want 1/0/2", archived, deferred, already)
	}
	records, err := store.ReadCategoryArchives(context.Background(), x.paths(t).DatabaseFile)
	if err != nil || len(records) != 3 {
		t.Fatalf("recorded %d category receipts: %v", len(records), err)
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("archiving removed %s: %v", path, err)
		}
	}
}

// local_retention none: a verified, bound category archive is proposed for
// quarantine at once; expiry re-binds the quarantined copy; the item restores
// from its archive by original path.
func TestCategoryArchiveQuarantinesExpiresAndRestores(t *testing.T) {
	x := newCategoryFixture(t)
	backdate(t, x.source, categoryIdleAge)
	report := x.categories(t, false)
	item := categoryItem(t, report, x.source)
	if item.Status != categoryArchived || item.Binding == nil || report.LocalFreedBytes != 0 {
		t.Fatalf("category archive not created: %+v", item)
	}
	if _, err := os.Stat(item.Binding.Manifest); err != nil {
		t.Fatalf("manifest missing: %v", err)
	}
	x.preserved(t, x.source)
	if again := categoryItem(t, x.categories(t, true), x.source); again.Status != categoryAlreadyArchived {
		t.Fatalf("unchanged archived item re-selected: %+v", again)
	}
	receipt := x.quarantine(t)
	x.preserved(t, receipt.Destination)
	if receipt.Quarantined == nil || receipt.Quarantined.WorkspaceArchive == nil || receipt.Quarantined.WorkspaceArchive.ManifestSHA256 != item.Binding.ManifestSHA256 {
		t.Fatalf("quarantine snapshot lacks the category archive binding: %+v", receipt.Quarantined)
	}
	if _, _, code := x.run(t, "apply", "--expire", "--cleanup", receipt.CleanupID, "--dry-run=false", "--confirm"); code != ExitOK {
		t.Fatalf("expiry of a verified category item failed: exit %d", code)
	}
	if _, err := os.Lstat(receipt.Destination); !os.IsNotExist(err) {
		t.Fatalf("expiry kept the quarantined copy: %v", err)
	}
	preview := x.data(t, "archive", "--restore-category-item", x.source, "--restore-to", x.source)
	var status string
	field(t, preview, "status", &status)
	if _, err := os.Lstat(x.source); status != "preview" || !os.IsNotExist(err) {
		t.Fatalf("restore preview status=%q wrote %v", status, err)
	}
	restored := x.data(t, "archive", "--restore-category-item", x.source, "--restore-to", x.source, "--dry-run=false", "--confirm")
	field(t, restored, "status", &status)
	if status != "restored" {
		t.Fatalf("restore status = %q", status)
	}
	x.preserved(t, x.source)
}

// local_retention 30d holds the archived item until 30 days after the archive
// was created; then the same flow proposes quarantine.
func TestCategoryArchiveLocalRetentionDelaysQuarantine(t *testing.T) {
	t.Run("30d just archived", func(t *testing.T) {
		x := newCategoryFixture(t)
		x.retention = "30d"
		x.write(t)
		backdate(t, x.source, categoryIdleAge)
		if item := categoryItem(t, x.categories(t, false), x.source); item.Status != categoryArchived {
			t.Fatalf("not archived: %+v", item)
		}
		if _, action := x.action(t, x.source); action.Kind != core.ActionKeep {
			t.Fatalf("30d retention proposed %s for a fresh archive", action.Kind)
		}
		x.preserved(t, x.source)
	})
	t.Run("30d elapsed", func(t *testing.T) {
		x := newCategoryFixture(t)
		x.retention = "30d"
		x.write(t)
		backdate(t, x.source, categoryIdleAge)
		x.recordBackdated(t, 31*24*time.Hour)
		if _, action := x.action(t, x.source); action.Kind != core.ActionQuarantine {
			t.Fatalf("elapsed 30d retention proposed %s", action.Kind)
		}
	})
	t.Run("none", func(t *testing.T) {
		x := newCategoryFixture(t)
		backdate(t, x.source, categoryIdleAge)
		x.categories(t, false)
		if _, action := x.action(t, x.source); action.Kind != core.ActionQuarantine {
			t.Fatalf("none retention proposed %s", action.Kind)
		}
	})
}

// A change after archiving fails Bind, so the item is retained and is not
// archived again while it is recent.
func TestCategoryArchiveChangedItemIsRetained(t *testing.T) {
	x := newCategoryFixture(t)
	backdate(t, x.source, categoryIdleAge)
	x.categories(t, false)
	if err := os.WriteFile(filepath.Join(x.source, "README.md"), []byte("edited after archiving\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, action := x.action(t, x.source); action.Kind == core.ActionQuarantine {
		t.Fatal("a changed category item was proposed for quarantine")
	}
	item := categoryItem(t, x.categories(t, true), x.source)
	if item.Status != categoryRefused || !strings.Contains(strings.Join(item.Reasons, "\n"), "idle") {
		t.Fatalf("changed item re-archived before it was idle again: %+v", item)
	}
}

// Restoring a quarantined category item is the owner's undo: its archive
// loses local expiry authority instead of re-quarantining it next cycle.
func TestCategoryArchiveOwnerRestoreWithdrawsExpiry(t *testing.T) {
	x := newCategoryFixture(t)
	backdate(t, x.source, categoryIdleAge)
	x.categories(t, false)
	receipt := x.quarantine(t)
	x.data(t, "restore", "--confirm", receipt.CleanupID)
	x.preserved(t, x.source)
	if _, action := x.action(t, x.source); action.Kind == core.ActionQuarantine {
		t.Fatal("an owner-restored category item was proposed for quarantine again")
	}
	item := categoryItem(t, x.categories(t, true), x.source)
	if item.Status != categoryAlreadyArchived || !strings.Contains(strings.Join(item.Reasons, "\n"), "restored") {
		t.Fatalf("restored item report = %+v", item)
	}
}

// The daily cycle archives categories before it scans, so auto-quarantine
// moves a local_retention none item in the same cycle.
func TestCycleArchivesCategoriesBeforePlanning(t *testing.T) {
	x := newCategoryFixture(t)
	x.prevention = "  auto_quarantine: true\n"
	x.write(t)
	backdate(t, x.source, categoryIdleAge)
	out, stderr, code := x.runAgents(t, "cycle")
	if code != ExitOK {
		t.Fatalf("cycle: exit=%d %s %s", code, out, stderr)
	}
	var report struct {
		Quarantine       string                 `json:"quarantine"`
		CategoryArchives *categoryArchiveReport `json:"category_archives"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("cycle output: %v\n%s", err, out)
	}
	if report.CategoryArchives == nil || report.CategoryArchives.Archived != 1 || report.Quarantine != "applied" {
		t.Fatalf("cycle report = %s", out)
	}
	if _, err := os.Lstat(x.source); !os.IsNotExist(err) {
		t.Fatalf("cycle did not quarantine the archived item: %v", err)
	}
	x.preserved(t, x.receipt(t).Destination)
}
