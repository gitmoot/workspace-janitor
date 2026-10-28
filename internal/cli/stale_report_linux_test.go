//go:build linux

package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

// staleFixture is the category fixture's isolated home with a stale report
// over its single root instead of archive categories. Owners come from a
// fixture Gitmoot ledger at ~/.gitmoot.
type staleFixture struct {
	*categoryFixture
	gitmoot, releaseAction string
	reportMaxItems         int
}

func newStaleFixture(t *testing.T) *staleFixture {
	t.Helper()
	x := &staleFixture{categoryFixture: newCategoryFixture(t), releaseAction: "none", reportMaxItems: 20}
	x.gitmoot = filepath.Join(x.home, ".gitmoot")
	if err := os.MkdirAll(x.gitmoot, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(x.gitmoot, "gitmoot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range []string{
		`CREATE TABLE jobs(id TEXT, state TEXT, payload TEXT, updated_at TEXT, dispatched_by TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE tasks(id TEXT, state TEXT, worktree_path TEXT, disposal_escalation_role TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE cleanup_obligations(owner_job_id TEXT, expected_path TEXT, resource_kind TEXT, state TEXT, created_at TEXT, updated_at TEXT)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	x.write(t)
	return x
}

func (x *staleFixture) write(t *testing.T) {
	t.Helper()
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
limits:
  command_timeout: 30s
%s
gitmoot:
  home: %s
  database: %s
report:
  enabled: true
  roots: [%s]
  coordinator_role: coordinator
  release_action: %s
  local_retention: none
  max_items_per_cycle: %d
  archive:
    directory: %s
%s`, x.work, x.archive, x.proc, x.services, x.limits, x.gitmoot, filepath.Join(x.gitmoot, "gitmoot.db"), x.work, x.releaseAction, x.reportMaxItems, x.archive, x.extra))
}

// job records a Gitmoot job for path dispatched by role.
func (x *staleFixture) job(t *testing.T, id, state, role, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(x.gitmoot, "gitmoot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	payload, err := json.Marshal(map[string]string{"worktree_path": path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO jobs VALUES (?, ?, ?, '2026-01-01 00:00:00', ?)`, id, state, string(payload), role); err != nil {
		t.Fatal(err)
	}
}

func (x *staleFixture) stale(t *testing.T, args ...string) staleReport {
	t.Helper()
	args = append([]string{"--format", "json", "report", "stale"}, args...)
	out, stderr, code := x.runAgents(t, args...)
	if code != ExitOK {
		t.Fatalf("%v: exit=%d stderr=%s stdout=%s", args, code, stderr, out)
	}
	var doc struct {
		Data staleReport `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return doc.Data
}

// reply runs a release or keep reply and returns its exit code and stderr.
func (x *staleFixture) reply(t *testing.T, args ...string) (ExitCode, string) {
	t.Helper()
	out, stderr, code := x.runAgents(t, append([]string{"--format", "json", "report"}, args...)...)
	if code == ExitOK && !strings.Contains(out, `"stale_report_reply"`) {
		t.Fatalf("%v succeeded without a reply document: %s", args, out)
	}
	return code, stderr
}

func (x *staleFixture) mustReply(t *testing.T, args ...string) {
	t.Helper()
	if code, stderr := x.reply(t, args...); code != ExitOK {
		t.Fatalf("%v: exit=%d %s", args, code, stderr)
	}
}

func (x *staleFixture) archiveRun(t *testing.T) categoryArchiveReport {
	t.Helper()
	out, stderr, code := x.runAgents(t, "--format", "json", "archive", "--categories", "--dry-run=false", "--confirm")
	if code != ExitOK {
		t.Fatalf("archive --categories: exit=%d stderr=%s stdout=%s", code, stderr, out)
	}
	var doc struct {
		Data categoryArchiveReport `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("archive output: %v\n%s", err, out)
	}
	return doc.Data
}

func staleListed(report staleReport, path string) (staleGroup, staleEntry, bool) {
	for _, group := range report.Groups {
		for _, entry := range group.Entries {
			if entry.Path == path {
				return group, entry, true
			}
		}
	}
	return staleGroup{}, staleEntry{}, false
}

func staleReleasedEntry(report staleReport, path string) (staleReleased, bool) {
	for _, released := range report.Released {
		if released.Path == path {
			return released, true
		}
	}
	return staleReleased{}, false
}

func replyCount(t *testing.T, x *staleFixture) int {
	t.Helper()
	replies, err := store.ReadReportReplies(context.Background(), x.paths(t).DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	return len(replies)
}

// An item no registration or producer evidence attributes is reported to
// the coordinator under an explicit unknown group and is never suggested for
// archiving, even when it would pass every archive check; an attributed item
// is routed to its own role only.
func TestStaleReportRoutesUnknownOwnerToCoordinatorAndNeverSuggestsArchive(t *testing.T) {
	x := newStaleFixture(t)
	owned := x.scratch(t, "owned", map[string]string{"README.md": "owned\n"})
	dirty := x.clone(t, "dirty-owned")
	if err := os.WriteFile(filepath.Join(dirty, "tracked"), []byte("uncommitted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{x.source, owned, dirty} {
		backdate(t, path, categoryIdleAge)
	}
	x.job(t, "job-owned", "succeeded", "seat-a", owned)
	x.job(t, "job-dirty", "failed", "seat-a", dirty)

	report := x.stale(t)
	group, unknown, ok := staleListed(report, x.source)
	if !ok || group.Owner != config.UnknownOwner || group.AddressedTo != "coordinator" || unknown.Owner != config.UnknownOwner {
		t.Fatalf("unknown-owner item not routed to the coordinator: %+v %+v", group, unknown)
	}
	if unknown.SuggestedAction != staleSuggestAsk || unknown.Git != staleGitNotGit || unknown.SizeMeasure != "deep" || unknown.SizeBytes <= 0 {
		t.Fatalf("unknown-owner item = %+v, want ask, not_git, deep size", unknown)
	}
	group, ownedEntry, ok := staleListed(report, owned)
	if !ok || group.Owner != "seat-a" || group.AddressedTo != "seat-a" || ownedEntry.Owner != "seat-a" || len(ownedEntry.OwnerEvidence) == 0 {
		t.Fatalf("owned item not routed to seat-a: %+v %+v", group, ownedEntry)
	}
	if _, dirtyEntry, ok := staleListed(report, dirty); !ok || dirtyEntry.Git != staleGitDirty || dirtyEntry.SuggestedAction != staleSuggestKeep {
		t.Fatalf("dirty owned clone = %+v, want git dirty and keep", dirtyEntry)
	}
	if last := report.Groups[len(report.Groups)-1]; last.Owner != config.UnknownOwner {
		t.Fatalf("unknown group is not last: %+v", report.Groups)
	}

	coordinator := x.stale(t, "--role", "coordinator")
	if _, _, ok := staleListed(coordinator, x.source); !ok || len(coordinator.Groups) != 1 {
		t.Fatalf("coordinator view = %+v", coordinator.Groups)
	}
	seat := x.stale(t, "--role", "seat-a")
	if _, _, ok := staleListed(seat, x.source); ok {
		t.Fatalf("seat-a received the unknown-owner item: %+v", seat.Groups)
	}
	text, stderr, code := x.runAgents(t, "report", "stale", "--role", "coordinator", "--format", "text")
	if code != ExitOK || !strings.Contains(text, x.source) || !strings.Contains(text, "Owner unknown") ||
		!strings.Contains(text, "janitor report release <path>... --role coordinator") || strings.Contains(text, owned) {
		t.Fatalf("coordinator message: exit=%d %s\n%s", code, stderr, text)
	}
}

// Each report candidate is measured on its own deep-size budget. A large
// first item must not leave a small idle sibling unmeasured (live 2026-10-28:
// 94 /root items unmeasured because the whole root shared one budget).
func TestStaleReportDeepBudgetIsPerItem(t *testing.T) {
	x := newStaleFixture(t)
	x.limits = "  deep_size_max_entries: 40\n"
	x.write(t)
	big := filepath.Join(x.work, "a-big")
	deep := filepath.Join(big, "d1", "d2", "d3", "d4", "d5", "d6")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range 50 {
		if err := os.WriteFile(filepath.Join(deep, fmt.Sprintf("f%02d", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{big, x.source} {
		backdate(t, path, categoryIdleAge)
	}
	report := x.stale(t)
	if _, entry, ok := staleListed(report, x.source); !ok || entry.SizeMeasure != "deep" {
		t.Fatalf("a small idle sibling after a large item was not measured on its own budget: listed=%v %+v unmeasured=%+v", ok, entry, report.Unmeasured)
	}
	found := false
	for _, item := range report.Unmeasured {
		found = found || item.Path == big
	}
	if !found {
		t.Fatalf("an item whose own walk exceeds the bound is not reported unmeasured: %+v", report.Unmeasured)
	}
}

// The suggestion itself: the same clean, idle, measured item is suggested
// for archiving when an owner is known and only asked about when not.
func TestStaleSuggestionNeverArchivesUnknownOwner(t *testing.T) {
	policy := config.Policy{Report: config.StaleReport{Roots: []string{"/srv/work"}, Idle: config.DefaultStaleReportIdle, MaxBytesPerItem: 1 << 30}}
	now := time.Now().UTC()
	entry := core.Entry{Path: "/srv/work/scratch", Kind: core.EntryKindDirectory, SizeBytes: 4096, SizeIsDeep: true, LatestModifiedAt: now.Add(-categoryIdleAge)}
	if action, reasons := staleSuggestion(policy, entry, core.Verdict{}, "seat-a", staleGitNotGit, "", now); action != staleSuggestArchive {
		t.Fatalf("owned clean item suggested %s: %v", action, reasons)
	}
	action, reasons := staleSuggestion(policy, entry, core.Verdict{}, config.UnknownOwner, staleGitNotGit, "", now)
	if action != staleSuggestAsk || len(reasons) == 0 || !strings.Contains(reasons[0], "owner unknown") {
		t.Fatalf("unknown-owner item suggested %s: %v", action, reasons)
	}
	entry.SizeIsLowerBound = true
	if action, _ := staleSuggestion(policy, entry, core.Verdict{}, "seat-a", staleGitNotGit, "", now); action == staleSuggestArchive {
		t.Fatal("an item measured only as a lower bound was suggested for archiving")
	}
}

// In-use items (live process, registered agent, nonterminal Gitmoot work)
// and recently changed items are never listed, and cannot be replied to.
func TestStaleReportExcludesInUseAndRecentlyChanged(t *testing.T) {
	x := newStaleFixture(t)
	idle := map[string]string{"README.md": "idle\n"}
	live := x.scratch(t, "live", idle)
	registered := x.scratch(t, "registered", idle)
	running := x.scratch(t, "running", idle)
	for _, path := range []string{x.source, live, registered, running} {
		backdate(t, path, categoryIdleAge)
	}
	recent := x.scratch(t, "recent", idle)
	backdate(t, recent, 3*24*time.Hour)
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
	x.job(t, "job-running", "running", "seat-a", running)

	report := x.stale(t)
	if _, _, ok := staleListed(report, x.source); !ok {
		t.Fatalf("idle unused item missing: %+v", report.Groups)
	}
	for _, path := range []string{live, registered, running, recent} {
		if _, entry, ok := staleListed(report, path); ok {
			t.Errorf("%s listed although in use or recently changed: %+v", path, entry)
		}
	}
	if report.Counts.InUse != 3 || report.Counts.Recent != 1 || report.Counts.Listed != 1 {
		t.Fatalf("counts = %+v, want 3 in use, 1 recent, 1 listed", report.Counts)
	}
	for path, fragment := range map[string]string{live: "in use", running: "in use", recent: "changed"} {
		code, stderr := x.reply(t, "release", path, "--role", "coordinator")
		if code == ExitOK || !strings.Contains(stderr, "not a current stale report entry") || !strings.Contains(stderr, fragment) {
			t.Errorf("release of %s: exit=%d %s", path, code, stderr)
		}
	}
	if n := replyCount(t, x); n != 0 {
		t.Fatalf("%d replies recorded for refused releases", n)
	}
}

// Only the owner (or the coordinator, for an unknown owner) may reply; with
// the default release_action none a release is only recorded and listed.
func TestStaleReportReleaseByNonOwnerIsRefused(t *testing.T) {
	x := newStaleFixture(t)
	owned := x.scratch(t, "owned", map[string]string{"README.md": "owned\n"})
	for _, path := range []string{x.source, owned} {
		backdate(t, path, categoryIdleAge)
	}
	x.job(t, "job-owned", "succeeded", "seat-a", owned)
	for _, tc := range []struct{ path, role, fragment string }{
		{owned, "seat-b", "owned by seat-a"},
		{owned, "coordinator", "owned by seat-a"},
		{x.source, "seat-a", "only the coordinator role coordinator"},
	} {
		code, stderr := x.reply(t, "release", tc.path, "--role", tc.role)
		if code == ExitOK || !strings.Contains(stderr, tc.fragment) {
			t.Errorf("release of %s by %s: exit=%d %s", tc.path, tc.role, code, stderr)
		}
	}
	if code, stderr := x.reply(t, "keep", owned, "--role", "seat-b"); code == ExitOK || !strings.Contains(stderr, "owned by seat-a") {
		t.Errorf("keep by a non-owner: exit=%d %s", code, stderr)
	}
	if n := replyCount(t, x); n != 0 {
		t.Fatalf("%d replies recorded by non-owners", n)
	}
	x.mustReply(t, "release", owned, "--role", "seat-a", "--note", "done with it")
	x.mustReply(t, "release", x.source, "--role", "coordinator")
	report := x.stale(t)
	for _, path := range []string{owned, x.source} {
		released, ok := staleReleasedEntry(report, path)
		if !ok || released.Status != "recorded" {
			t.Fatalf("%s release = %+v, want recorded", path, released)
		}
		if _, _, listed := staleListed(report, path); listed {
			t.Fatalf("released %s is still listed for a reply", path)
		}
	}
	// release_action none: nothing archives a release, now or in the cycle.
	if out, stderr, code := x.runAgents(t, "archive", "--categories", "--dry-run=false", "--confirm"); code == ExitOK {
		t.Fatalf("archive --categories ran with release_action none: %s %s", out, stderr)
	}
	if out, stderr, code := x.runAgents(t, "cycle"); code != ExitOK || strings.Contains(out, `"category_archives":{`) {
		t.Fatalf("cycle with release_action none: exit=%d %s %s", code, out, stderr)
	}
	if entries, err := os.ReadDir(x.archive); err != nil || len(entries) != 0 {
		t.Fatalf("release_action none wrote %d archive entries: %v", len(entries), err)
	}
	for _, path := range []string{owned, x.source} {
		x.preservedAt(t, path)
	}
}

// preservedAt checks that path still exists as a directory.
func (x *staleFixture) preservedAt(t *testing.T, path string) {
	t.Helper()
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		t.Fatalf("%s was removed or replaced: %v", path, err)
	}
}

// A release snapshots the item: once it changes, the release is void, so the
// archive step refuses it even when it is idle again, and the report asks
// again.
func TestStaleReportReleaseThenChangeDoesNotArchive(t *testing.T) {
	x := newStaleFixture(t)
	x.releaseAction = "archive"
	x.write(t)
	backdate(t, x.source, categoryIdleAge)
	x.mustReply(t, "release", x.source, "--role", "coordinator")
	if err := os.WriteFile(filepath.Join(x.source, "README.md"), []byte("edited after the release\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Idle again, but not the tree the coordinator released.
	backdate(t, x.source, 45*24*time.Hour)

	item := categoryItem(t, x.archiveRun(t), x.source)
	if item.Status != categoryRefused || !strings.Contains(strings.Join(item.Reasons, "\n"), "void") {
		t.Fatalf("changed released item = %+v, want refused as void", item)
	}
	if entries, err := os.ReadDir(x.archive); err != nil || len(entries) != 0 {
		t.Fatalf("a void release was archived: %d entries, %v", len(entries), err)
	}
	report := x.stale(t)
	if _, entry, ok := staleListed(report, x.source); !ok || !strings.Contains(entry.PriorReply, "void") {
		t.Fatalf("changed released item not asked again: %+v", entry)
	}
	if _, ok := staleReleasedEntry(report, x.source); ok {
		t.Fatal("a void release is still reported as released")
	}
}

// With release_action archive, released items go through the verified
// category archive path, oldest first and at most max_items_per_cycle per
// run; the archived item is then proposed for quarantine by the ordinary
// plan. An unreleased item is never archived.
func TestStaleReportReleaseWithOptInArchivesWithinMaxPerCycle(t *testing.T) {
	x := newStaleFixture(t)
	x.releaseAction, x.reportMaxItems = "archive", 1
	x.write(t)
	second := x.scratch(t, "second", map[string]string{"README.md": "second\n"})
	unreleased := x.scratch(t, "unreleased", map[string]string{"README.md": "unreleased\n"})
	backdate(t, x.source, categoryIdleAge+24*time.Hour)
	backdate(t, second, categoryIdleAge)
	backdate(t, unreleased, categoryIdleAge)
	x.mustReply(t, "release", x.source, "--role", "coordinator")
	x.mustReply(t, "release", second, "--role", "coordinator")

	first := x.archiveRun(t)
	archived := categoryItem(t, first, x.source)
	if archived.Status != categoryArchived || archived.Category != config.ReportReleaseCategory || !strings.HasPrefix(archived.Name, config.ReportReleaseCategory+"-") {
		t.Fatalf("oldest released item = %+v, want archived under %s", archived, config.ReportReleaseCategory)
	}
	if item := categoryItem(t, first, second); item.Status != categoryDeferred {
		t.Fatalf("second released item = %+v, want deferred by max_items_per_cycle 1", item)
	}
	for _, item := range first.Items {
		if item.Path == unreleased {
			t.Fatalf("an unreleased item reached the archive step: %+v", item)
		}
	}
	if first.Archived != 1 || first.Deferred != 1 {
		t.Fatalf("first run archived=%d deferred=%d, want 1/1", first.Archived, first.Deferred)
	}
	records, err := store.ReadCategoryArchives(context.Background(), x.paths(t).DatabaseFile)
	if err != nil || len(records) != 1 || records[0].Category != config.ReportReleaseCategory || !strings.HasPrefix(records[0].Release, "coordinator@report-reply-") {
		t.Fatalf("release receipts = %+v, %v", records, err)
	}
	if released, ok := staleReleasedEntry(x.stale(t), x.source); !ok || released.Status != "archived" || released.Archive != archived.Name {
		t.Fatalf("archived release reported as %+v", released)
	}
	if _, action := x.action(t, x.source); action.Kind != core.ActionQuarantine {
		t.Fatalf("archived released item proposed %s, want quarantine (local_retention none)", action.Kind)
	}

	again := x.archiveRun(t)
	if item := categoryItem(t, again, second); item.Status != categoryArchived {
		t.Fatalf("deferred release not archived on the next run: %+v", item)
	}
	if item := categoryItem(t, again, x.source); item.Status != categoryAlreadyArchived {
		t.Fatalf("archived release re-archived: %+v", item)
	}
	x.preservedAt(t, unreleased)
}

// A keep reply leaves the item out of reports until its date or until the
// item changes, whichever comes first.
func TestStaleReportKeepSuppressesUntilExpiry(t *testing.T) {
	x := newStaleFixture(t)
	other := x.scratch(t, "other", map[string]string{"README.md": "other\n"})
	backdate(t, x.source, categoryIdleAge)
	backdate(t, other, categoryIdleAge)
	until := time.Now().UTC().Add(30 * 24 * time.Hour).Format("2006-01-02")
	x.mustReply(t, "keep", x.source, "--role", "coordinator", "--until", until, "--note", "owner asked")
	x.mustReply(t, "keep", other, "--role", "coordinator")

	report := x.stale(t)
	for _, path := range []string{x.source, other} {
		if _, _, ok := staleListed(report, path); ok {
			t.Fatalf("kept %s still listed", path)
		}
	}
	if report.Counts.Kept != 2 || len(report.Kept) != 2 {
		t.Fatalf("kept = %+v", report.Kept)
	}

	// The same keep, expired: the item is asked about again.
	ctx := context.Background()
	replies, err := store.ReadReportReplies(ctx, x.paths(t).DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	var expired store.ReportReply
	for _, reply := range replies {
		if reply.Path == x.source {
			expired = reply
		}
	}
	past := time.Now().UTC().Add(-time.Hour)
	expired.Until, expired.RecordedAt = &past, time.Now().UTC()
	db, err := store.Open(ctx, x.paths(t).DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.RecordReportReply(ctx, expired)
		return err
	})
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	// And the open-ended keep, after a change.
	if err := os.WriteFile(filepath.Join(other, "README.md"), []byte("changed after keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	backdate(t, other, 40*24*time.Hour)

	report = x.stale(t)
	if _, entry, ok := staleListed(report, x.source); !ok || !strings.Contains(entry.PriorReply, "expired") {
		t.Fatalf("expired keep still suppresses: %+v", entry)
	}
	if _, entry, ok := staleListed(report, other); !ok || !strings.Contains(entry.PriorReply, "void") {
		t.Fatalf("keep survived a change: %+v", entry)
	}
	if code, stderr := x.reply(t, "keep", other, "--role", "coordinator", "--until", "2001-01-01"); code != ExitUsage || !strings.Contains(stderr, "not in the future") {
		t.Fatalf("keep with a past date: exit=%d %s", code, stderr)
	}
}

// Live-use evidence follows the quarantine/expiry recheck rules: a skipped
// process collector or a partial Gitmoot collector makes the whole report
// incomplete, so no entry is suggested for archiving and every reply is
// refused, even for items that would otherwise pass.
func TestStaleReportIncompleteLiveUseEvidenceSuggestsNothingAndRefusesReplies(t *testing.T) {
	for _, tc := range []struct {
		name, collector string
		degrade         func(t *testing.T, x *staleFixture)
	}{
		{"processes skipped", "processes", func(t *testing.T, x *staleFixture) {
			if err := os.RemoveAll(x.proc); err != nil {
				t.Fatal(err)
			}
		}},
		{"gitmoot partial", "Gitmoot", func(t *testing.T, x *staleFixture) {
			// The cleanup ledger is gone, so collectGitmoot cannot mark any
			// path, while the job ledger still attributes an owner.
			db, err := sql.Open("sqlite", filepath.Join(x.gitmoot, "gitmoot.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(`DROP TABLE cleanup_obligations`); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newStaleFixture(t)
			owned := x.scratch(t, "owned", map[string]string{"README.md": "owned\n"})
			for _, path := range []string{x.source, owned} {
				backdate(t, path, categoryIdleAge)
			}
			x.job(t, "job-owned", "succeeded", "seat-a", owned)
			tc.degrade(t, x)

			report := x.stale(t)
			if !strings.Contains(report.InUseEvidence, "incomplete") || !strings.Contains(report.InUseEvidence, tc.collector) {
				t.Fatalf("in-use evidence = %q, want incomplete naming %s", report.InUseEvidence, tc.collector)
			}
			for _, path := range []string{x.source, owned} {
				_, entry, ok := staleListed(report, path)
				if !ok {
					t.Fatalf("%s missing: %+v", path, report.Groups)
				}
				if entry.SuggestedAction == staleSuggestArchive {
					t.Errorf("%s suggested for archiving on incomplete live-use evidence: %+v", path, entry)
				}
			}
			for _, reply := range [][]string{
				{"release", x.source, "--role", "coordinator"},
				{"keep", x.source, "--role", "coordinator"},
				{"release", owned, "--role", "seat-a"},
			} {
				code, stderr := x.reply(t, reply...)
				if code == ExitOK || !strings.Contains(stderr, "cannot be verified as not in use") {
					t.Errorf("%v accepted on incomplete evidence: exit=%d %s", reply, code, stderr)
				}
			}
			if n := replyCount(t, x); n != 0 {
				t.Fatalf("%d replies recorded on incomplete evidence", n)
			}
		})
	}
}

// A keep binds the owner who gave it, like a release: once the ledger
// attributes the item to a different owner, the keep no longer suppresses
// it and the new owner is asked.
func TestStaleReportKeepVoidedWhenOwnerChanges(t *testing.T) {
	x := newStaleFixture(t)
	backdate(t, x.source, categoryIdleAge)
	x.mustReply(t, "keep", x.source, "--role", "coordinator")
	if _, _, ok := staleListed(x.stale(t), x.source); ok {
		t.Fatal("kept item still listed")
	}
	x.job(t, "job-late", "succeeded", "seat-a", x.source)

	report := x.stale(t)
	group, entry, ok := staleListed(report, x.source)
	if !ok || group.Owner != "seat-a" || !strings.Contains(entry.PriorReply, "owner attribution changed from unknown to seat-a") {
		t.Fatalf("keep survived an owner change: %+v %+v", group, entry)
	}
	if report.Counts.Kept != 0 {
		t.Fatalf("kept count = %d after the owner changed", report.Counts.Kept)
	}
}

// replyDoc runs a reply and decodes its document; it fails unless the call
// succeeded.
func (x *staleFixture) replyDoc(t *testing.T, args ...string) (staleReplyReport, string) {
	t.Helper()
	out, stderr, code := x.runAgents(t, append([]string{"--format", "json", "report"}, args...)...)
	if code != ExitOK {
		t.Fatalf("%v: exit=%d %s", args, code, stderr)
	}
	var doc struct {
		Data staleReplyReport `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return doc.Data, out
}

// staleParityFixture has one entry for each way the full report lists or
// excludes an item: unknown owner, owned by seat-a, in use by a process,
// changed recently, and unmeasured because its own deep walk exceeds the
// bound.
func staleParityFixture(t *testing.T) (x *staleFixture, owned, live, recent, big string) {
	t.Helper()
	x = newStaleFixture(t)
	x.limits = "  deep_size_max_entries: 40\n"
	x.write(t)
	idle := map[string]string{"README.md": "idle\n"}
	owned = x.scratch(t, "owned", idle)
	live = x.scratch(t, "live", idle)
	big = filepath.Join(x.work, "a-big")
	deep := filepath.Join(big, "d1", "d2", "d3")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range 60 {
		if err := os.WriteFile(filepath.Join(deep, fmt.Sprintf("f%02d", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{x.source, owned, live, big} {
		backdate(t, path, categoryIdleAge)
	}
	recent = x.scratch(t, "recent", idle)
	backdate(t, recent, 3*24*time.Hour)
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
	x.job(t, "job-owned", "succeeded", "seat-a", owned)
	return x, owned, live, recent, big
}

// A reply observes only its own entry, yet it is accepted or refused exactly
// when the full report says that role may reply for that path: listed with
// that owner (or unknown, for the coordinator), and not in use, changed
// recently or unmeasured.
func TestStaleReportReplyMatchesFullReport(t *testing.T) {
	x, owned, live, recent, big := staleParityFixture(t)
	full := x.stale(t)
	unmeasured := false
	for _, item := range full.Unmeasured {
		unmeasured = unmeasured || item.Path == big
	}
	if !unmeasured {
		t.Fatalf("fixture: %s is not unmeasured in the full report: %+v", big, full.Unmeasured)
	}
	for _, tc := range []struct{ path, role, refusal string }{
		{x.source, "seat-a", "only the coordinator role"},
		{owned, "coordinator", "owned by seat-a"},
		{live, "coordinator", "in use"},
		{recent, "coordinator", "changed"},
		{big, "coordinator", "newest modification"},
		{x.source, "coordinator", ""},
		{owned, "seat-a", ""},
	} {
		group, _, listed := staleListed(full, tc.path)
		want := listed && (group.Owner == tc.role || group.Owner == config.UnknownOwner && tc.role == "coordinator")
		if want != (tc.refusal == "") {
			t.Fatalf("fixture: full report says replyable=%v for %s by %s", want, tc.path, tc.role)
		}
		code, stderr := x.reply(t, "keep", tc.path, "--role", tc.role)
		if got := code == ExitOK; got != want {
			t.Errorf("keep %s by %s: accepted=%v, full report says %v: %s", tc.path, tc.role, got, want, stderr)
		}
		if !want && !strings.Contains(stderr, tc.refusal) {
			t.Errorf("keep %s by %s refused without %q: %s", tc.path, tc.role, tc.refusal, stderr)
		}
	}
	if n := replyCount(t, x); n != 2 {
		t.Fatalf("%d replies recorded, want the 2 accepted ones", n)
	}
}

// Several paths are validated together against one observation: one refused
// path records nothing; when all are valid each gets its own reply.
func TestStaleReportMultiPathReplyIsAllOrNothing(t *testing.T) {
	x, owned, live, _, _ := staleParityFixture(t)
	other := x.scratch(t, "other", map[string]string{"README.md": "other\n"})
	backdate(t, other, categoryIdleAge)
	for _, args := range [][]string{
		{"keep", x.source, owned, "--role", "coordinator"},
		{"release", x.source, "--role", "coordinator", live},
		{"keep", x.source, other, filepath.Join(x.home, "elsewhere"), "--role", "coordinator"},
	} {
		code, stderr := x.reply(t, args...)
		if code == ExitOK || !strings.Contains(stderr, "no reply was recorded") {
			t.Errorf("%v: exit=%d %s", args, code, stderr)
		}
	}
	if code, stderr := x.reply(t, "keep", x.source, x.source, "--role", "coordinator"); code != ExitUsage || !strings.Contains(stderr, "more than once") {
		t.Errorf("duplicate path: exit=%d %s", code, stderr)
	}
	if n := replyCount(t, x); n != 0 {
		t.Fatalf("%d replies recorded by refused multi-path calls", n)
	}

	doc, _ := x.replyDoc(t, "keep", x.source, "--role", "coordinator", other, "--note", "both kept")
	if len(doc.Replies) != 2 || doc.Replies[0].Path != x.source || doc.Replies[1].Path != other ||
		doc.Replies[0].Sequence == doc.Replies[1].Sequence || doc.Replies[1].Note != "both kept" {
		t.Fatalf("multi-path replies = %+v", doc.Replies)
	}
	if n := replyCount(t, x); n != 2 {
		t.Fatalf("%d effective replies, want one per path", n)
	}
	report := x.stale(t)
	if report.Counts.Kept != 2 {
		t.Fatalf("kept = %+v, want both paths kept", report.Kept)
	}
}

// A reply's observation covers only the replied entry: a large sibling whose
// own deep walk exceeds deep_size_max_entries (unmeasured in the full report)
// is neither walked nor mentioned, and does not affect the reply.
func TestStaleReportReplyObservesOnlyRepliedEntries(t *testing.T) {
	x, _, _, _, big := staleParityFixture(t)
	doc, out := x.replyDoc(t, "keep", x.source, "--role", "coordinator")
	if len(doc.Observation.Entries) != 1 || doc.Observation.Entries[0] != x.source {
		t.Fatalf("reply observed %v, want only %s", doc.Observation.Entries, x.source)
	}
	deepSized := false
	for _, collector := range doc.Observation.Collectors {
		if collector.Name == collect.CollectorDeepSize {
			deepSized = true
			if collector.Status != core.CollectorRan || strings.Contains(collector.Detail, "lower bound") {
				t.Fatalf("reply deep-size report shows another entry's walk: %+v", collector)
			}
		}
	}
	if !deepSized {
		t.Fatalf("reply did not deep-size its entry: %+v", doc.Observation.Collectors)
	}
	if strings.Contains(out, big) {
		t.Fatalf("reply output mentions the unreplied sibling %s:\n%s", big, out)
	}
}
