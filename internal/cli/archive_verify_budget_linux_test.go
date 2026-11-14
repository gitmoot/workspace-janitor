//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
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

// Live 2026-11-14 (#211): the nightly cycle re-verified a 1.5 GB category
// archive over sshfs before quarantining it, inside the 48 s a 60 s
// limits.command_timeout left the workspace archive collector. The read ran
// out, the item was refused as if its archive were corrupt, the cycle exited
// 1 and its receipt stayed prepared. These fixtures scale that down: a 3 s
// command timeout leaves binding 1.5 s, and a bind made slow by the seam
// stands in for the long read.

const slowVerification = 2500 * time.Millisecond

// newVerifyBudgetFixture archives the released directory as a local_retention
// none category item under a 3 s command timeout, with automatic quarantine
// and the given extra limits lines.
func newVerifyBudgetFixture(t *testing.T, limits string) *categoryFixture {
	t.Helper()
	x := newCategoryFixture(t)
	x.prevention = "  auto_quarantine: true\n"
	x.limits = limits
	x.write(t)
	policyFile := filepath.Join(x.home, ".config", config.AppName, "policy.yaml")
	raw, err := os.ReadFile(policyFile)
	if err != nil {
		t.Fatal(err)
	}
	x.writePolicy(t, strings.Replace(string(raw), "command_timeout: 30s", "command_timeout: 3s", 1))
	backdate(t, x.source, categoryIdleAge)
	if item := categoryItem(t, x.categories(t, false), x.source); item.Status != categoryArchived {
		t.Fatalf("released directory not archived: %+v", item)
	}
	return x
}

// slowBinds makes every archive bind for which slow reports true take d.
func slowBinds(t *testing.T, d time.Duration, slow func() bool) {
	t.Helper()
	collect.BeforeWorkspaceArchiveBind = func() {
		if slow() {
			time.Sleep(d)
		}
	}
	t.Cleanup(func() { collect.BeforeWorkspaceArchiveBind = nil })
}

// revalidating reports whether a quarantine of the source is under way: a
// receipt directory exists and the source has not moved yet. The scan's
// binds come before any receipt and are not slowed.
func (x *categoryFixture) revalidating(t *testing.T) func() bool {
	quarantine := x.paths(t).QuarantineDir
	return func() bool {
		receipts, _ := os.ReadDir(quarantine)
		_, err := os.Lstat(x.source)
		return err == nil && len(receipts) != 0
	}
}

func (x *categoryFixture) cycle(t *testing.T) (cycleReport, string, ExitCode) {
	t.Helper()
	out, stderr, code := x.runAgents(t, "cycle")
	var report cycleReport
	if line := strings.TrimSpace(out); line != "" {
		if err := json.Unmarshal([]byte(line[strings.LastIndex(line, "\n")+1:]), &report); err != nil {
			t.Fatalf("cycle output: %v\n%s\n%s", err, out, stderr)
		}
	}
	return report, out + stderr, code
}

// sourceReceipts lists every cleanup receipt of the released directory.
func (x *categoryFixture) sourceReceipts(t *testing.T) []core.CleanupItem {
	t.Helper()
	var found []core.CleanupItem
	for _, item := range x.items(t) {
		if item.Source == x.source {
			found = append(found, item)
		}
	}
	return found
}

// items lists every cleanup receipt in creation order.
func (x *categoryFixture) items(t *testing.T) []core.CleanupItem {
	t.Helper()
	db, err := store.OpenExisting(context.Background(), x.paths(t).DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var items []core.CleanupItem
	err = db.Read(context.Background(), func(tx *store.Tx) error {
		var err error
		items, err = tx.CleanupItems(context.Background(), "")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return items
}

// A full verification that needs longer than the collector's binding budget
// but fits limits.archive_verify_timeout (default 30m) is completed and the
// item moves.
func TestCycleVerifiesAnArchiveBeyondTheCollectorBudget(t *testing.T) {
	x := newVerifyBudgetFixture(t, "")
	slowBinds(t, slowVerification, x.revalidating(t))
	report, output, code := x.cycle(t)
	if code != ExitOK {
		t.Fatalf("cycle: exit=%d %s", code, output)
	}
	if report.Quarantine != "applied" {
		t.Fatalf("cycle report: %s", output)
	}
	if _, err := os.Lstat(x.source); !os.IsNotExist(err) {
		t.Fatalf("slow but complete verification did not quarantine the item: %v\n%s", err, output)
	}
	receipts := x.sourceReceipts(t)
	if len(receipts) != 1 || receipts[0].State != core.CleanupQuarantined {
		t.Fatalf("receipts = %+v", receipts)
	}
	x.preserved(t, receipts[0].Destination)
}

// A full verification that runs out of limits.archive_verify_timeout is
// deferred: the item stays where it was, the cycle succeeds, no receipt is
// left prepared, and the next cycle verifies and moves it.
func TestCycleDefersAQuarantineWhoseArchiveVerificationRunsOutOfBudget(t *testing.T) {
	x := newVerifyBudgetFixture(t, "  archive_verify_timeout: 1s\n")
	slowBinds(t, slowVerification, x.revalidating(t))
	report, output, code := x.cycle(t)
	if code != ExitOK {
		t.Fatalf("a deferred verification failed the cycle: exit=%d %s", code, output)
	}
	if !strings.Contains(report.QuarantineReport, "archive verification deferred: budget 1s exceeded; retried next cycle") ||
		strings.Contains(report.QuarantineReport, "does not bind") {
		t.Fatalf("quarantine report does not show the deferral: %s", output)
	}
	x.preserved(t, x.source)
	receipts := x.sourceReceipts(t)
	if len(receipts) != 1 || receipts[0].State != core.CleanupRestored ||
		!strings.Contains(receipts[0].Reason, "archive verification deferred") {
		t.Fatalf("deferral left receipts %+v", receipts)
	}
	if _, err := os.Lstat(receipts[0].Destination); !os.IsNotExist(err) {
		t.Fatalf("deferred item reached its receipt: %v", err)
	}

	collect.BeforeWorkspaceArchiveBind = nil
	if _, output, code := x.cycle(t); code != ExitOK {
		t.Fatalf("next cycle: exit=%d %s", code, output)
	}
	if _, err := os.Lstat(x.source); !os.IsNotExist(err) {
		t.Fatalf("next cycle did not retry the deferred item: %v", err)
	}
}

// #214: in a batch where one action was deferred and another quarantined,
// repeating the same plan's apply retries the deferred action under a fresh
// receipt and replays the quarantined one; it used to fail on the deferred
// action's closed (cleanup id, action id) receipt.
func TestSamePlanApplyRetriesADeferredActionBesideAQuarantinedOne(t *testing.T) {
	x := newVerifyBudgetFixture(t, "  archive_verify_timeout: 1s\n")
	second := x.scratch(t, "second", map[string]string{"notes.txt": "second\n"})
	backdate(t, second, categoryIdleAge)
	if item := categoryItem(t, x.categories(t, false), second); item.Status != categoryArchived {
		t.Fatalf("second directory not archived: %+v", item)
	}
	// Only the batch's first revalidation is slow: that action is deferred,
	// the other moves.
	quarantine := x.paths(t).QuarantineDir
	slowed := false
	slowBinds(t, slowVerification, func() bool {
		if receipts, _ := os.ReadDir(quarantine); len(receipts) == 0 || slowed {
			return false
		}
		slowed = true
		return true
	})
	if _, output, code := x.cycle(t); code != ExitOK {
		t.Fatalf("cycle: exit=%d %s", code, output)
	}
	collect.BeforeWorkspaceArchiveBind = nil
	states := func() map[string][]core.CleanupState {
		got := map[string][]core.CleanupState{}
		for _, item := range x.items(t) {
			got[item.Source] = append(got[item.Source], item.State)
		}
		return got
	}
	items := x.items(t)
	if len(items) != 2 || items[0].CleanupID != items[1].CleanupID {
		t.Fatalf("want one two-action batch, got %+v", states())
	}
	counts := map[core.CleanupState]int{}
	for _, item := range items {
		counts[item.State]++
	}
	if counts[core.CleanupRestored] != 1 || counts[core.CleanupQuarantined] != 1 {
		t.Fatalf("want one deferred and one quarantined action, got %+v", states())
	}
	for run := 1; run <= 2; run++ {
		if out, stderr, code := x.run(t, "apply", "--quarantine", "--plan", items[0].PlanID, "--dry-run=false", "--confirm"); code != ExitOK {
			t.Fatalf("same-plan apply %d: exit=%d %s %s", run, code, out, stderr)
		}
	}
	for _, path := range []string{x.source, second} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("%s not quarantined by the retry: %v (%+v)", path, err, states())
		}
	}
	for source, got := range states() {
		if got[len(got)-1] != core.CleanupQuarantined {
			t.Fatalf("%s receipts %v", source, got)
		}
	}
}

// An expiry whose full verification runs out of its budget is deferred too:
// the copy stays quarantined, not investigate, and the cycle succeeds.
func TestCycleDefersAnExpiryWhoseArchiveVerificationRunsOutOfBudget(t *testing.T) {
	x := newVerifyBudgetFixture(t, "  archive_verify_timeout: 1s\n")
	if _, output, code := x.cycle(t); code != ExitOK {
		t.Fatalf("quarantine cycle: exit=%d %s", code, output)
	}
	receipts := x.sourceReceipts(t)
	if len(receipts) != 1 || receipts[0].State != core.CleanupQuarantined {
		t.Fatalf("receipts = %+v", receipts)
	}
	x.prevention = "  auto_quarantine: true\n  auto_expire: true\n"
	x.write(t)
	// The source is gone, so the only binds left are expiry's.
	slowBinds(t, slowVerification, func() bool { return true })
	report, output, code := x.cycle(t)
	if code != ExitOK {
		t.Fatalf("a deferred expiry failed the cycle: exit=%d %s", code, output)
	}
	if !strings.Contains(report.ExpiryReport, "archive verification deferred") {
		t.Fatalf("expiry report does not show the deferral: %s", output)
	}
	receipts = x.sourceReceipts(t)
	if len(receipts) != 1 || receipts[0].State != core.CleanupQuarantined {
		t.Fatalf("deferred expiry left receipts %+v", receipts)
	}
	x.preserved(t, receipts[0].Destination)
}

// Guard: a genuine mismatch is still refused as one, never deferred.
func TestCycleStillRefusesAChangedArchive(t *testing.T) {
	x := newVerifyBudgetFixture(t, "")
	var tarPath string
	if err := filepath.WalkDir(x.archive, func(path string, entry fs.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(path, ".tar") {
			tarPath = path
		}
		return err
	}); err != nil || tarPath == "" {
		t.Fatalf("archive tar not found: %v", err)
	}
	data, err := os.ReadFile(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.Index(data, []byte("payload\n"))
	if at < 0 {
		t.Fatal("member content not found in the tar")
	}
	f, err := os.OpenFile(tarPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("P"), int64(at)); err != nil {
		t.Fatal(err)
	}
	f.Close()
	_, output, code := x.cycle(t)
	if code == ExitOK || !strings.Contains(output, "does not bind the local tree") || strings.Contains(output, "verification deferred") {
		t.Fatalf("changed archive not refused as a mismatch: exit=%d %s", code, output)
	}
	x.preserved(t, x.source)
}
