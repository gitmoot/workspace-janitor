//go:build linux

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cycleHistoryFixture(t *testing.T, safetyMinFree int64) (f *fixture, dbPath string, before int64) {
	t.Helper()
	f = newFixture(t)
	root := filepath.Join(f.home, "workspace")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	f.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\ncollectors:\n  git: false\n  processes: false\n  services: false\nprevention:\n  min_free_percent: 0\nsafety:\n  min_free_bytes: %d\n", root, safetyMinFree))
	dbPath = seedHistory(t, f, 40, 200, nil)
	execSQL(t, dbPath, "PRAGMA wal_checkpoint(TRUNCATE)")
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	return f, dbPath, info.Size()
}

func runHistoryCycle(t *testing.T, f *fixture) map[string]json.RawMessage {
	t.Helper()
	out, stderr, code := f.run(t, "cycle")
	if code != ExitOK {
		t.Fatalf("cycle: exit=%d %s %s", code, out, stderr)
	}
	var report map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("cycle report: %v: %s", err, out)
	}
	return report
}

// requireVacuumSkipped checks the cycle reported a skipped vacuum for reason
// and left the database file at least its previous size.
func requireVacuumSkipped(t *testing.T, report map[string]json.RawMessage, dbPath string, before int64, reason string) {
	t.Helper()
	var history struct {
		Space struct {
			Vacuumed bool   `json:"vacuumed"`
			Skipped  string `json:"skipped"`
		} `json:"space"`
	}
	if err := json.Unmarshal(report["history"], &history); err != nil {
		t.Fatalf("history report: %v: %s", err, report["history"])
	}
	if history.Space.Vacuumed || !strings.Contains(history.Space.Skipped, reason) {
		t.Fatalf("vacuum not skipped for %q: %s", reason, report["history"])
	}
	execSQL(t, dbPath, "PRAGMA wal_checkpoint(TRUNCATE)")
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() < before {
		t.Fatalf("skipped vacuum shrank the file: %d -> %d", before, info.Size())
	}
}

func TestCycleShrinksDatabaseAfterTrimmingHistory(t *testing.T) {
	f, dbPath, before := cycleHistoryFixture(t, 1<<20)
	report := runHistoryCycle(t, f)
	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > before/2 {
		t.Fatalf("database did not shrink: %d -> %d bytes; history %s", before, info.Size(), report["history"])
	}
}

func TestCycleKeepsDatabaseFileWithoutVacuumHeadroom(t *testing.T) {
	// No filesystem has an exbibyte free beyond the vacuum's own need.
	f, dbPath, before := cycleHistoryFixture(t, 1<<60)
	requireVacuumSkipped(t, runHistoryCycle(t, f), dbPath, before, "bytes free")
}

// A confirmed mutation journals its move only after the filesystem op; a
// vacuum holding SQLite's write lock past that write's wait would leave a
// moved file under a prepared receipt, so the vacuum yields to the apply lock.
func TestCycleSkipsVacuumWhileApplyLockHeld(t *testing.T) {
	f, dbPath, before := cycleHistoryFixture(t, 1<<20)
	unlock, err := lockApply(filepath.Dir(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	requireVacuumSkipped(t, runHistoryCycle(t, f), dbPath, before, "apply lock held")
}
