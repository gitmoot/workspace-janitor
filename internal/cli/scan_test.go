package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

// scanFixture is a fixture home plus a scannable workspace root. Process and
// service collection stay off unless a test enables them, so no test reads
// the machine's real process table or service definitions.
type scanFixture struct {
	*fixture
	root string
}

func newScanFixture(t *testing.T) *scanFixture {
	t.Helper()
	f := newFixture(t)
	root := filepath.Join(f.home, "workspace")
	if err := os.MkdirAll(filepath.Join(root, "project", "nested"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "project", "nested", "deep.txt"), []byte("deep"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "notes.md"), []byte("notes"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.writePolicy(t, strings.Join([]string{
		"roots:",
		"  - path: " + root,
		"    max_depth: 1",
		"collectors:",
		"  git: false",
		"  processes: false",
		"  services: false",
		"",
	}, "\n"))
	return &scanFixture{fixture: f, root: root}
}

func (f *scanFixture) scanJSON(t *testing.T, args ...string) scanDocument {
	t.Helper()
	stdout, stderr, code := f.run(t, append([]string{"--format", "json", "scan"}, args...)...)
	if code != ExitOK {
		t.Fatalf("scan exit = %d, stderr = %s", code, stderr)
	}
	var doc scanDocument
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("scan JSON is not valid: %v\n%s", err, stdout)
	}
	return doc
}

// scanDocument mirrors the published scan envelope.
type scanDocument struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	Data          struct {
		Scan      core.Scan    `json:"scan"`
		Persisted bool         `json:"persisted"`
		PriorScan string       `json:"prior_scan_id"`
		Protected int          `json:"protected_entries"`
		Unknowns  int          `json:"unknown_observations"`
		Entries   []core.Entry `json:"entries"`
	} `json:"data"`
}

func (d scanDocument) collector(name string) (core.CollectorReport, bool) {
	for _, report := range d.Data.Scan.Collectors {
		if report.Name == name {
			return report, true
		}
	}
	return core.CollectorReport{}, false
}

func (d scanDocument) paths() []string {
	paths := make([]string, 0, len(d.Data.Entries))
	for _, entry := range d.Data.Entries {
		paths = append(paths, entry.Path)
	}
	return paths
}

// The scan document must say which collectors ran, failed, or were skipped:
// a sparse inventory is otherwise indistinguishable from a clean machine.
func TestScanJSONExplainsEveryCollector(t *testing.T) {
	f := newScanFixture(t)
	doc := f.scanJSON(t)

	if doc.SchemaVersion != core.ContractVersion || doc.Kind != "scan" {
		t.Errorf("envelope = %+v", doc)
	}
	statuses := map[string]core.CollectorStatus{}
	for _, report := range doc.Data.Scan.Collectors {
		statuses[report.Name] = report.Status
	}
	for _, name := range []string{"filesystem", "deep_size", "git", "processes", "agents", "services"} {
		status, ok := statuses[name]
		if !ok {
			t.Errorf("collector %q missing from the scan document: %v", name, statuses)
			continue
		}
		if !status.Valid() {
			t.Errorf("collector %q has invalid status %q", name, status)
		}
	}
	for _, name := range []string{"git", "processes", "services"} {
		report, _ := doc.collector(name)
		if report.Status != core.CollectorSkipped || report.Detail == "" {
			t.Errorf("collector %q = %+v, want skipped with a reason", name, report)
		}
	}
	if doc.Data.Scan.Status != core.ScanCompleted || doc.Data.Scan.FinishedAt == nil {
		t.Errorf("scan = %+v, want a completed scan", doc.Data.Scan)
	}
}

// A default scan is a top-level pass: no recursive reads, no deep sizes.
func TestScanIsTopLevelByDefaultAndDeepSizeIsOptIn(t *testing.T) {
	f := newScanFixture(t)

	doc := f.scanJSON(t)
	wantPaths := []string{filepath.Join(f.root, "notes.md"), filepath.Join(f.root, "project")}
	if got := doc.paths(); len(got) != len(wantPaths) || got[0] != wantPaths[0] || got[1] != wantPaths[1] {
		t.Fatalf("entries = %v, want the top level only %v", got, wantPaths)
	}
	fs, _ := doc.collector("filesystem")
	if fs.Visited != 2 {
		t.Errorf("filesystem visited %d paths, want 2", fs.Visited)
	}
	for _, entry := range doc.Data.Entries {
		if entry.SizeIsDeep {
			t.Errorf("%s reports a deep size in a default scan", entry.Path)
		}
		if entry.Fingerprint == "" {
			t.Errorf("%s has no fingerprint", entry.Path)
		}
	}

	deep := f.scanJSON(t, "--deep-size")
	report, _ := deep.collector("deep_size")
	if report.Status == core.CollectorSkipped {
		t.Errorf("deep size report = %+v, want it to run when requested", report)
	}
	for _, entry := range deep.Data.Entries {
		if entry.Kind == core.EntryKindDirectory && !entry.SizeIsDeep {
			t.Errorf("%s has no deep size after --deep-size", entry.Path)
		}
	}
}

func TestScanPersistsInventoryAndComparesWithPriorScan(t *testing.T) {
	f := newScanFixture(t)
	first := f.scanJSON(t)
	if !first.Data.Persisted {
		t.Fatal("scan did not persist its inventory")
	}

	second := f.scanJSON(t)
	if second.Data.PriorScan != first.Data.Scan.ID {
		t.Errorf("prior scan = %q, want %q", second.Data.PriorScan, first.Data.Scan.ID)
	}
	unchanged := 0
	for _, entry := range second.Data.Entries {
		for _, evidence := range entry.Evidence {
			if evidence.Signal == "unchanged_since_prior_scan" {
				unchanged++
			}
		}
	}
	if unchanged != len(second.Data.Entries) {
		t.Errorf("%d of %d entries compared as unchanged", unchanged, len(second.Data.Entries))
	}

	// The stored scan must carry the same collector reports and entries.
	ctx := context.Background()
	db, err := store.OpenExisting(ctx, filepath.Join(f.home, ".local", "state", "workspace-janitor", "janitor.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	if err := db.Read(ctx, func(tx *store.Tx) error {
		stored, err := tx.Scan(ctx, second.Data.Scan.ID)
		if err != nil {
			return err
		}
		if len(stored.Collectors) != len(second.Data.Scan.Collectors) {
			t.Errorf("stored collector reports = %d, want %d", len(stored.Collectors), len(second.Data.Scan.Collectors))
		}
		entries, err := tx.Entries(ctx, second.Data.Scan.ID)
		if err != nil {
			return err
		}
		if len(entries) != len(second.Data.Entries) {
			t.Fatalf("stored entries = %d, want %d", len(entries), len(second.Data.Entries))
		}
		for i, entry := range entries {
			if entry.Fingerprint != second.Data.Entries[i].Fingerprint {
				t.Errorf("%s stored fingerprint = %q, want %q", entry.Path, entry.Fingerprint, second.Data.Entries[i].Fingerprint)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("read store: %v", err)
	}
}

func TestScanNoStoreLeavesDatabaseUntouched(t *testing.T) {
	f := newScanFixture(t)
	doc := f.scanJSON(t, "--no-store")
	if doc.Data.Persisted {
		t.Error("--no-store still persisted the scan")
	}

	ctx := context.Background()
	db, err := store.OpenExisting(ctx, filepath.Join(f.home, ".local", "state", "workspace-janitor", "janitor.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()
	stats, err := db.Stats(ctx)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Scans != 0 || stats.InventoryEntries != 0 {
		t.Errorf("stats = %+v, want no stored scan", stats)
	}
}

func TestScanRootArgumentsInheritPolicyBounds(t *testing.T) {
	f := newScanFixture(t)
	project := filepath.Join(f.root, "project")

	doc := f.scanJSON(t, project)
	if got := doc.paths(); len(got) != 1 || got[0] != filepath.Join(project, "nested") {
		t.Fatalf("entries = %v, want the requested root's children", got)
	}
	if len(doc.Data.Scan.Roots) != 1 || doc.Data.Scan.Roots[0] != project {
		t.Errorf("scan roots = %v, want %q", doc.Data.Scan.Roots, project)
	}

	_, stderr, code := f.run(t, "scan", "relative/path")
	if code != ExitUsage {
		t.Errorf("relative root exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "absolute") {
		t.Errorf("stderr = %q, want an absolute-path complaint", stderr)
	}
}

func TestScanTextOutputListsCollectorsAndEntries(t *testing.T) {
	f := newScanFixture(t)
	stdout, stderr, code := f.run(t, "scan")
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{"Collectors:", "Entries:", "filesystem", "skipped", filepath.Join(f.root, "notes.md")} {
		if !strings.Contains(stdout, want) {
			t.Errorf("scan output does not contain %q:\n%s", want, stdout)
		}
	}
}

// A symlink whose target the policy does not permit resolving is ambiguous,
// so the scan must present it as protected.
func TestScanReportsProtectionsForAmbiguousEntries(t *testing.T) {
	f := newScanFixture(t)
	link := filepath.Join(f.root, "link")
	if err := os.Symlink(filepath.Join(f.root, "project"), link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	doc := f.scanJSON(t)
	if doc.Data.Protected < 1 {
		t.Fatalf("protected entries = %d, want the unresolved symlink counted", doc.Data.Protected)
	}
	if doc.Data.Unknowns < 1 {
		t.Errorf("unknown observations = %d, want the unresolved target counted", doc.Data.Unknowns)
	}
	for _, entry := range doc.Data.Entries {
		if entry.Path != link {
			continue
		}
		if !entry.Protected() {
			t.Errorf("symlink entry is not protected: %+v", entry.Protections)
		}
		return
	}
	t.Fatalf("no entry for %s", link)
}

func TestScanFailsOnInvalidPolicy(t *testing.T) {
	f := newScanFixture(t)
	f.writePolicy(t, "roots:\n  - path: relative\n")
	_, stderr, code := f.run(t, "scan")
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "invalid configuration") {
		t.Errorf("stderr = %q", stderr)
	}
}
