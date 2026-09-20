package collect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// fixedNow keeps observation timestamps deterministic in tests.
var fixedNow = time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)

// fixtureOptions builds bounded options over one fixture root. Every
// collector that would read real machine state is off by default: tests opt
// in explicitly and always against fixture paths.
func fixtureOptions(root string) Options {
	return Options{
		Roots: []RootSpec{{Path: root, MaxDepth: 1}},
		Limits: Limits{
			GitTimeout:         5 * time.Second,
			CommandTimeout:     5 * time.Second,
			MaxEntries:         1000,
			MaxDirEntries:      100,
			DeepSizeMaxEntries: 1000,
			DeepSizeMaxDepth:   8,
		},
		Now: func() time.Time { return fixedNow },
	}
}

func mustMkdir(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	return path
}

func mustWrite(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func mustSymlink(t *testing.T, target, link string) string {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink %s -> %s: %v", link, target, err)
	}
	return link
}

func run(t *testing.T, opts Options) Result {
	t.Helper()
	result, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return result
}

func entryFor(t *testing.T, result Result, path string) core.Entry {
	t.Helper()
	for _, entry := range result.Entries {
		if entry.Path == path {
			return entry
		}
	}
	t.Fatalf("no entry for %s; got %v", path, entryPaths(result))
	return core.Entry{}
}

func entryPaths(result Result) []string {
	paths := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		paths = append(paths, entry.Path)
	}
	return paths
}

func reportFor(t *testing.T, result Result, name string) core.CollectorReport {
	t.Helper()
	for _, report := range result.Reports {
		if report.Name == name {
			return report
		}
	}
	t.Fatalf("no report for collector %q", name)
	return core.CollectorReport{}
}

func hasProtection(entry core.Entry, kind core.ProtectionKind) bool {
	for _, protection := range entry.Protections {
		if protection.Kind == kind && protection.Blocking {
			return true
		}
	}
	return false
}

func hasSignal(entry core.Entry, signal string) bool {
	for _, evidence := range entry.Evidence {
		if evidence.Signal == signal {
			return true
		}
	}
	return false
}

// A default scan is a top-level metadata pass: it records the root's
// children, reads no file contents, and never descends recursively.
func TestFilesystemCollectorStaysTopLevelAndMetadataOnly(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "project"))
	mustWrite(t, filepath.Join(root, "project", "deep.txt"), "should not be visited")
	mustMkdir(t, filepath.Join(root, "project", "nested", "deeper"))
	mustWrite(t, filepath.Join(root, "notes.md"), "hello")

	result := run(t, fixtureOptions(root))

	wantPaths := []string{filepath.Join(root, "notes.md"), filepath.Join(root, "project")}
	got := entryPaths(result)
	if len(got) != len(wantPaths) {
		t.Fatalf("entries = %v, want exactly the top-level children %v", got, wantPaths)
	}
	for i, want := range wantPaths {
		if got[i] != want {
			t.Errorf("entries[%d] = %q, want %q", i, got[i], want)
		}
	}

	fs := reportFor(t, result, CollectorFilesystem)
	if fs.Status != core.CollectorRan {
		t.Errorf("filesystem status = %q (%s)", fs.Status, fs.Detail)
	}
	if fs.Visited != 2 {
		t.Errorf("filesystem visited %d paths, want 2: a top-level scan must not walk into subdirectories", fs.Visited)
	}

	project := entryFor(t, result, filepath.Join(root, "project"))
	if project.SizeIsDeep {
		t.Error("a default scan must not report a deep size")
	}
	if project.Kind != core.EntryKindDirectory || project.FilesystemID.Zero() {
		t.Errorf("project entry = %+v, want a directory with filesystem identity", project)
	}
	if deep := reportFor(t, result, CollectorDeepSize); deep.Status != core.CollectorSkipped {
		t.Errorf("deep size status = %q, want skipped by default", deep.Status)
	}
	notes := entryFor(t, result, filepath.Join(root, "notes.md"))
	if notes.Kind != core.EntryKindFile || notes.SizeBytes != int64(len("hello")) {
		t.Errorf("notes entry = %+v", notes)
	}
}

func TestMetadataWalkHonoursDepthAndEntryBounds(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "a", "b", "c"))

	opts := fixtureOptions(root)
	opts.Roots[0].MaxDepth = 2
	result := run(t, opts)
	if got := entryPaths(result); len(got) != 2 {
		t.Fatalf("entries = %v, want depth-2 entries only", got)
	}

	bounded := fixtureOptions(root)
	bounded.Roots[0].MaxDepth = 3
	bounded.Limits.MaxEntries = 2
	result = run(t, bounded)
	report := reportFor(t, result, CollectorFilesystem)
	if report.Status != core.CollectorPartial {
		t.Errorf("status = %q, want partial once the entry bound is hit", report.Status)
	}
	if !strings.Contains(report.Detail, "entry limit") {
		t.Errorf("detail = %q, want it to name the bound that stopped the walk", report.Detail)
	}
}

func TestDirectoryListingBoundIsReported(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a", "b", "c", "d"} {
		mustWrite(t, filepath.Join(root, name), name)
	}
	opts := fixtureOptions(root)
	opts.Limits.MaxDirEntries = 2

	result := run(t, opts)
	report := reportFor(t, result, CollectorFilesystem)
	if report.Status != core.CollectorPartial {
		t.Errorf("status = %q, want partial when a listing is truncated", report.Status)
	}
	if len(result.Entries) != 2 {
		t.Fatalf("entries = %v, want the listing bound honoured", entryPaths(result))
	}
	for _, entry := range result.Entries {
		if !hasSignal(entry, "unknown:directory_truncated") {
			t.Errorf("%s does not record that its sibling listing was truncated", entry.Path)
		}
	}
}

// Not following a symlink is the safe default, but it leaves the target
// unknown, so the entry must be protected rather than look clean.
func TestUnresolvedSymlinkIsProtected(t *testing.T) {
	root := t.TempDir()
	target := mustMkdir(t, filepath.Join(root, "real"))
	link := mustSymlink(t, target, filepath.Join(root, "link"))

	entry := entryFor(t, run(t, fixtureOptions(root)), link)
	if entry.Kind != core.EntryKindSymlink {
		t.Fatalf("kind = %q, want symlink", entry.Kind)
	}
	if entry.SymlinkTarget != target {
		t.Errorf("target = %q, want %q", entry.SymlinkTarget, target)
	}
	if entry.CanonicalPath != "" {
		t.Errorf("canonical path = %q, want empty: the link must not be resolved", entry.CanonicalPath)
	}
	if !hasProtection(entry, core.ProtectSymlinkEscape) {
		t.Errorf("unresolved symlink is not protected: %+v", entry.Protections)
	}
}

func TestSymlinkCycleIsProtectedWhenFollowingIsAllowed(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	mustSymlink(t, second, first)
	mustSymlink(t, first, second)

	opts := fixtureOptions(root)
	opts.Roots[0].FollowSymlinks = true
	result := run(t, opts)

	entry := entryFor(t, result, first)
	if !hasProtection(entry, core.ProtectSymlinkEscape) {
		t.Errorf("symlink cycle is not protected: %+v", entry.Protections)
	}
	if !hasSignal(entry, "unknown:symlink_unresolvable") {
		t.Errorf("symlink cycle is not recorded as unknown: %+v", entry.Evidence)
	}
	if report := reportFor(t, result, CollectorFilesystem); report.Status != core.CollectorPartial {
		t.Errorf("status = %q, want partial after an unresolvable link", report.Status)
	}
}

func TestSymlinkEscapingRootIsProtected(t *testing.T) {
	root := t.TempDir()
	outside := mustMkdir(t, filepath.Join(t.TempDir(), "elsewhere"))
	link := mustSymlink(t, outside, filepath.Join(root, "escape"))

	opts := fixtureOptions(root)
	opts.Roots[0].FollowSymlinks = true
	entry := entryFor(t, run(t, opts), link)

	if !hasProtection(entry, core.ProtectSymlinkEscape) {
		t.Errorf("escaping symlink is not protected: %+v", entry.Protections)
	}
	if !hasSignal(entry, "unknown:symlink_escapes_root") {
		t.Errorf("escape is not recorded: %+v", entry.Evidence)
	}
}

func TestSymlinkInsideRootResolvesCleanly(t *testing.T) {
	root := t.TempDir()
	target := mustMkdir(t, filepath.Join(root, "real"))
	link := mustSymlink(t, target, filepath.Join(root, "link"))

	opts := fixtureOptions(root)
	opts.Roots[0].FollowSymlinks = true
	entry := entryFor(t, run(t, opts), link)

	if entry.CanonicalPath != target {
		t.Errorf("canonical path = %q, want %q", entry.CanonicalPath, target)
	}
	if hasProtection(entry, core.ProtectSymlinkEscape) {
		t.Errorf("a link resolving inside its root must not be protected as ambiguous: %+v", entry.Protections)
	}
}

// A directory the scan cannot list hides whatever is inside it, so the
// parent must carry a blocking unknown instead of looking empty.
func TestUnreadableDirectoryFailsClosed(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: permission bits do not deny access")
	}
	root := t.TempDir()
	locked := mustMkdir(t, filepath.Join(root, "locked"))
	mustWrite(t, filepath.Join(locked, "secret.txt"), "hidden")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	opts := fixtureOptions(root)
	opts.Roots[0].MaxDepth = 2
	result := run(t, opts)

	entry := entryFor(t, result, locked)
	if !hasProtection(entry, core.ProtectCollectorFailure) {
		t.Errorf("unlistable directory is not protected: %+v", entry.Protections)
	}
	if !hasSignal(entry, "unknown:directory_not_listed") {
		t.Errorf("unlistable directory is not recorded as unknown: %+v", entry.Evidence)
	}
	if report := reportFor(t, result, CollectorFilesystem); report.Status != core.CollectorPartial {
		t.Errorf("status = %q, want partial", report.Status)
	}
}

func TestDeepSizeIsOptionalAndBounded(t *testing.T) {
	root := t.TempDir()
	project := mustMkdir(t, filepath.Join(root, "project"))
	mustWrite(t, filepath.Join(project, "one.bin"), strings.Repeat("x", 100))
	mustWrite(t, filepath.Join(project, "nested", "two.bin"), strings.Repeat("y", 250))

	opts := fixtureOptions(root)
	opts.DeepSize = true
	result := run(t, opts)

	entry := entryFor(t, result, project)
	if !entry.SizeIsDeep {
		t.Fatal("deep sizing must mark the size as recursive")
	}
	if entry.SizeBytes < 350 {
		t.Errorf("size = %d, want at least the 350 bytes of file content", entry.SizeBytes)
	}
	if !hasSignal(entry, "deep_size") {
		t.Errorf("deep size evidence missing: %+v", entry.Evidence)
	}

	bounded := fixtureOptions(root)
	bounded.DeepSize = true
	bounded.Limits.DeepSizeMaxDepth = 1
	boundedResult := run(t, bounded)
	boundedEntry := entryFor(t, boundedResult, project)
	if !hasSignal(boundedEntry, "unknown:deep_size_partial") {
		t.Errorf("a bounded size must be reported as partial, not as a measured total: %+v", boundedEntry.Evidence)
	}
	if report := reportFor(t, boundedResult, CollectorDeepSize); report.Status != core.CollectorPartial {
		t.Errorf("deep size status = %q, want partial", report.Status)
	}
}

func TestDeepSizeDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	project := mustMkdir(t, filepath.Join(root, "project"))
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "big.bin"), strings.Repeat("z", 10000))
	mustSymlink(t, outside, filepath.Join(project, "link"))

	opts := fixtureOptions(root)
	opts.DeepSize = true
	entry := entryFor(t, run(t, opts), project)

	if entry.SizeBytes >= 10000 {
		t.Errorf("size = %d: deep sizing followed a symlink out of the tree", entry.SizeBytes)
	}
}

func TestRunReportsEveryCollector(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "project"))

	result := run(t, fixtureOptions(root))
	seen := map[string]core.CollectorStatus{}
	for _, report := range result.Reports {
		seen[report.Name] = report.Status
		if !report.Status.Valid() {
			t.Errorf("collector %q has invalid status %q", report.Name, report.Status)
		}
		if report.Status == core.CollectorSkipped && report.Detail == "" {
			t.Errorf("collector %q was skipped without saying why", report.Name)
		}
	}
	for _, name := range []string{
		CollectorFilesystem, CollectorDeepSize, CollectorGit,
		CollectorProcesses, CollectorAgents, CollectorServices,
	} {
		if _, ok := seen[name]; !ok {
			t.Errorf("collector %q is missing from the scan report: %v", name, seen)
		}
	}
	for i := 1; i < len(result.Reports); i++ {
		if result.Reports[i-1].Name > result.Reports[i].Name {
			t.Fatalf("reports are not ordered: %v", result.Reports)
		}
	}
}

func TestRunRejectsUnusableOptions(t *testing.T) {
	cases := map[string]func(*Options){
		"relative root":    func(o *Options) { o.Roots[0].Path = "relative" },
		"zero depth":       func(o *Options) { o.Roots[0].MaxDepth = 0 },
		"zero entry bound": func(o *Options) { o.Limits.MaxEntries = 0 },
		"no proc root":     func(o *Options) { o.Processes = true; o.ProcRoot = "" },
		"no git timeout":   func(o *Options) { o.Git = true; o.Limits.GitTimeout = 0 },
	}
	for name, mutate := range cases {
		opts := fixtureOptions(t.TempDir())
		mutate(&opts)
		if _, err := Run(context.Background(), opts); err == nil {
			t.Errorf("%s: expected Run to reject the options", name)
		}
	}
}

func TestFingerprintTracksMetadataChanges(t *testing.T) {
	base := core.Entry{
		Path:         "/repos/app",
		Kind:         core.EntryKindDirectory,
		FilesystemID: core.FilesystemID{Device: 1, Inode: 2},
		Ownership:    core.Ownership{UID: 1000, GID: 1000, Mode: "0755"},
		SizeBytes:    4096,
		ModifiedAt:   fixedNow,
	}
	stable := Fingerprint(base)
	if stable != Fingerprint(base) {
		t.Fatal("fingerprint is not stable for identical metadata")
	}

	// Evidence and observation time change every scan and must not change
	// the fingerprint, or nothing would ever compare as unchanged.
	noisy := base
	noisy.ObservedAt = fixedNow.Add(time.Hour)
	noisy.Evidence = []core.Evidence{{Source: core.SourceFilesystem, Signal: "lstat", ObservedAt: fixedNow}}
	if Fingerprint(noisy) != stable {
		t.Error("evidence or observation time changed the fingerprint")
	}

	for name, mutate := range map[string]func(*core.Entry){
		"size":     func(e *core.Entry) { e.SizeBytes = 8192 },
		"identity": func(e *core.Entry) { e.FilesystemID.Inode = 3 },
		"mode":     func(e *core.Entry) { e.Ownership.Mode = "0700" },
		"modified": func(e *core.Entry) { e.ModifiedAt = fixedNow.Add(time.Second) },
		"git":      func(e *core.Entry) { e.Git = &core.GitState{DirtyFiles: 1} },
	} {
		changed := base
		mutate(&changed)
		if Fingerprint(changed) == stable {
			t.Errorf("%s change did not change the fingerprint", name)
		}
	}
}

func TestPriorScanComparison(t *testing.T) {
	root := t.TempDir()
	stable := mustWrite(t, filepath.Join(root, "stable.txt"), "same")
	changing := mustWrite(t, filepath.Join(root, "changing.txt"), "before")

	first := run(t, fixtureOptions(root))
	mustWrite(t, changing, "after-with-more-bytes")
	mustWrite(t, filepath.Join(root, "fresh.txt"), "new")

	opts := fixtureOptions(root)
	opts.Prior = first.Entries
	opts.PriorScanID = "scan-earlier"
	second := run(t, opts)

	if !hasSignal(entryFor(t, second, stable), "unchanged_since_prior_scan") {
		t.Error("an unchanged file was not recognised as unchanged")
	}
	if !hasSignal(entryFor(t, second, changing), "changed_since_prior_scan") {
		t.Error("a changed file was not recognised as changed")
	}
	if !hasSignal(entryFor(t, second, filepath.Join(root, "fresh.txt")), "new_since_prior_scan") {
		t.Error("a new file was not recognised as new")
	}
	for _, entry := range second.Entries {
		if entry.Fingerprint == "" {
			t.Errorf("%s has no fingerprint", entry.Path)
		}
	}
}

func TestPathWithin(t *testing.T) {
	cases := []struct {
		path, entry string
		want        bool
	}{
		{"/repos/app", "/repos/app", true},
		{"/repos/app/src", "/repos/app", true},
		{"/repos/application", "/repos/app", false},
		{"/repos", "/repos/app", false},
	}
	for _, tc := range cases {
		if got := pathWithin(tc.path, tc.entry); got != tc.want {
			t.Errorf("pathWithin(%q, %q) = %t, want %t", tc.path, tc.entry, got, tc.want)
		}
	}
}

// Git facts that decide protections must be part of the fingerprint.
// Gaining an upstream at the same HEAD removes the unknown-publication
// protection, so it must not compare as unchanged.
func TestFingerprintCoversGitFactsThatDecideProtections(t *testing.T) {
	base := core.Entry{
		Path:       "/repos/app",
		Kind:       core.EntryKindDirectory,
		ModifiedAt: fixedNow,
		Git: &core.GitState{
			RepoRoot: "/repos/app",
			Head:     "abcdef",
			Branch:   "main",
		},
	}
	stable := Fingerprint(base)
	for name, mutate := range map[string]func(*core.GitState){
		"upstream became known":  func(g *core.GitState) { g.UpstreamKnown = true },
		"repository became bare": func(g *core.GitState) { g.Bare = true },
		"worktree owner changed": func(g *core.GitState) { g.WorktreeOf = "/repos/origin" },
		"remote changed":         func(g *core.GitState) { g.Remote = "git@example.invalid:app.git" },
	} {
		state := *base.Git
		mutate(&state)
		changed := base
		changed.Git = &state
		if Fingerprint(changed) == stable {
			t.Errorf("%s did not change the fingerprint", name)
		}
	}
}

// Nested roots are valid policy input. A path both roots cover must appear
// once, with the protections either root recorded, so the reported count
// matches what the store will hold.
func TestOverlappingRootsProduceOneEntryPerPath(t *testing.T) {
	outer := t.TempDir()
	inner := mustMkdir(t, filepath.Join(outer, "inner"))
	shared := mustMkdir(t, filepath.Join(inner, "project"))

	opts := fixtureOptions(outer)
	opts.Roots = []RootSpec{
		{Path: outer, MaxDepth: 2},
		{Path: inner, MaxDepth: 1, ReportOnly: true},
	}
	result := run(t, opts)

	seen := map[string]int{}
	for _, entry := range result.Entries {
		seen[entry.Path]++
	}
	for path, count := range seen {
		if count != 1 {
			t.Errorf("%s appears %d times, want once", path, count)
		}
	}
	entry := entryFor(t, result, shared)
	if entry.Root != inner {
		t.Errorf("root = %q, want the most specific root %q", entry.Root, inner)
	}
	// The report-only protection was recorded under the inner root; merging
	// must not drop it.
	if !hasProtection(entry, core.ProtectPolicyProtected) {
		t.Errorf("merged entry lost the report-only protection: %+v", entry.Protections)
	}
}

// A collector that finished must never be reported as timed out, even when
// its result and the deadline are both ready. The seam forces exactly that
// interleaving, which a plain select would settle by coin flip.
func TestRunBoundedKeepsResultWhenDeadlineAlsoFired(t *testing.T) {
	opts := fixtureOptions(t.TempDir())
	opts.Limits.CommandTimeout = 40 * time.Millisecond

	finished := make(chan struct{})
	gather := func(context.Context, *Options) ([]Reference, core.CollectorReport) {
		defer close(finished)
		return []Reference{{
			Path:       "/repos/app",
			Source:     core.SourceProcess,
			Protection: core.ProtectActiveProcess,
			Signal:     "process_cwd",
		}}, core.CollectorReport{Name: CollectorProcesses, Status: core.CollectorRan, Visited: 5}
	}

	beforeSettle = func() {
		// Wait until the collector has produced its result and the deadline
		// has certainly elapsed: both outcomes are now available.
		<-finished
		time.Sleep(80 * time.Millisecond)
	}
	t.Cleanup(func() { beforeSettle = nil })

	refs, report := runBounded(context.Background(), &opts, CollectorProcesses, gather)
	if report.Status != core.CollectorRan || report.Visited != 5 {
		t.Errorf("report = %+v, want the finished collector's own report", report)
	}
	if len(refs) != 1 {
		t.Errorf("refs = %+v, want the finished collector's references", refs)
	}
}

// A collector that finished must never be reported as timed out, even when
// its result and the deadline become ready at the same moment.
func TestRunBoundedPrefersACompletedCollectorOverTheDeadline(t *testing.T) {
	opts := fixtureOptions(t.TempDir())
	opts.Limits.CommandTimeout = 2 * time.Second

	want := []Reference{{
		Path:       "/repos/app",
		Source:     core.SourceProcess,
		Protection: core.ProtectActiveProcess,
		Signal:     "process_cwd",
	}}
	gather := func(context.Context, *Options) ([]Reference, core.CollectorReport) {
		return want, core.CollectorReport{Name: CollectorProcesses, Status: core.CollectorRan, Visited: 7}
	}

	for i := 0; i < 200; i++ {
		refs, report := runBounded(context.Background(), &opts, CollectorProcesses, gather)
		if report.Status != core.CollectorRan {
			t.Fatalf("iteration %d: status = %q (%s), want the completed collector's own report",
				i, report.Status, report.Detail)
		}
		if report.Visited != 7 || len(refs) != 1 {
			t.Fatalf("iteration %d: result was discarded: report = %+v refs = %+v", i, report, refs)
		}
	}
}

// The same guarantee through the full scan: a fast collector must not be
// reported partial merely because the configured timeout is tiny.
func TestScanDoesNotFalselyReportTimeoutsForFastCollectors(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "project"))

	for i := 0; i < 50; i++ {
		opts := fixtureOptions(root)
		result := run(t, opts)
		for _, name := range []string{CollectorProcesses, CollectorAgents, CollectorServices} {
			report := reportFor(t, result, name)
			if report.Status != core.CollectorSkipped {
				t.Fatalf("iteration %d: %s report = %+v, want skipped: these collectors are disabled and do no work",
					i, name, report)
			}
		}
	}
}

// The deadline is exact. A collector that answers late must not extend the
// scan, and its result must be discarded rather than applied.
func TestRunBoundedDoesNotWaitPastTheDeadline(t *testing.T) {
	opts := fixtureOptions(t.TempDir())
	opts.Limits.CommandTimeout = 60 * time.Millisecond

	late := func(context.Context, *Options) ([]Reference, core.CollectorReport) {
		time.Sleep(400 * time.Millisecond)
		return []Reference{{
			Path:       "/repos/app",
			Source:     core.SourceProcess,
			Protection: core.ProtectActiveProcess,
			Signal:     "process_cwd",
		}}, core.CollectorReport{Name: CollectorProcesses, Status: core.CollectorRan, Visited: 3}
	}

	start := time.Now()
	refs, report := runBounded(context.Background(), &opts, CollectorProcesses, late)
	elapsed := time.Since(start)

	if elapsed > 250*time.Millisecond {
		t.Errorf("runBounded waited %s for a %s deadline: the bound must not be extended", elapsed, opts.Limits.CommandTimeout)
	}
	if report.Status != core.CollectorPartial || report.Unknowns != 1 {
		t.Errorf("report = %+v, want a partial timeout report", report)
	}
	if len(refs) != 0 {
		t.Errorf("refs = %+v, want the late result discarded", refs)
	}
}

// Lateness must be decided against the deadline, not against goroutine
// scheduling. A collector that finishes after the deadline must be
// discarded even when the caller was delayed long enough to still be
// waiting for it.
func TestRunBoundedDiscardsResultFinishedAfterTheDeadline(t *testing.T) {
	opts := fixtureOptions(t.TempDir())
	opts.Limits.CommandTimeout = 40 * time.Millisecond

	finished := make(chan struct{})
	late := func(context.Context, *Options) ([]Reference, core.CollectorReport) {
		time.Sleep(120 * time.Millisecond) // returns well after the deadline
		defer close(finished)
		return []Reference{{
			Path:       "/repos/app",
			Source:     core.SourceProcess,
			Protection: core.ProtectActiveProcess,
			Signal:     "process_cwd",
		}}, core.CollectorReport{Name: CollectorProcesses, Status: core.CollectorRan, Visited: 9}
	}

	// Hold the caller until the late collector has finished, which is the
	// interleaving where a scheduling-based claim would accept its result.
	beforeSettle = func() {
		<-finished
		time.Sleep(20 * time.Millisecond)
	}
	t.Cleanup(func() { beforeSettle = nil })

	refs, report := runBounded(context.Background(), &opts, CollectorProcesses, late)
	if report.Status != core.CollectorPartial || report.Unknowns != 1 {
		t.Errorf("report = %+v, want a partial timeout report for a late collector", report)
	}
	if report.Visited != 0 || len(refs) != 0 {
		t.Errorf("late result was accepted: report = %+v refs = %+v", report, refs)
	}
}

// The deadline branch must never block on a collector that is publishing.
func TestRunBoundedNeverBlocksOnAPublishingCollector(t *testing.T) {
	opts := fixtureOptions(t.TempDir())
	opts.Limits.CommandTimeout = 30 * time.Millisecond

	stall := make(chan struct{})
	t.Cleanup(func() { close(stall) })
	blocked := func(context.Context, *Options) ([]Reference, core.CollectorReport) {
		<-stall
		return nil, core.CollectorReport{Name: CollectorServices, Status: core.CollectorRan}
	}

	start := time.Now()
	_, report := runBounded(context.Background(), &opts, CollectorServices, blocked)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("runBounded waited %s for a %s deadline", elapsed, opts.Limits.CommandTimeout)
	}
	if report.Status != core.CollectorPartial {
		t.Errorf("report = %+v, want partial", report)
	}
}

// Context cancellation is asynchronous: a collector that finished after the
// deadline can still observe a nil context error. The decision must use the
// recorded deadline, so a completion placed past it is dropped even while
// the context is still live.
func TestRunBoundedDropsLateResultBeforeContextCancellationLands(t *testing.T) {
	opts := fixtureOptions(t.TempDir())
	opts.Limits.CommandTimeout = 200 * time.Millisecond

	start := time.Now()
	// The collector finishes immediately in real time, but the clock it is
	// judged against reports a moment past the deadline — the cancellation
	// lag the context check could not see. The first reading arms the
	// deadline; every later reading is past it.
	var armed bool
	nowFunc = func() time.Time {
		if !armed {
			armed = true
			return start
		}
		return start.Add(time.Hour)
	}
	t.Cleanup(func() { nowFunc = time.Now })

	gather := func(ctx context.Context, _ *Options) ([]Reference, core.CollectorReport) {
		if ctx.Err() != nil {
			t.Error("the context must still be live: this test is about the cancellation lag")
		}
		return []Reference{{
			Path:       "/repos/app",
			Source:     core.SourceProcess,
			Protection: core.ProtectActiveProcess,
			Signal:     "process_cwd",
		}}, core.CollectorReport{Name: CollectorProcesses, Status: core.CollectorRan, Visited: 4}
	}

	refs, report := runBounded(context.Background(), &opts, CollectorProcesses, gather)
	if report.Status != core.CollectorPartial || report.Unknowns != 1 {
		t.Errorf("report = %+v, want a partial timeout report", report)
	}
	if len(refs) != 0 || report.Visited != 0 {
		t.Errorf("a result completed past the deadline was accepted: report = %+v refs = %+v", report, refs)
	}
}
