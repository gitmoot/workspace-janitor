//go:build linux

package collect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/workspacearchive"
)

func blockingReason(entry core.Entry, kind core.ProtectionKind) string {
	for _, p := range entry.Protections {
		if p.Kind == kind && p.Blocking {
			return p.Reason
		}
	}
	return ""
}

// A unit's companion (an OMP session's "<stem>.jsonl") is never a cleanup
// candidate of its own, at its original path or as a quarantined copy.
func TestWorkspaceArchiveCompanionMovesOnlyWithItsUnit(t *testing.T) {
	base := t.TempDir()
	unit := filepath.Join(base, "sessions", "project", "2026-11-01_abc")
	rule := config.WorkspaceArchiveRule{Name: "session", Path: unit, Companion: unit + ".jsonl", Owner: config.CategoryOwnerPrefix + "omp_sessions"}
	quarantined := filepath.Join(base, "quarantine", "cleanup", "action", "item.jsonl")
	entries := []core.Entry{
		{Path: unit, Kind: core.EntryKindDirectory},
		{Path: unit + ".jsonl", Kind: core.EntryKindFile},
		{Path: quarantined, Kind: core.EntryKindFile},
		{Path: unit + ".other", Kind: core.EntryKindFile},
	}
	opts := &Options{WorktreePolicy: &config.Policy{WorkspaceArchives: []config.WorkspaceArchiveRule{rule}},
		WorktreeOrigins: map[string]string{quarantined: unit + ".jsonl"},
		Limits:          Limits{CommandTimeout: 10 * time.Second}}
	collectWorkspaceArchives(context.Background(), opts, entries, time.Now())
	for _, entry := range entries[1:3] {
		if reason := blockingReason(entry, core.ProtectDurableEvidence); !strings.Contains(reason, "companion of released unit "+unit) {
			t.Fatalf("%s protection = %q, want the companion protection", entry.Path, reason)
		}
	}
	if len(entries[3].Protections) != 0 {
		t.Fatalf("unrelated sibling protected: %+v", entries[3].Protections)
	}
	if entries[1].WorkspaceArchive != nil || entries[2].WorkspaceArchive != nil {
		t.Fatal("a companion was bound as a unit of its own")
	}
}

// archivedFile archives and pins one regular file, as a gitmoot job log
// category unit does.
func archivedFile(t *testing.T) (*Options, config.WorkspaceArchiveRule) {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	logs := filepath.Join(home, ".gitmoot", "logs", "jobs")
	archive, proc := filepath.Join(home, "archive"), filepath.Join(home, "proc")
	for _, dir := range []string{logs, archive, proc} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(logs, "job-1.log")
	if err := os.WriteFile(path, []byte("job output\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rule := config.WorkspaceArchiveRule{Name: "job-1", Path: path, Owner: "seat-a", Release: "release-msg-1",
		DependentRoots: []string{home}, LocalExpiryEnabled: true, LocalRetention: core.RetentionNone,
		Archive: config.WorkspaceArchiveDestination{Directory: archive}}
	_, binding, err := workspacearchive.Create(context.Background(), rule, workspacearchive.Scope{ProcRoot: proc, SearchRoots: []string{home}}, func() error { return nil })
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	rule.Archive.Manifest, rule.Archive.ManifestSHA256 = binding.Manifest, binding.ManifestSHA256
	return &Options{WorktreePolicy: &config.Policy{WorkspaceArchives: []config.WorkspaceArchiveRule{rule}},
		ProcRoot: proc, VerifyArchiveContents: true, Limits: Limits{CommandTimeout: 30 * time.Second}}, rule
}

func TestWorkspaceArchiveBindsARegularFileUnit(t *testing.T) {
	opts, rule := archivedFile(t)
	entries := []core.Entry{{Path: rule.Path, Kind: core.EntryKindFile}}
	collectWorkspaceArchives(context.Background(), opts, entries, time.Now())
	if entries[0].WorkspaceArchive == nil {
		t.Fatalf("regular file unit not bound: %+v", entries[0].Evidence)
	}
	if reason := blockingReason(entries[0], core.ProtectDurableEvidence); reason != "" {
		t.Fatalf("bound file still protected: %s", reason)
	}
	// Any other type at that name stays protected.
	entries = []core.Entry{{Path: rule.Path, Kind: core.EntryKindSymlink}}
	collectWorkspaceArchives(context.Background(), opts, entries, time.Now())
	if entries[0].WorkspaceArchive != nil || !strings.Contains(blockingReason(entries[0], core.ProtectDurableEvidence), "symlinks and other types remain protected") {
		t.Fatalf("symlink unit: %+v %+v", entries[0].WorkspaceArchive, entries[0].Protections)
	}
}

// #213: a verification is deferred only when Bind stops on its own
// deadline. A genuine read failure that arrives after that deadline (here
// the manifest cannot be opened, which no context check precedes) is
// refused like any other, not folded into a deferral.
func TestWorkspaceArchiveReadErrorAfterTheVerifyDeadlineIsRefused(t *testing.T) {
	opts, rule := archivedFile(t)
	opts.Limits.ArchiveVerifyTimeout = 100 * time.Millisecond
	BeforeWorkspaceArchiveBind = func() {
		time.Sleep(300 * time.Millisecond)
		if err := os.Rename(rule.Archive.Manifest, rule.Archive.Manifest+".unreadable"); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { BeforeWorkspaceArchiveBind = nil })
	entries := []core.Entry{{Path: rule.Path, Kind: core.EntryKindFile}}
	collectWorkspaceArchives(context.Background(), opts, entries, time.Now())
	reason := blockingReason(entries[0], core.ProtectDurableEvidence)
	if entries[0].WorkspaceArchive != nil || !strings.Contains(reason, "does not bind the local tree") {
		t.Fatalf("read error after the deadline not refused: %q", reason)
	}
	if err := ArchiveVerifyDeferral(entries[0]); err != nil {
		t.Fatalf("read error after the deadline deferred: %v", err)
	}
}

// A bound unit with a companion carries the companion's identity, which the
// fingerprint covers: a replaced companion invalidates a saved plan.
func TestWorkspaceArchiveBindingCarriesItsCompanion(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	unit := filepath.Join(home, "sessions", "project", "2026-11-01_abc")
	archive, proc := filepath.Join(home, "archive"), filepath.Join(home, "proc")
	for _, dir := range []string{unit, archive, proc} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(unit, "artifact"), []byte("tool output\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit+".jsonl", []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rule := config.WorkspaceArchiveRule{Name: "session", Path: unit, Companion: unit + ".jsonl", Owner: "seat-a", Release: "release-msg-1",
		DependentRoots: []string{home}, LocalExpiryEnabled: true, LocalRetention: core.RetentionNone,
		Archive: config.WorkspaceArchiveDestination{Directory: archive}}
	_, binding, err := workspacearchive.Create(context.Background(), rule, workspacearchive.Scope{ProcRoot: proc, SearchRoots: []string{home}}, func() error { return nil })
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	rule.Archive.Manifest, rule.Archive.ManifestSHA256 = binding.Manifest, binding.ManifestSHA256
	opts := &Options{WorktreePolicy: &config.Policy{WorkspaceArchives: []config.WorkspaceArchiveRule{rule}},
		ProcRoot: proc, VerifyArchiveContents: true, Limits: Limits{CommandTimeout: 30 * time.Second}}
	entries := []core.Entry{{Path: unit, Kind: core.EntryKindDirectory}}
	collectWorkspaceArchives(context.Background(), opts, entries, time.Now())
	b := entries[0].WorkspaceArchive
	if b == nil {
		t.Fatalf("unit not bound: %+v", entries[0].Evidence)
	}
	info, err := os.Lstat(unit + ".jsonl")
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	if b.CompanionSuffix != ".jsonl" || b.CompanionID != (core.FilesystemID{Device: uint64(st.Dev), Inode: st.Ino}) {
		t.Fatalf("binding companion = %q %s", b.CompanionSuffix, b.CompanionID)
	}
	replaced := entries[0]
	replaced.WorkspaceArchive = &core.WorkspaceArchiveBinding{}
	*replaced.WorkspaceArchive = *b
	replaced.WorkspaceArchive.CompanionID.Inode++
	if Fingerprint(replaced) == Fingerprint(entries[0]) {
		t.Fatal("fingerprint ignores the companion identity")
	}
}
