package collect

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// An owner checking a clone with `git status` or `git fetch` before releasing
// it rewrites .git bookkeeping only. That must not make the clone look
// recently changed; a new local commit (refs/heads) and any work-tree edit
// still must.
func TestDeepSizeNewestIgnoresGitBookkeeping(t *testing.T) {
	root := t.TempDir()
	clone := filepath.Join(root, "clone")
	old := time.Now().Add(-30 * 24 * time.Hour).Truncate(time.Second)
	recent := time.Now().Add(-time.Minute).Truncate(time.Second)
	write := func(rel string, at time.Time) {
		t.Helper()
		path := filepath.Join(clone, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(rel), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, at, at); err != nil {
			t.Fatal(err)
		}
	}
	for _, rel := range []string{"README.md", ".git/HEAD", ".git/config", ".git/refs/heads/main"} {
		write(rel, old)
	}
	// What git status and git fetch rewrite.
	for _, rel := range []string{".git/index", ".git/FETCH_HEAD", ".git/ORIG_HEAD", ".git/packed-refs",
		".git/logs/HEAD", ".git/logs/refs/remotes/origin/main", ".git/refs/remotes/origin/main", ".git/objects/ab/cdef"} {
		write(rel, recent)
	}
	ageDirs := func() {
		t.Helper()
		if err := filepath.Walk(clone, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				return os.Chtimes(path, old, old)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		// git status creates and renames index.lock, moving .git's own mtime.
		if err := os.Chtimes(filepath.Join(clone, ".git"), recent, recent); err != nil {
			t.Fatal(err)
		}
	}
	newest := func() time.Time {
		t.Helper()
		info, err := os.Lstat(clone)
		if err != nil {
			t.Fatal(err)
		}
		stat := statOf(info)
		entries := []core.Entry{{Path: clone, Root: root, Kind: core.EntryKindDirectory,
			FilesystemID: core.FilesystemID{Device: stat.Device, Inode: stat.Inode}, SizeBytes: info.Size(), ModifiedAt: info.ModTime()}}
		options := fixtureOptions(root)
		collectDeepSize(context.Background(), &options, entries, time.Now())
		if entries[0].SizeIsLowerBound {
			t.Fatalf("fixture walk incomplete: %+v", entries[0])
		}
		return entries[0].LatestModifiedAt
	}

	ageDirs()
	if got := newest(); !got.Equal(old) {
		t.Fatalf("git bookkeeping made the clone look changed at %s, want %s", got, old)
	}
	write(".git/refs/heads/main", recent)
	ageDirs()
	if got := newest(); !got.Equal(recent) {
		t.Fatalf("a new local commit was hidden: newest %s, want %s", got, recent)
	}
	write(".git/refs/heads/main", old)
	write("notes.txt", recent)
	ageDirs()
	if got := newest(); !got.Equal(recent) {
		t.Fatalf("a work-tree edit was hidden: newest %s, want %s", got, recent)
	}
}
