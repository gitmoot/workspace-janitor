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

// The same bookkeeping inside a linked worktree's or a submodule's Git
// directory, a shallow-fetch update, and an entry that is itself a bare
// repository must not count as change either; their own new commits must.
func TestDeepSizeNewestIgnoresNestedAndBareGitBookkeeping(t *testing.T) {
	old := time.Now().Add(-30 * 24 * time.Hour).Truncate(time.Second)
	recent := time.Now().Add(-time.Minute).Truncate(time.Second)
	newestOf := func(t *testing.T, root, entry string, layout map[string]time.Time) time.Time {
		t.Helper()
		for rel, at := range layout {
			path := filepath.Join(entry, rel)
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
		// Every directory mtime is old except Git directories, whose own mtime
		// moves with lock files.
		if err := filepath.Walk(entry, func(path string, info os.FileInfo, err error) error {
			if err != nil || !info.IsDir() {
				return err
			}
			at := old
			if head, err := os.Lstat(filepath.Join(path, "HEAD")); err == nil && head.Mode().IsRegular() {
				at = recent
			}
			return os.Chtimes(path, at, at)
		}); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(entry)
		if err != nil {
			t.Fatal(err)
		}
		stat := statOf(info)
		entries := []core.Entry{{Path: entry, Root: root, Kind: core.EntryKindDirectory,
			FilesystemID: core.FilesystemID{Device: stat.Device, Inode: stat.Inode}, SizeBytes: info.Size(), ModifiedAt: info.ModTime()}}
		options := fixtureOptions(root)
		collectDeepSize(context.Background(), &options, entries, time.Now())
		if entries[0].SizeIsLowerBound {
			t.Fatalf("fixture walk incomplete: %+v", entries[0])
		}
		return entries[0].LatestModifiedAt
	}
	repository := func(prefix string, refs time.Time) map[string]time.Time {
		return map[string]time.Time{
			prefix + "HEAD": old, prefix + "config": old, prefix + "objects/info/packs": old,
			prefix + "refs/heads/main": refs,
		}
	}
	t.Run("worktree submodule and shallow", func(t *testing.T) {
		root := t.TempDir()
		clone := filepath.Join(root, "clone")
		layout := repository(".git/", old)
		layout["README.md"] = old
		layout[".git/shallow"] = recent
		layout[".git/worktrees/feature/HEAD"] = old
		layout[".git/worktrees/feature/commondir"] = old
		layout[".git/worktrees/feature/index"] = recent
		layout[".git/worktrees/feature/logs/HEAD"] = recent
		for rel, at := range repository(".git/modules/lib/", old) {
			layout[rel] = at
		}
		layout[".git/modules/lib/index"] = recent
		layout[".git/modules/lib/FETCH_HEAD"] = recent
		if got := newestOf(t, root, clone, layout); !got.Equal(old) {
			t.Fatalf("nested Git bookkeeping made the clone look changed at %s, want %s", got, old)
		}
		layout[".git/modules/lib/refs/heads/main"] = recent
		if got := newestOf(t, root, clone, layout); !got.Equal(recent) {
			t.Fatalf("a new submodule commit was hidden: newest %s, want %s", got, recent)
		}
	})
	t.Run("bare repository entry", func(t *testing.T) {
		root := t.TempDir()
		bare := filepath.Join(root, "repo.git")
		layout := repository("", old)
		layout["FETCH_HEAD"] = recent
		layout["objects/ab/cdef"] = recent
		layout["packed-refs"] = recent
		if got := newestOf(t, root, bare, layout); !got.Equal(old) {
			t.Fatalf("bare repository bookkeeping counted as change at %s, want %s", got, old)
		}
		layout["refs/heads/main"] = recent
		if got := newestOf(t, root, bare, layout); !got.Equal(recent) {
			t.Fatalf("a new bare repository commit was hidden: newest %s, want %s", got, recent)
		}
	})
}
