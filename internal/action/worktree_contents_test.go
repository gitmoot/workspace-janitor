//go:build linux

package action

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

func publishedContentsFixture(t *testing.T, linked bool) (*Engine, string, *time.Time) {
	t.Helper()
	e, root, clock := fixtureEngine(t)
	source := filepath.Join(root, "checkout")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	fixtureGit(t, root, source, "init")
	if err := os.WriteFile(filepath.Join(source, ".gitignore"), []byte("private/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fixtureGit(t, root, source, "add", ".gitignore")
	fixtureGit(t, root, source, "commit", "-m", "published fixture")
	remote := filepath.Join(t.TempDir(), "remote.git")
	fixtureGit(t, root, root, "init", "--bare", remote)
	fixtureGit(t, root, source, "remote", "add", "origin", remote)
	fixtureGit(t, root, source, "push", "-u", "origin", "HEAD")
	if linked {
		owner := source
		source = filepath.Join(root, "linked")
		fixtureGit(t, root, owner, "worktree", "add", "-b", "linked", source)
		fixtureGit(t, root, source, "push", "-u", "origin", "HEAD")
	}
	// Create the empty ignored container before planning. Later nested writes
	// must not accidentally exercise only the preexisting root-mtime guard.
	if err := os.Mkdir(filepath.Join(source, "private"), 0700); err != nil {
		t.Fatal(err)
	}
	return e, source, clock
}

func writeIgnoredFixture(t *testing.T, root, relative string) string {
	t.Helper()
	path := filepath.Join(root, "private", relative)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("synthetic unique payload"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWholeWorktreeQuarantinePreservesIgnoredDescendants(t *testing.T) {
	for _, linked := range []bool{false, true} {
		for _, name := range []string{"nested/credentials.json", "nested/evidence.json", "nested/package-lock.json"} {
			t.Run(strings.ReplaceAll(name, "/", "_")+map[bool]string{true: "_linked", false: "_root"}[linked], func(t *testing.T) {
				e, source, _ := publishedContentsFixture(t, linked)
				item := prepareFixture(t, e, source, core.RetentionNone)
				path := writeIgnoredFixture(t, source, name)
				if _, err := e.Quarantine(context.Background(), item); err == nil {
					t.Fatal("quarantined whole worktree containing unproven ignored content")
				}
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("ignored content was not preserved: %v", err)
				}
			})
		}
	}
}

func TestWholeWorktreeExpiryPreservesLegacyIgnoredDescendants(t *testing.T) {
	for _, linked := range []bool{false, true} {
		t.Run(map[bool]string{true: "linked", false: "root"}[linked], func(t *testing.T) {
			e, source, clock := publishedContentsFixture(t, linked)
			item := prepareFixture(t, e, source, core.RetentionNone)
			var err error
			item, err = e.Quarantine(context.Background(), item)
			if err != nil {
				t.Fatal(err)
			}
			// Model a pre-fix receipt: nested ignored payload was never part of
			// Git's recorded status or the root identity/fingerprint.
			path := writeIgnoredFixture(t, item.Destination, "nested/credentials.json")
			writeIgnoredFixture(t, item.Destination, "nested/evidence.json")
			writeIgnoredFixture(t, item.Destination, "nested/package-lock.json")
			*clock = clock.Add(time.Hour)
			if err := e.ExpiryPreview(context.Background(), item); err == nil {
				t.Fatal("expiry preview approved unproven ignored content")
			}
			if item, err = e.Delete(context.Background(), item); err == nil {
				t.Fatal("expiry deleted unproven ignored content")
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("ignored receipt content was not preserved: %v", err)
			}
			item, err = e.Restore(context.Background(), item)
			if err != nil || item.State != core.CleanupRestored {
				t.Fatalf("protected receipt cannot restore: %v", err)
			}
		})
	}
}

func TestWholeWorktreeQuarantineRefusesUnboundedOrUnreadableTree(t *testing.T) {
	for _, kind := range []string{"depth", "entries", "unreadable", "nested_git", "ignored_symlink"} {
		t.Run(kind, func(t *testing.T) {
			e, source, _ := publishedContentsFixture(t, false)
			e.Collect.Limits.GitTimeout = 30 * time.Second
			item := prepareFixture(t, e, source, core.RetentionNone)
			path := filepath.Join(source, "private")
			switch kind {
			case "depth":
				for range 65 {
					path = filepath.Join(path, "d")
				}
				if err := os.MkdirAll(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "entries":
				for i := range 100000 {
					if err := os.Mkdir(filepath.Join(path, strconv.Itoa(i)), 0700); err != nil {
						t.Fatal(err)
					}
				}
			case "unreadable":
				if err := os.Chmod(path, 0000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(path, 0700) })
			case "nested_git":
				if err := os.Mkdir(filepath.Join(path, ".git"), 0700); err != nil {
					t.Fatal(err)
				}
			case "ignored_symlink":
				if err := os.Symlink(t.TempDir(), filepath.Join(path, "link")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := e.Quarantine(context.Background(), item); err == nil {
				t.Fatal("quarantined worktree with incomplete or unsupported descendant proof")
			}
			if _, err := os.Lstat(source); err != nil {
				t.Fatal("source not preserved:", err)
			}
		})
	}
}
