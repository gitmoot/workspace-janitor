//go:build linux

package action

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// writeSupersedeTree writes a small tree with every entry type a comparison
// handles, with explicit modes so the umask cannot make two copies differ.
func writeSupersedeTree(t *testing.T, dir, notes string) {
	t.Helper()
	for _, step := range []func() error{
		func() error { return os.Mkdir(dir, 0o755) },
		func() error { return os.WriteFile(filepath.Join(dir, "tool"), []byte("#!/bin/sh\nexit 0\n"), 0o755) },
		func() error { return os.Mkdir(filepath.Join(dir, "sub"), 0o700) },
		func() error { return os.WriteFile(filepath.Join(dir, "sub", "notes"), []byte(notes), 0o644) },
		func() error { return os.Symlink("sub/notes", filepath.Join(dir, "link")) },
		func() error { return os.Chmod(dir, 0o755) },
		func() error { return os.Chmod(filepath.Join(dir, "tool"), 0o755) },
		func() error { return os.Chmod(filepath.Join(dir, "sub"), 0o700) },
		func() error { return os.Chmod(filepath.Join(dir, "sub", "notes"), 0o644) },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
}

// treeState is every fact of the tree at path, without following symlinks:
// expiry must leave the original exactly as it was, inodes and times included.
func treeState(t *testing.T, path string) string {
	t.Helper()
	var out strings.Builder
	err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st := info.Sys().(*syscall.Stat_t)
		fmt.Fprintf(&out, "%s %s %d %d %d|", p, info.Mode(), st.Ino, st.Mtim.Nano(), st.Ctim.Nano())
		switch {
		case info.Mode().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out.Write(data)
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			out.WriteString(target)
		}
		out.WriteString("\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// Expiry of a receipt whose original path was recreated after quarantine
// (sandboxd-*-omp, admin-v*-work: restored from archives, then referenced).
// Only an original identical to the quarantined copy makes the copy
// redundant; it alone is removed and recorded superseded_by_original, while
// anything else at the original path keeps today's refusal, and a guard on
// the copy itself still keeps it.
func TestExpiryOfRecreatedOriginal(t *testing.T) {
	type outcome int
	const (
		deleted outcome = iota
		superseded
		refusedReference // today's refusal: the original path is referenced
		refusedCopy      // a guard on the quarantined copy refuses
	)
	cases := []struct {
		name string
		// recreate puts something back at source after quarantine and
		// reports whether a service then references source.
		recreate func(t *testing.T, e *Engine, root, source string, item core.CleanupItem) bool
		want     outcome
	}{
		{"never recreated", func(*testing.T, *Engine, string, string, core.CleanupItem) bool { return false }, deleted},
		{"identical and referenced", func(t *testing.T, _ *Engine, _, source string, _ core.CleanupItem) bool {
			writeSupersedeTree(t, source, "notes\n")
			return true
		}, superseded},
		{"one byte different", func(t *testing.T, _ *Engine, _, source string, _ core.CleanupItem) bool {
			writeSupersedeTree(t, source, "notez\n")
			return true
		}, refusedReference},
		{"symlink to an identical tree", func(t *testing.T, _ *Engine, root, source string, _ core.CleanupItem) bool {
			elsewhere := filepath.Join(root, "elsewhere")
			writeSupersedeTree(t, elsewhere, "notes\n")
			if err := os.Symlink(elsewhere, source); err != nil {
				t.Fatal(err)
			}
			return true
		}, refusedReference},
		{"file where a directory was", func(t *testing.T, _ *Engine, _, source string, _ core.CleanupItem) bool {
			if err := os.WriteFile(source, []byte("notes\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return true
		}, refusedReference},
		{"open descriptor inside the copy", func(t *testing.T, e *Engine, root, source string, item core.CleanupItem) bool {
			writeSupersedeTree(t, source, "notes\n")
			pid := filepath.Join(e.Collect.ProcRoot, "987654321")
			if err := os.MkdirAll(filepath.Join(pid, "fd"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(pid, "comm"), []byte("reader\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(root, filepath.Join(pid, "cwd")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(item.Destination, "sub", "notes"), filepath.Join(pid, "fd", "3")); err != nil {
				t.Fatal(err)
			}
			return true
		}, refusedCopy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, root, clock := fixtureEngine(t)
			ctx := context.Background()
			source := filepath.Join(root, "sandboxd-omp")
			writeSupersedeTree(t, source, "notes\n")
			item := prepareFixture(t, e, source, core.Retention30Days)
			item, err := e.Quarantine(ctx, item)
			if err != nil {
				t.Fatal(err)
			}
			*clock = clock.Add(31 * 24 * time.Hour)
			if tc.recreate(t, e, root, source, item) {
				unit := "[Service]\nWorkingDirectory=" + source + "\nExecStart=/bin/true\n"
				if err := os.WriteFile(filepath.Join(e.Collect.ServiceSources.SystemdDirs[0], "user.service"), []byte(unit), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var original string
			if _, err := os.Lstat(source); err == nil {
				original = treeState(t, source)
			}
			copyBefore := treeState(t, item.Destination)

			item, err = e.Delete(ctx, item)

			switch tc.want {
			case deleted, superseded:
				want := map[outcome]core.CleanupState{deleted: core.CleanupDeleted, superseded: core.CleanupSuperseded}[tc.want]
				if err != nil || item.State != want {
					t.Fatalf("expiry: %s %q %v, want %s", item.State, item.Reason, err, want)
				}
				if _, err := os.Lstat(item.Destination); !os.IsNotExist(err) {
					t.Fatalf("quarantined copy still exists: %v", err)
				}
			default:
				if err == nil || item.State != core.CleanupInvestigate {
					t.Fatalf("expiry: %s %v, want a refusal", item.State, err)
				}
				references := strings.Contains(item.Reason, "original source has new protected references")
				if references != (tc.want == refusedReference) {
					t.Fatalf("refusal %q, want original-reference refusal=%t", item.Reason, tc.want == refusedReference)
				}
				if got := treeState(t, item.Destination); got != copyBefore {
					t.Fatalf("refused copy changed:\n%s\nwas\n%s", got, copyBefore)
				}
			}
			if original != "" {
				if got := treeState(t, source); got != original {
					t.Fatalf("expiry touched the original:\n%s\nwas\n%s", got, original)
				}
			}
			stored, err := e.Items(ctx, item.CleanupID)
			if err != nil || len(stored) != 1 || stored[0].State != item.State {
				t.Fatalf("journaled receipt: %+v %v, want %s", stored, err, item.State)
			}
		})
	}
}

// Expiry removes a superseded copy before journaling it. If it stops in
// between, the next expiry finds the copy gone and records the outcome its
// marker names, superseded_by_original rather than deleted or investigate.
func TestExpiryRecordsAnInterruptedSupersededRemoval(t *testing.T) {
	e, root, clock := fixtureEngine(t)
	ctx := context.Background()
	source := filepath.Join(root, "sandboxd-omp")
	writeSupersedeTree(t, source, "notes\n")
	item := prepareFixture(t, e, source, core.Retention30Days)
	item, err := e.Quarantine(ctx, item)
	if err != nil {
		t.Fatal(err)
	}
	*clock = clock.Add(31 * 24 * time.Hour)
	writeSupersedeTree(t, source, "notes\n")
	if err := writeRemovalMarker(item, core.CleanupSuperseded); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(item.Destination); err != nil {
		t.Fatal(err)
	}
	item, err = e.Delete(ctx, item)
	if err != nil || item.State != core.CleanupSuperseded {
		t.Fatalf("interrupted superseded removal: %s %q %v, want %s", item.State, item.Reason, err, core.CleanupSuperseded)
	}
}

// The identity proof fails closed. Permission bits are compared (a restore
// brings them back, and they decide who may use the tree); modification
// times are not (copying a tree resets them). A tree over the entry budget
// is not compared, and a change to either tree after the comparison, even
// one that leaves the bytes equal, voids the proof before removal.
func TestIdenticalTreeProofFailsClosed(t *testing.T) {
	setup := func(t *testing.T) (original, copy string, id core.FilesystemID) {
		t.Helper()
		base := t.TempDir()
		original, copy = filepath.Join(base, "original"), filepath.Join(base, "receipt", "item")
		if err := os.Mkdir(filepath.Dir(copy), 0o700); err != nil {
			t.Fatal(err)
		}
		writeSupersedeTree(t, original, "notes\n")
		writeSupersedeTree(t, copy, "notes\n")
		// Change times come from a coarse clock (one kernel tick); let the
		// next change land in a later tick than this setup.
		time.Sleep(50 * time.Millisecond)
		info, err := os.Lstat(copy)
		if err != nil {
			t.Fatal(err)
		}
		return original, copy, fileIdentity(info)
	}
	ctx := context.Background()
	t.Run("modification times differ", func(t *testing.T) {
		original, copy, id := setup(t)
		old := time.Now().Add(-48 * time.Hour)
		if err := os.Chtimes(filepath.Join(original, "tool"), old, old); err != nil {
			t.Fatal(err)
		}
		if _, err := compareTrees(ctx, original, copy, id, 100); err != nil {
			t.Fatalf("trees differing only in mtime: %v", err)
		}
	})
	t.Run("permission bits differ", func(t *testing.T) {
		original, copy, id := setup(t)
		if err := os.Chmod(filepath.Join(original, "tool"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := compareTrees(ctx, original, copy, id, 100); err == nil {
			t.Fatal("trees differing in mode compared identical")
		}
	})
	t.Run("entry budget", func(t *testing.T) {
		original, copy, id := setup(t)
		if _, err := compareTrees(ctx, original, copy, id, 4); err == nil {
			t.Fatal("a five-entry tree was compared within a four-entry budget")
		}
	})
	t.Run("changed after comparison", func(t *testing.T) {
		original, copy, id := setup(t)
		proof, err := compareTrees(ctx, original, copy, id, 100)
		if err != nil {
			t.Fatal(err)
		}
		if err := proof.unchanged(ctx); err != nil {
			t.Fatalf("unchanged trees: %v", err)
		}
		// Same bytes rewritten: content still equal, but it is no longer
		// what was compared.
		if err := os.WriteFile(filepath.Join(original, "sub", "notes"), []byte("notes\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := proof.unchanged(ctx); err == nil {
			t.Fatal("a rewrite after the comparison kept the proof")
		}
	})
}
