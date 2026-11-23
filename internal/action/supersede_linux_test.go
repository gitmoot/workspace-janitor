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
	"golang.org/x/sys/unix"
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

// growOriginal adds entries the quarantined copy lacks to the tree at
// source, at its top and inside a directory the copy shares, and changes
// the shared directories' permissions, as a rebuilt original does.
func growOriginal(t *testing.T, source string) {
	t.Helper()
	for _, step := range []func() error{
		func() error { return os.WriteFile(filepath.Join(source, "extra"), []byte("new\n"), 0o644) },
		func() error { return os.WriteFile(filepath.Join(source, "sub", "more"), []byte("more\n"), 0o644) },
		func() error { return os.Mkdir(filepath.Join(source, "added"), 0o755) },
		func() error { return os.Chmod(source, 0o700) },
		func() error { return os.Chmod(filepath.Join(source, "sub"), 0o755) },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
}

// Expiry of a receipt whose original path was recreated after quarantine
// (sandboxd-*-omp, admin-v*-work: restored from archives, then referenced;
// efm-text-cache: rebuilt and grown past the copy). Only an original
// identical to the quarantined copy, or one containing every entry of it
// identical at the same relative path, makes the copy redundant; it alone
// is removed and recorded superseded_by_original, while anything else at
// the original path keeps today's refusal, and a guard on the copy itself
// still keeps it.
func TestExpiryOfRecreatedOriginal(t *testing.T) {
	type outcome int
	const (
		deleted outcome = iota
		superseded
		contained        // superseded by an original holding more than the copy
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
		{"contained and referenced", func(t *testing.T, _ *Engine, _, source string, _ core.CleanupItem) bool {
			writeSupersedeTree(t, source, "notes\n")
			growOriginal(t, source)
			return true
		}, contained},
		{"grown, one file different", func(t *testing.T, _ *Engine, _, source string, _ core.CleanupItem) bool {
			writeSupersedeTree(t, source, "notez\n")
			growOriginal(t, source)
			return true
		}, refusedReference},
		{"grown, one file missing", func(t *testing.T, _ *Engine, _, source string, _ core.CleanupItem) bool {
			writeSupersedeTree(t, source, "notes\n")
			growOriginal(t, source)
			if err := os.Remove(filepath.Join(source, "sub", "notes")); err != nil {
				t.Fatal(err)
			}
			return true
		}, refusedReference},
		{"grown, symlink retargeted", func(t *testing.T, _ *Engine, _, source string, _ core.CleanupItem) bool {
			writeSupersedeTree(t, source, "notes\n")
			growOriginal(t, source)
			link := filepath.Join(source, "link")
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("sub/notez", link); err != nil {
				t.Fatal(err)
			}
			return true
		}, refusedReference},
		{"grown, directory where the copy has a file", func(t *testing.T, _ *Engine, _, source string, _ core.CleanupItem) bool {
			writeSupersedeTree(t, source, "notes\n")
			growOriginal(t, source)
			tool := filepath.Join(source, "tool")
			if err := os.Remove(tool); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(tool, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(tool, "inner"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
				t.Fatal(err)
			}
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
			case deleted, superseded, contained:
				want := map[outcome]core.CleanupState{deleted: core.CleanupDeleted, superseded: core.CleanupSuperseded, contained: core.CleanupSuperseded}[tc.want]
				if err != nil || item.State != want {
					t.Fatalf("expiry: %s %q %v, want %s", item.State, item.Reason, err, want)
				}
				if _, err := os.Lstat(item.Destination); !os.IsNotExist(err) {
					t.Fatalf("quarantined copy still exists: %v", err)
				}
				if wantContained := tc.want == contained; tc.want != deleted && strings.Contains(item.Reason, "contained") != wantContained {
					t.Fatalf("superseded reason %q, want a contained reason=%t", item.Reason, wantContained)
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
// times are not (copying a tree resets them). A copy over the entry budget
// is not compared, and a change to either tree after the comparison, even
// one that leaves the bytes equal, voids the proof before removal. An
// original containing the copy is bounded by the copy's entries alone, and
// may keep gaining entries beside the compared ones, but a change to a
// compared original file voids the proof.
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
	t.Run("contained: budget bounds the copy alone", func(t *testing.T) {
		original, copy, id := setup(t)
		growOriginal(t, original)
		if _, err := compareTrees(ctx, original, copy, id, 5); err != nil {
			t.Fatalf("a five-entry copy inside an eight-entry original, budget five: %v", err)
		}
	})
	t.Run("contained: changed after comparison", func(t *testing.T) {
		original, copy, id := setup(t)
		growOriginal(t, original)
		proof, err := compareTrees(ctx, original, copy, id, 100)
		if err != nil {
			t.Fatal(err)
		}
		// A live original gains entries beside the compared ones: the
		// counterparts still hold what was compared.
		if err := os.WriteFile(filepath.Join(original, "sub", "later"), []byte("later\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := proof.unchanged(ctx); err != nil {
			t.Fatalf("original grown beside the compared entries: %v", err)
		}
		if err := os.WriteFile(filepath.Join(original, "sub", "notes"), []byte("notes\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := proof.unchanged(ctx); err == nil {
			t.Fatal("a rewrite of a compared original file after the comparison kept the proof")
		}
	})
	// The original's directories are looked up, not listed: a search-only
	// one does not stop a containment proof. Root reads it regardless, so
	// this runs only unprivileged.
	t.Run("contained: search-only original directory", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a search-only directory anyway; run unprivileged")
		}
		original, copy, id := setup(t)
		sub := filepath.Join(original, "sub")
		if err := os.Chmod(sub, 0o111); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(sub, 0o755) })
		proof, err := compareTrees(ctx, original, copy, id, 100)
		if err != nil {
			t.Fatalf("original with a search-only directory: %v", err)
		}
		if err := proof.unchanged(ctx); err != nil {
			t.Fatalf("unchanged trees: %v", err)
		}
	})
	t.Run("search-only parent of the original", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a search-only directory anyway; run unprivileged")
		}
		original, copy, id := setup(t)
		parent := filepath.Dir(original)
		if err := os.Chmod(parent, 0o111); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(parent, 0o700) })
		proof, err := compareTrees(ctx, original, copy, id, 100)
		if err != nil {
			t.Fatalf("original below a search-only parent: %v", err)
		}
		if err := proof.unchanged(ctx); err != nil {
			t.Fatalf("unchanged trees: %v", err)
		}
	})
	// A readable directory that cannot be searched can still be listed: an
	// empty one on both sides leaves the trees identical, so the proof stays
	// an identical one, which an entry added to the original voids.
	t.Run("identical: readable, non-searchable empty directory", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root searches any directory anyway; run unprivileged")
		}
		original, copy, id := setup(t)
		for _, dir := range []string{filepath.Join(original, "empty"), filepath.Join(copy, "empty")} {
			if err := os.Mkdir(dir, 0o400); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o400); err != nil {
				t.Fatal(err)
			}
		}
		proof, err := compareTrees(ctx, original, copy, id, 100)
		if err != nil {
			t.Fatalf("identical trees with a 0400 empty directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(original, "later"), []byte("later\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := proof.unchanged(ctx); err == nil {
			t.Fatal("an entry added to an original proven identical kept the proof: it was taken as containing the copy")
		}
	})
}

// privateMounts skips unless the test runs as root in a mount namespace of
// its own (the suite runs under unshare -m), and keeps its mounts from
// propagating out of it.
func privateMounts(t *testing.T) {
	t.Helper()
	self, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Skipf("no mount namespace: %v", err)
	}
	if init, err := os.Readlink("/proc/1/ns/mnt"); err != nil || init == self || os.Geteuid() != 0 {
		t.Skip("needs root in a private mount namespace (unshare -m)")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Skipf("cannot make mounts private: %v", err)
	}
}

func bindMount(t *testing.T, from, to string) {
	t.Helper()
	if err := unix.Mount(from, to, "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind %s at %s: %v", from, to, err)
	}
	t.Cleanup(func() { unix.Unmount(to, unix.MNT_DETACH) })
}

// writeTwins writes a tree whose directories a and b hold the same bytes,
// so either can stand in for the other.
func writeTwins(t *testing.T, dir string) {
	t.Helper()
	for _, path := range []string{dir, filepath.Join(dir, "a"), filepath.Join(dir, "b")} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{filepath.Join(dir, "a", "data"), filepath.Join(dir, "b", "data")} {
		if err := os.WriteFile(path, []byte("payload\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// An original that shows the quarantined copy's own directories (bind
// mounts of the same filesystem, so device numbers match) proves nothing:
// removing the copy would remove what the original was compared to. Both
// the crossed binds (copy a at original b and copy b at original a, which
// match byte for byte) and a bind of a copy directory at its own path keep
// the copy and today's refusal, identical or containing.
func TestExpiryRefusesAnOriginalShowingTheCopy(t *testing.T) {
	privateMounts(t)
	crossed := func(t *testing.T, source, copy string) {
		bindMount(t, filepath.Join(copy, "a"), filepath.Join(source, "b"))
		bindMount(t, filepath.Join(copy, "b"), filepath.Join(source, "a"))
	}
	samePath := func(t *testing.T, source, copy string) {
		bindMount(t, filepath.Join(copy, "a"), filepath.Join(source, "a"))
	}
	cases := []struct {
		name string
		grow bool
		bind func(t *testing.T, source, copy string)
	}{
		{"crossed binds, otherwise identical", false, crossed},
		{"crossed binds, original grown", true, crossed},
		{"copy directory bound at its own path", true, samePath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, root, clock := fixtureEngine(t)
			ctx := context.Background()
			source := filepath.Join(root, "cache")
			writeTwins(t, source)
			item := prepareFixture(t, e, source, core.Retention30Days)
			item, err := e.Quarantine(ctx, item)
			if err != nil {
				t.Fatal(err)
			}
			*clock = clock.Add(31 * 24 * time.Hour)
			writeTwins(t, source)
			if tc.grow {
				if err := os.WriteFile(filepath.Join(source, "extra"), []byte("new\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			tc.bind(t, source, item.Destination)
			unit := "[Service]\nWorkingDirectory=" + source + "\nExecStart=/bin/true\n"
			if err := os.WriteFile(filepath.Join(e.Collect.ServiceSources.SystemdDirs[0], "user.service"), []byte(unit), 0o600); err != nil {
				t.Fatal(err)
			}
			copyBefore := treeState(t, item.Destination)

			item, err = e.Delete(ctx, item)

			if err == nil || item.State != core.CleanupInvestigate || !strings.Contains(item.Reason, "original source has new protected references") {
				t.Fatalf("expiry: %s %q %v, want the original-reference refusal", item.State, item.Reason, err)
			}
			if got := treeState(t, item.Destination); got != copyBefore {
				t.Fatalf("refused copy changed:\n%s\nwas\n%s", got, copyBefore)
			}
			for _, path := range []string{source, item.Destination} {
				for _, dir := range []string{"a", "b"} {
					if _, err := os.Lstat(filepath.Join(path, dir, "data")); err != nil {
						t.Fatalf("payload lost: %v", err)
					}
				}
			}
		})
	}
}
