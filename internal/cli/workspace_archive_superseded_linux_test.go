//go:build linux

package cli

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// recreateIdentical puts a byte-for-byte copy of the quarantined tree back at
// the original path, with the same permission bits, as a restore outside
// Janitor would.
func recreateIdentical(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		target := filepath.Join(to, rel)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			if err := os.Mkdir(target, 0o700); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if err := os.WriteFile(target, data, 0o600); err != nil {
				return err
			}
		default:
			t.Fatalf("fixture tree holds an unexpected %s", info.Mode())
		}
		return os.Chmod(target, info.Mode().Perm())
	})
	if err != nil {
		t.Fatal(err)
	}
}

// fakeReader adds a procfs stand-in process whose only use of the tree is an
// open descriptor on file.
func fakeReader(t *testing.T, proc, home, file string) {
	t.Helper()
	pid := filepath.Join(proc, "987654321")
	if err := os.MkdirAll(filepath.Join(pid, "fd"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pid, "comm"), []byte("reader\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(home, filepath.Join(pid, "cwd")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(file, filepath.Join(pid, "fd", "3")); err != nil {
		t.Fatal(err)
	}
}

// An archived workspace whose rule stays active is quarantined, then put back
// identical at its original path outside Janitor. A process reading only the
// original says nothing about the redundant quarantined copy: expiry removes
// the copy as superseded_by_original and leaves the original alone. Binding
// the copy to the still-active archive rule used to check live use of the
// original names too, so that reader refused the copy. A reader of the copy
// still keeps it.
func TestArchivedCopySupersededDespiteOriginalOnlyReader(t *testing.T) {
	for _, reads := range []string{"original", "copy"} {
		t.Run("reader of the "+reads, func(t *testing.T) {
			x := newWorkspaceExpiryFixture(t)
			x.archiveAndPin(t, pastRetention, true)
			receipt := x.quarantine(t)
			if receipt.Quarantined == nil || receipt.Quarantined.WorkspaceArchive == nil {
				t.Fatalf("quarantine snapshot lacks the archive binding: %+v", receipt.Quarantined)
			}
			recreateIdentical(t, receipt.Destination, x.source)
			held := filepath.Join(x.source, "README.md")
			if reads == "copy" {
				held = filepath.Join(receipt.Destination, "README.md")
			}
			fakeReader(t, x.proc, x.home, held)
			before := originalState(t, x.source)

			out, stderr, code := x.run(t, "apply", "--expire", "--cleanup", receipt.CleanupID, "--dry-run=false", "--confirm")

			if got := originalState(t, x.source); got != before {
				t.Fatalf("expiry touched the original:\n%s\nwas\n%s", got, before)
			}
			if reads == "original" {
				if code != ExitOK || !strings.Contains(out, "(superseded_by_original)") {
					t.Fatalf("expiry: exit=%d %s %s", code, out, stderr)
				}
				if _, err := os.Lstat(receipt.Destination); !os.IsNotExist(err) {
					t.Fatalf("superseded copy remains: %v", err)
				}
				return
			}
			after := x.receipt(t)
			if code == ExitOK || after.State != core.CleanupInvestigate || !strings.Contains(after.Reason, "in use") {
				t.Fatalf("copy in use: exit=%d %s %q %s", code, after.State, after.Reason, stderr)
			}
			x.preserved(t, receipt.Destination)
		})
	}
}

// originalState is every fact of the tree at root a removal or rewrite would
// change: names, modes, inodes, modification and change times, and bytes.
func originalState(t *testing.T, root string) string {
	t.Helper()
	var out strings.Builder
	err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		st := info.Sys().(*syscall.Stat_t)
		fmt.Fprintf(&out, "%s %s %d %d %d|", path, info.Mode(), st.Ino, st.Mtim.Nano(), st.Ctim.Nano())
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out.Write(data)
		}
		out.WriteString("\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.String()
}
