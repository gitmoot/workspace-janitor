//go:build linux

package action

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
)

func observedIdentity(t *testing.T, path string) (core.FilesystemID, int64) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	return core.FilesystemID{Device: uint64(st.Dev), Inode: st.Ino}, int64(st.Ctim.Sec)*1e9 + int64(st.Ctim.Nsec)
}

// A replacement that reuses the observed inode passes a (device, inode)
// check; the observed ctime catches it. Any change after observation (here
// a chmod, which keeps the inode and moves the ctime) refuses the removal
// and leaves the tree in place.
func TestRemoveAnchoredRefusesAChangedCtime(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "entry")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "file"), []byte("data\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	id, ctime := observedIdentity(t, dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if now, after := observedIdentity(t, dir); now != id || after == ctime {
		t.Skip("filesystem did not move the ctime on chmod")
	}
	if err := RemoveAnchored(context.Background(), dir, id, ctime); err == nil {
		t.Fatal("removal with a stale ctime succeeded")
	}
	if _, err := os.Stat(filepath.Join(dir, "sub", "file")); err != nil {
		t.Fatalf("a refused removal touched the tree: %v", err)
	}
	_, current := observedIdentity(t, dir)
	if err := RemoveAnchored(context.Background(), dir, id, current); err != nil {
		t.Fatalf("removal with the current ctime: %v", err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("entry still present: %v", err)
	}
}
