//go:build linux

package action

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

func TestEstimateReclaimExcludesExternalHardlinksAndSparseHoles(t *testing.T) {
	root := t.TempDir()
	candidate := filepath.Join(root, "cache")
	if err := os.Mkdir(candidate, 0700); err != nil {
		t.Fatal(err)
	}
	sparse := filepath.Join(candidate, "sparse")
	file, err := os.Create(sparse)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(1 << 30); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(candidate, "shared")
	if err := os.WriteFile(shared, []byte("outside link"), 0600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.Link(shared, outside); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(candidate)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	entry := core.Entry{Path: candidate, Kind: core.EntryKindDirectory, FilesystemID: core.FilesystemID{Device: uint64(stat.Dev), Inode: stat.Ino}}
	got, err := EstimateReclaim(context.Background(), []core.Entry{entry}, 10)
	if err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Lstat(sparse)
	if err != nil {
		t.Fatal(err)
	}
	want := (stat.Blocks + fileInfo.Sys().(*syscall.Stat_t).Blocks) * 512
	if got.Bytes != want || got.SharedInodes != 1 {
		t.Fatalf("estimate = %+v, want %d bytes and one externally linked inode", got, want)
	}
	if got.Bytes >= 1<<30 {
		t.Fatalf("sparse hole counted as allocated: %d", got.Bytes)
	}
	// Overlapping approval never treats the same hardlink as another selected link.
	got, err = EstimateReclaim(context.Background(), []core.Entry{entry, {Path: shared, Kind: core.EntryKindFile}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got.Bytes != want || got.SharedInodes != 1 {
		t.Fatalf("overlap counted twice: %+v", got)
	}
}

func TestEstimateReclaimRejectsChangedIdentityAndBound(t *testing.T) {
	root := t.TempDir()
	entry := core.Entry{Path: root, Kind: core.EntryKindDirectory, FilesystemID: core.FilesystemID{Device: 1, Inode: 1}}
	if _, err := EstimateReclaim(context.Background(), []core.Entry{entry}, 10); err == nil {
		t.Fatal("changed identity was estimated")
	}
	info, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	entry.FilesystemID = core.FilesystemID{Device: uint64(stat.Dev), Inode: stat.Ino}
	if err := os.WriteFile(filepath.Join(root, "child"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := EstimateReclaim(context.Background(), []core.Entry{entry}, 1); err == nil {
		t.Fatal("incomplete traversal was estimated")
	}
}
