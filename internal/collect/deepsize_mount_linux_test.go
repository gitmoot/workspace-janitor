//go:build linux

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

// A mount point listed by the metadata walk must not become the start of a
// deep-size walk into that other filesystem when the root does not cross
// filesystems. /dev/shm is a separate tmpfs below devtmpfs /dev on Linux.
func TestDeepSizeDoesNotEnterMountBoundaryEntry(t *testing.T) {
	const root, mount = "/dev", "/dev/shm"
	rootInfo, err := os.Lstat(root)
	if err != nil {
		t.Skipf("no %s: %v", root, err)
	}
	mountInfo, err := os.Lstat(mount)
	if err != nil {
		t.Skipf("no %s: %v", mount, err)
	}
	rootStat, mountStat := statOf(rootInfo), statOf(mountInfo)
	if !rootStat.Known || !mountStat.Known || rootStat.Device == mountStat.Device {
		t.Skipf("%s is not a separate filesystem below %s here", mount, root)
	}
	// Bytes that exist only on the other filesystem.
	dir, err := os.MkdirTemp(mount, "janitor-deepsize-")
	if err != nil {
		t.Skipf("cannot write to %s: %v", mount, err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.WriteFile(filepath.Join(dir, "payload"), make([]byte, 64<<10), 0o600); err != nil {
		t.Fatal(err)
	}

	mountEntries := func() []core.Entry {
		return []core.Entry{{
			Path: mount, Root: root, Kind: core.EntryKindDirectory,
			FilesystemID: core.FilesystemID{Device: mountStat.Device, Inode: mountStat.Inode},
			SizeBytes:    mountInfo.Size(), ModifiedAt: mountInfo.ModTime(),
		}}
	}
	options := fixtureOptions(root)

	entries := mountEntries()
	report := collectDeepSize(context.Background(), &options, entries, time.Now())
	if report.Visited != 0 {
		t.Fatalf("deep size entered %s across the root's mount boundary: visited %d", mount, report.Visited)
	}
	if !entries[0].SizeIsLowerBound || report.Status != core.CollectorPartial {
		t.Fatalf("unseen filesystem reported as a complete size: %+v %+v", report, entries[0])
	}
	if !hasEvidenceDetail(entries[0], "unknown:deep_size_partial", "mount boundary") {
		t.Fatalf("boundary refusal not recorded as unknown evidence: %+v", entries[0].Evidence)
	}

	// A root that explicitly crosses filesystems still measures it.
	options.Roots[0].CrossFilesystem = true
	entries = mountEntries()
	report = collectDeepSize(context.Background(), &options, entries, time.Now())
	if report.Visited == 0 || entries[0].SizeBytes < 64<<10 {
		t.Fatalf("cross_filesystem root did not measure %s: visited %d size %d", mount, report.Visited, entries[0].SizeBytes)
	}
}

func hasEvidenceDetail(entry core.Entry, signal, detail string) bool {
	for _, e := range entry.Evidence {
		if e.Signal == signal && strings.Contains(e.Detail, detail) {
			return true
		}
	}
	return false
}
