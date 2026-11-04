package workspacearchive

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
)

// An archive/restore allocation may leave exactly the reserve free, never less.
func TestRequireSpaceKeepsTheAllocationReserve(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "probe"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var stat unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	available := stat.Bavail * uint64(stat.Bsize)
	saved := core.AllocationReserveBytes
	defer func() { core.AllocationReserveBytes = saved }()
	const want = 4096
	if available < want+1<<20 {
		t.Skip("filesystem too full for a meaningful boundary")
	}
	// Free space moves while the test runs; leave a margin either side.
	core.AllocationReserveBytes = available - want - 1<<20
	if err := requireSpace(f, want); err != nil {
		t.Fatalf("allocation leaving more than the reserve refused: %v", err)
	}
	core.AllocationReserveBytes = available - want + 1<<20
	if err := requireSpace(f, want); err == nil {
		t.Fatal("allocation crossing the reserve allowed")
	}
}
