//go:build linux

package action

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// ReclaimEstimate counts blocks that would become unreferenced after deleting
// all candidates. A hardlink outside the selected set contributes no bytes;
// sparse files contribute allocated blocks, not their apparent length.
type ReclaimEstimate struct {
	Bytes           int64 `json:"bytes"`
	SharedInodes    int   `json:"shared_inodes"`
	ObservedEntries int   `json:"observed_entries"`
}

type inodeKey struct{ device, inode uint64 }
type inodeUse struct {
	blocks    int64
	links     uint64
	seen      uint64
	directory bool
}

// EstimateReclaim returns no estimate on an incomplete traversal, identity
// change, mount boundary or non-filesystem object. The caller must never turn
// an error into a claimed zero-byte estimate.
func EstimateReclaim(ctx context.Context, entries []core.Entry, maxEntries int) (ReclaimEstimate, error) {
	if maxEntries <= 0 {
		return ReclaimEstimate{}, fmt.Errorf("estimate entry limit must be positive")
	}
	seen := make(map[inodeKey]*inodeUse)
	result := ReclaimEstimate{}
	ordered := append([]core.Entry(nil), entries...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	// A parent already accounts for its entire subtree. Never count an
	// explicitly selected child a second time or inflate link counts.
	ancestor := ""
	for _, entry := range ordered {
		if ancestor != "" && core.PathWithin(entry.Path, ancestor) {
			continue
		}
		if entry.Kind == core.EntryKindDirectory {
			ancestor = entry.Path
		}
		device := entry.FilesystemID.Device
		stack := []string{entry.Path}
		for len(stack) != 0 {
			if err := ctx.Err(); err != nil {
				return ReclaimEstimate{}, err
			}
			path := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			info, err := os.Lstat(path)
			if err != nil {
				return ReclaimEstimate{}, fmt.Errorf("estimate %s: %w", path, err)
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || uint64(st.Dev) != device {
				return ReclaimEstimate{}, fmt.Errorf("estimate %s: mount boundary or unknown metadata", path)
			}
			if path == entry.Path {
				if st.Ino != entry.FilesystemID.Inode || info.IsDir() != (entry.Kind == core.EntryKindDirectory) {
					return ReclaimEstimate{}, fmt.Errorf("estimate %s: filesystem identity or kind changed", path)
				}
			}
			result.ObservedEntries++
			if result.ObservedEntries > maxEntries {
				return ReclaimEstimate{}, fmt.Errorf("estimate exceeds %d entries", maxEntries)
			}
			key := inodeKey{uint64(st.Dev), st.Ino}
			use := seen[key]
			if use == nil {
				use = &inodeUse{blocks: st.Blocks, links: uint64(st.Nlink), directory: info.IsDir()}
				seen[key] = use
			}
			if !info.IsDir() {
				use.seen++
			}
			if !info.IsDir() {
				continue
			}
			file, err := os.Open(path)
			if err != nil {
				return ReclaimEstimate{}, fmt.Errorf("open %s: %w", path, err)
			}
			for {
				// One entry at a time avoids allocating for an unbounded cache dir.
				batch, readErr := file.ReadDir(1)
				if readErr != nil && readErr != io.EOF {
					file.Close()
					return ReclaimEstimate{}, fmt.Errorf("list %s: %w", path, readErr)
				}
				for _, child := range batch {
					stack = append(stack, filepath.Join(path, child.Name()))
				}
				if readErr == io.EOF {
					break
				}
				if len(stack)+result.ObservedEntries > maxEntries {
					file.Close()
					return ReclaimEstimate{}, fmt.Errorf("estimate exceeds %d entries", maxEntries)
				}
			}
			if err := file.Close(); err != nil {
				return ReclaimEstimate{}, err
			}
		}
	}
	for _, use := range seen {
		if !use.directory && use.seen < use.links {
			result.SharedInodes++
			continue
		}
		if use.blocks < 0 || use.blocks > (int64(^uint64(0)>>1)-result.Bytes)/512 {
			return ReclaimEstimate{}, fmt.Errorf("estimated blocks overflow")
		}
		result.Bytes += use.blocks * 512
	}
	return result, nil
}
