package collect

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// collectDeepSize computes recursive sizes for directory entries.
//
// It is opt-in because it is the expensive pass: a default scan stays at
// lstat metadata. Even when enabled it reads no file contents, follows no
// symlink, stays on the entry's filesystem unless the root permits crossing,
// and stops at the configured entry and depth bounds. A size that hit a
// bound or could not read a subtree is reported as partial, never as a
// measured total.
func collectDeepSize(ctx context.Context, opts *Options, entries []core.Entry, now time.Time) core.CollectorReport {
	report := core.CollectorReport{Name: CollectorDeepSize, Status: core.CollectorRan}
	budget := opts.Limits.DeepSizeMaxEntries
	rootsByPath := make(map[string]RootSpec, len(opts.Roots))
	for _, root := range opts.Roots {
		rootsByPath[root.Path] = root
	}

	for i := range entries {
		entry := &entries[i]
		if entry.Kind != core.EntryKindDirectory {
			continue
		}
		if err := ctx.Err(); err != nil {
			report.Status = core.CollectorPartial
			report.Detail = err.Error()
			return report
		}
		root := rootsByPath[entry.Root]
		sum := &sizeSum{
			crossFilesystem: root.CrossFilesystem,
			device:          entry.FilesystemID.Device,
			maxDepth:        opts.Limits.DeepSizeMaxDepth,
			budget:          budget,
			newest:          entry.ModifiedAt,
		}
		sum.walk(ctx, entry.Path, 1)
		budget = sum.budget
		report.Visited += sum.visited
		report.Recorded++

		entry.SizeBytes = sum.bytes
		if !sum.partial() {
			entry.LatestModifiedAt = sum.newest
		}
		entry.SizeIsDeep = true
		detail := fmt.Sprintf("%d byte(s) across %d entrie(s)", sum.bytes, sum.visited)
		if sum.partial() {
			report.Unknowns++
			report.Status = core.CollectorPartial
			addEvidence(entry, core.Evidence{
				Source:     core.SourceFilesystem,
				Signal:     "unknown:deep_size_partial",
				Detail:     fmt.Sprintf("%s; incomplete: %s", detail, sum.reason),
				ObservedAt: now,
			})
			continue
		}
		addEvidence(entry, core.Evidence{
			Source:     core.SourceFilesystem,
			Signal:     "deep_size",
			Detail:     detail,
			ObservedAt: now,
		})
	}

	if report.Detail == "" {
		report.Detail = fmt.Sprintf("sized %d director(ies) within %d entrie(s)",
			report.Recorded, opts.Limits.DeepSizeMaxEntries)
	}
	return report
}

// sizeSum accumulates a bounded recursive size.
type sizeSum struct {
	crossFilesystem bool
	device          uint64
	maxDepth        int
	budget          int

	bytes    int64
	visited  int
	newest   time.Time
	bounded  bool
	failures int
	reason   string
}

func (s *sizeSum) partial() bool { return s.bounded || s.failures > 0 }

func (s *sizeSum) note(reason string) {
	if s.reason == "" {
		s.reason = reason
	}
}

func (s *sizeSum) walk(ctx context.Context, dir string, depth int) {
	if ctx.Err() != nil {
		s.bounded = true
		s.note("collection was cancelled")
		return
	}
	if depth > s.maxDepth {
		s.bounded = true
		s.note(fmt.Sprintf("depth limit %d reached at %s", s.maxDepth, dir))
		return
	}
	names, err := readDirNamesBounded(dir, s.budget+1)
	if err != nil {
		s.failures++
		s.note(fmt.Sprintf("could not list %s: %v", dir, err))
		return
	}
	if names.bounded {
		s.bounded = true
		s.note(fmt.Sprintf("entry budget reached in %s", dir))
	}

	for _, name := range names.names {
		if s.budget <= 0 {
			s.bounded = true
			s.note("entry budget exhausted")
			return
		}
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			s.failures++
			s.note(fmt.Sprintf("lstat %s: %v", path, err))
			continue
		}
		s.budget--
		s.visited++
		if info.ModTime().After(s.newest) {
			s.newest = info.ModTime()
		}
		s.bytes += info.Size()

		if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
			continue
		}
		if stat := statOf(info); stat.Known && stat.Device != s.device && !s.crossFilesystem {
			s.bounded = true
			s.note(fmt.Sprintf("stopped at mount boundary %s", path))
			continue
		}
		s.walk(ctx, path, depth+1)
	}
}
