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
	// Each root gets its own budget, so one enormous tree cannot leave every
	// later root unsized.
	budgets := make(map[string]int, len(opts.Roots))
	rootsByPath := make(map[string]RootSpec, len(opts.Roots))
	for _, root := range opts.Roots {
		rootsByPath[root.Path] = root
	}
	// The metadata walk reports a mount-boundary directory without entering it.
	// Measure every entry against its root's device, not its own, so the
	// separate deep pass cannot start a walk inside that other filesystem.
	rootDevices := make(map[string]rootDevice, len(opts.Roots))

	lowerBounds := 0
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
		budget, seen := budgets[entry.Root]
		if !seen {
			budget = opts.Limits.DeepSizeMaxEntries
		}
		var rd rootDevice
		if !root.CrossFilesystem {
			cached := false
			rd, cached = rootDevices[entry.Root]
			if !cached {
				rd = statRootDevice(entry.Root)
				rootDevices[entry.Root] = rd
			}
		}
		sum := &sizeSum{
			crossFilesystem: root.CrossFilesystem,
			device:          entry.FilesystemID.Device,
			maxDepth:        opts.Limits.DeepSizeMaxDepth,
			budget:          budget,
			newest:          entry.ModifiedAt,
		}
		switch {
		case root.CrossFilesystem || (rd.err == nil && !rd.known):
			// Crossing is allowed, or this platform exposes no device identity.
			sum.walk(ctx, entry.Path, 1)
		case rd.err != nil:
			sum.blind = true
			sum.note(fmt.Sprintf("root %s device is unknown (%v), so %s was not sized", entry.Root, rd.err, entry.Path))
		case entry.FilesystemID.Device != rd.device:
			// Unknown, never zero: the bytes behind a boundary are simply unseen.
			sum.blind = true
			sum.note(fmt.Sprintf("stopped at mount boundary %s (device %d, root device %d)", entry.Path, entry.FilesystemID.Device, rd.device))
		default:
			sum.walk(ctx, entry.Path, 1)
		}
		budgets[entry.Root] = sum.budget
		report.Visited += sum.visited
		report.Recorded++

		entry.SizeBytes = sum.bytes
		if !sum.partial() {
			entry.LatestModifiedAt = sum.newest
		}
		entry.SizeIsDeep = true
		entry.SizeIsLowerBound = sum.partial()
		detail := fmt.Sprintf("%d byte(s) across %d entrie(s)", sum.bytes, sum.visited)
		switch {
		case sum.unknown():
			report.Unknowns++
			report.Status = core.CollectorPartial
			addEvidence(entry, core.Evidence{
				Source:     core.SourceFilesystem,
				Signal:     "unknown:deep_size_partial",
				Detail:     fmt.Sprintf("%s; incomplete: %s", detail, sum.reason),
				ObservedAt: now,
			})
		case sum.limited:
			// Hitting the entry or depth budget only stops counting: the
			// size is a lower bound, not a blind spot. Nothing unseen here
			// bears on safety, which re-observes the target and walks the
			// whole deletion tree for mount points before mutating.
			lowerBounds++
			addEvidence(entry, core.Evidence{
				Source:     core.SourceFilesystem,
				Signal:     "deep_size_lower_bound",
				Detail:     fmt.Sprintf("at least %s; stopped: %s", detail, sum.reason),
				ObservedAt: now,
			})
		default:
			addEvidence(entry, core.Evidence{
				Source:     core.SourceFilesystem,
				Signal:     "deep_size",
				Detail:     detail,
				ObservedAt: now,
			})
		}
	}

	if report.Detail == "" {
		report.Detail = fmt.Sprintf("sized %d director(ies) within %d entrie(s)",
			report.Recorded, opts.Limits.DeepSizeMaxEntries)
		if lowerBounds > 0 {
			report.Detail += fmt.Sprintf("; %d size(s) are lower bounds", lowerBounds)
		}
	}
	return report
}

// sizeSum accumulates a bounded recursive size.
type sizeSum struct {
	crossFilesystem bool
	device          uint64
	maxDepth        int
	budget          int

	bytes   int64
	visited int
	newest  time.Time
	// limited means the entry or depth budget stopped the count.
	limited bool
	// blind means part of the tree could not be observed at all: a
	// cancelled walk or a mount boundary the root does not cross.
	blind    bool
	failures int
	reason   string
}

func (s *sizeSum) partial() bool { return s.limited || s.unknown() }

// unknown reports a gap in what was observed, as opposed to a count that
// was merely cut short.
func (s *sizeSum) unknown() bool { return s.blind || s.failures > 0 }

func (s *sizeSum) note(reason string) {
	if s.reason == "" {
		s.reason = reason
	}
}

func (s *sizeSum) walk(ctx context.Context, dir string, depth int) {
	if ctx.Err() != nil {
		s.blind = true
		s.note("collection was cancelled")
		return
	}
	if depth > s.maxDepth {
		s.limited = true
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
		s.limited = true
		s.note(fmt.Sprintf("entry budget reached in %s", dir))
	}

	for _, name := range names.names {
		if s.budget <= 0 {
			s.limited = true
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
			s.blind = true
			s.note(fmt.Sprintf("stopped at mount boundary %s", path))
			continue
		}
		s.walk(ctx, path, depth+1)
	}
}

type rootDevice struct {
	device uint64
	known  bool
	err    error
}

func statRootDevice(path string) rootDevice {
	info, err := os.Lstat(path)
	if err != nil {
		return rootDevice{err: err}
	}
	stat := statOf(info)
	return rootDevice{device: stat.Device, known: stat.Known}
}
