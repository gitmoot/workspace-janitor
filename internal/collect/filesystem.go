package collect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// collectFilesystem walks each root with lstat only, to the root's configured
// depth. It reads no file contents, follows no symlink unless the root
// permits it, and never leaves the root's filesystem unless the root permits
// that either.
func collectFilesystem(ctx context.Context, opts *Options, now time.Time) ([]core.Entry, []core.CollectorReport) {
	report := core.CollectorReport{Name: CollectorFilesystem, Status: core.CollectorRan}
	var (
		entries []core.Entry
		details []string
	)

	for _, root := range opts.Roots {
		rootInfo, err := os.Lstat(root.Path)
		if err != nil {
			report.Unknowns++
			report.Status = core.CollectorPartial
			details = append(details, fmt.Sprintf("%s: %v", root.Path, err))
			continue
		}
		if !rootInfo.IsDir() {
			report.Unknowns++
			report.Status = core.CollectorPartial
			details = append(details, fmt.Sprintf("%s: not a directory", root.Path))
			continue
		}
		rootStat := statOf(rootInfo)
		walker := &metadataWalk{
			opts:    opts,
			root:    root,
			rootDev: rootStat.Device,
			now:     now,
			seen:    map[core.FilesystemID]struct{}{},
			report:  &report,
			details: &details,
		}
		rootEntries, err := walker.walk(ctx, root.Path, 1)
		entries = append(entries, rootEntries...)
		if err != nil {
			details = append(details, fmt.Sprintf("%s: %v", root.Path, err))
		}
	}

	report.Recorded = len(entries)
	if report.Unknowns > 0 && report.Status == core.CollectorRan {
		report.Status = core.CollectorPartial
	}
	if len(details) > 0 {
		sort.Strings(details)
		report.Detail = strings.Join(details, "; ")
	}
	if report.Detail == "" {
		report.Detail = fmt.Sprintf("%d root(s), lstat metadata only", len(opts.Roots))
	}
	return entries, []core.CollectorReport{report}
}

// metadataWalk carries the bounds and bookkeeping of one root's walk.
type metadataWalk struct {
	opts    *Options
	root    RootSpec
	rootDev uint64
	now     time.Time
	seen    map[core.FilesystemID]struct{}
	report  *core.CollectorReport
	details *[]string
}

// note records a scan-wide explanation of a bound or failure.
func (w *metadataWalk) note(detail string) {
	for _, existing := range *w.details {
		if existing == detail {
			return
		}
	}
	*w.details = append(*w.details, detail)
}

func (w *metadataWalk) walk(ctx context.Context, dir string, depth int) ([]core.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	names, err := readDirNamesBounded(dir, w.opts.Limits.MaxDirEntries)
	if err != nil {
		w.report.Unknowns++
		w.report.Status = core.CollectorPartial
		return nil, err
	}
	if names.bounded {
		w.report.Status = core.CollectorPartial
		w.note(fmt.Sprintf("listing of %s was truncated at %d entries", dir, w.opts.Limits.MaxDirEntries))
	}

	var entries []core.Entry
	for _, name := range names.names {
		if err := ctx.Err(); err != nil {
			return entries, err
		}
		if w.report.Visited >= w.opts.Limits.MaxEntries {
			w.report.Status = core.CollectorPartial
			err := fmt.Errorf("%w: entry limit %d reached, so the inventory is incomplete", errBounded, w.opts.Limits.MaxEntries)
			w.note(err.Error())
			return entries, err
		}
		w.report.Visited++

		path := filepath.Join(dir, name)
		entry, descend := w.entryFor(path, names.bounded)
		entries = append(entries, entry)

		if !descend || depth >= w.root.MaxDepth {
			continue
		}
		child, err := w.walk(ctx, path, depth+1)
		entries = append(entries, child...)
		if err != nil {
			// An unreadable or bounded subdirectory hides what is inside it,
			// so the parent entry must not look clean.
			addUnknown(&entries[len(entries)-len(child)-1], core.SourceFilesystem, core.ProtectCollectorFailure,
				"directory_not_listed", fmt.Sprintf("could not list %s: %v", path, err), w.now)
		}
	}
	return entries, nil
}

// entryFor builds one entry from an lstat result and reports whether the walk
// may descend into it.
func (w *metadataWalk) entryFor(path string, dirBounded bool) (core.Entry, bool) {
	entry := core.Entry{
		Path:       path,
		Root:       w.root.Path,
		Kind:       core.EntryKindUnknown,
		Class:      core.ClassUnknown,
		ObservedAt: w.now,
	}
	if dirBounded {
		addEvidence(&entry, core.Evidence{
			Source:     core.SourceFilesystem,
			Signal:     "unknown:directory_truncated",
			Detail:     fmt.Sprintf("sibling listing was truncated at %d entries", w.opts.Limits.MaxDirEntries),
			ObservedAt: w.now,
		})
	}
	if w.root.ReportOnly {
		addEvidence(&entry, core.Evidence{
			Source:     core.SourcePolicy,
			Signal:     "report_only_root",
			Detail:     fmt.Sprintf("root %s is report-only", w.root.Path),
			ObservedAt: w.now,
		})
		addProtection(&entry, core.Protection{
			Kind:     core.ProtectPolicyProtected,
			Reason:   fmt.Sprintf("root %s is report-only", w.root.Path),
			Source:   core.SourcePolicy,
			Blocking: true,
		})
	}

	info, err := os.Lstat(path)
	if err != nil {
		w.report.Unknowns++
		w.report.Status = core.CollectorPartial
		addUnknown(&entry, core.SourceFilesystem, core.ProtectCollectorFailure,
			"lstat_failed", fmt.Sprintf("lstat %s: %v", path, err), w.now)
		return entry, false
	}

	mode := info.Mode()
	stat := statOf(info)
	entry.Kind = entryKind(mode)
	entry.SizeBytes = info.Size()
	entry.ModifiedAt = info.ModTime().UTC()
	entry.FilesystemID = core.FilesystemID{Device: stat.Device, Inode: stat.Inode}
	entry.Ownership = core.Ownership{UID: stat.UID, GID: stat.GID, Mode: fmt.Sprintf("%04o", mode.Perm())}
	if stat.Known {
		entry.AccessedAt = stat.AccessedAt
	} else {
		entry.AccessedAt = entry.ModifiedAt
		w.report.Unknowns++
		w.report.Status = core.CollectorPartial
		addUnknown(&entry, core.SourceFilesystem, core.ProtectCollectorFailure,
			"identity_unavailable", "filesystem identity is unavailable on this platform", w.now)
	}
	addEvidence(&entry, core.Evidence{
		Source:     core.SourceFilesystem,
		Signal:     "lstat",
		Detail:     fmt.Sprintf("%s %s identity %s", entry.Kind, entry.Ownership.Mode, entry.FilesystemID),
		ObservedAt: w.now,
	})

	if mode&fs.ModeSymlink != 0 {
		w.resolveSymlink(&entry)
		return entry, false
	}
	if !info.IsDir() {
		return entry, false
	}
	w.recordProjectMarkers(&entry)

	// Mount boundary: a different device means a different filesystem, which
	// the walk does not enter unless the root allows it.
	if stat.Known && stat.Device != w.rootDev {
		addEvidence(&entry, core.Evidence{
			Source:     core.SourceFilesystem,
			Signal:     "mount_boundary",
			Detail:     fmt.Sprintf("device %d differs from root device %d", stat.Device, w.rootDev),
			ObservedAt: w.now,
		})
		if !w.root.CrossFilesystem {
			return entry, false
		}
	}
	// Identity loop guard. The walk never follows symlinks, so a repeated
	// device/inode pair means something stranger than a symlink cycle; stop
	// rather than recurse.
	if _, repeat := w.seen[entry.FilesystemID]; repeat && !entry.FilesystemID.Zero() {
		addUnknown(&entry, core.SourceFilesystem, core.ProtectSymlinkEscape,
			"directory_cycle", fmt.Sprintf("directory identity %s was already visited", entry.FilesystemID), w.now)
		return entry, false
	}
	if !entry.FilesystemID.Zero() {
		w.seen[entry.FilesystemID] = struct{}{}
	}
	return entry, true
}

// recordProjectMarkers notes which project markers a directory contains.
//
// This is one lstat per configured marker, not a directory read: the cost
// is bounded by the marker list, and a default scan stays metadata-only.
// The planner classifies from this evidence rather than touching the disk
// itself.
func (w *metadataWalk) recordProjectMarkers(entry *core.Entry) {
	for _, marker := range w.opts.ProjectMarkers {
		if marker == "" {
			continue
		}
		if _, err := os.Lstat(filepath.Join(entry.Path, marker)); err != nil {
			continue
		}
		addEvidence(entry, core.Evidence{
			Source:     core.SourceFilesystem,
			Signal:     "project_marker",
			Detail:     marker,
			ObservedAt: w.now,
		})
	}
}

// resolveSymlink records the link target and, per the safety contract, treats
// an unresolved or escaping link as ambiguous and therefore protected.
func (w *metadataWalk) resolveSymlink(entry *core.Entry) {
	target, err := os.Readlink(entry.Path)
	if err != nil {
		w.report.Unknowns++
		w.report.Status = core.CollectorPartial
		addUnknown(entry, core.SourceFilesystem, core.ProtectSymlinkEscape,
			"readlink_failed", fmt.Sprintf("readlink %s: %v", entry.Path, err), w.now)
		return
	}
	entry.SymlinkTarget = target
	addEvidence(entry, core.Evidence{
		Source:     core.SourceFilesystem,
		Signal:     "symlink",
		Detail:     "target " + target,
		ObservedAt: w.now,
	})

	if !w.root.FollowSymlinks {
		// Not following is the safe default, but it leaves the real target
		// unknown, so the entry stays protected rather than looking clean.
		addUnknown(entry, core.SourceFilesystem, core.ProtectSymlinkEscape,
			"symlink_not_resolved", fmt.Sprintf("policy does not permit following symlinks under %s", w.root.Path), w.now)
		return
	}

	resolved, err := filepath.EvalSymlinks(entry.Path)
	if err != nil {
		w.report.Unknowns++
		w.report.Status = core.CollectorPartial
		addUnknown(entry, core.SourceFilesystem, core.ProtectSymlinkEscape,
			"symlink_unresolvable", fmt.Sprintf("resolve %s: %v", entry.Path, err), w.now)
		return
	}
	entry.CanonicalPath = resolved
	if !pathWithin(resolved, w.root.Path) {
		addUnknown(entry, core.SourceFilesystem, core.ProtectSymlinkEscape,
			"symlink_escapes_root", fmt.Sprintf("%s resolves to %s, outside root %s", entry.Path, resolved, w.root.Path), w.now)
		return
	}
	addEvidence(entry, core.Evidence{
		Source:     core.SourceFilesystem,
		Signal:     "symlink_resolved",
		Detail:     "canonical " + resolved,
		ObservedAt: w.now,
	})
}

func entryKind(mode fs.FileMode) core.EntryKind {
	switch {
	case mode&fs.ModeSymlink != 0:
		return core.EntryKindSymlink
	case mode.IsDir():
		return core.EntryKindDirectory
	case mode.IsRegular():
		return core.EntryKindFile
	default:
		return core.EntryKindSpecial
	}
}

// boundedNames is a directory listing plus whether it was truncated.
type boundedNames struct {
	names   []string
	bounded bool
}

// readDirNamesBounded lists at most limit names, sorted for determinism.
func readDirNamesBounded(dir string, limit int) (boundedNames, error) {
	f, err := os.Open(dir)
	if err != nil {
		return boundedNames{}, err
	}
	defer f.Close()
	return readDirNamesFromFile(f, limit)
}

// readDirNamesFromFile keeps service listing anchored to the same opened
// directory used for definition reads, even if a parent path is renamed.
func readDirNamesFromFile(f *os.File, limit int) (boundedNames, error) {
	names, err := f.Readdirnames(limit + 1)
	if err != nil && len(names) == 0 {
		if errors.Is(err, io.EOF) {
			return boundedNames{}, nil
		}
		return boundedNames{}, err
	}
	result := boundedNames{names: names}
	if len(names) > limit {
		result.names = names[:limit]
		result.bounded = true
	}
	sort.Strings(result.names)
	return result, nil
}
