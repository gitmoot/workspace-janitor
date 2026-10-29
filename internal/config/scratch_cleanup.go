package config

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// Scratch cleanup defaults and bounds.
const (
	DefaultScratchIdle  = IdleDuration(72 * time.Hour)
	DefaultScratchEvery = IdleDuration(48 * time.Hour)
	minScratchInterval  = 24 * time.Hour
	maxScratchCleanups  = 16
	maxScratchPatterns  = 256
)

// ScratchCleanup is one opt-in scratch directory (for example /tmp) whose
// idle depth-1 entries Janitor removes. Entries matching Skip are never
// touched; entries matching Regenerable are deleted without an archive; every
// other entry is archived, verified, and only then deleted. Sensitive names
// are not configured here: the built-in secret screen and
// protect.name_patterns keep any entry that holds a matching name local.
type ScratchCleanup struct {
	Path string `yaml:"path" json:"path"`
	// Idle is measured from the newest mtime or ctime anywhere in the entry.
	Idle IdleDuration `yaml:"idle" json:"idle"`
	// Every is the shortest interval between two runs started by the cycle.
	Every IdleDuration `yaml:"every" json:"every"`
	// Skip and Regenerable are filepath.Match globs on the entry name.
	Skip        []string                            `yaml:"skip" json:"skip"`
	Regenerable []string                            `yaml:"regenerable" json:"regenerable"`
	Archive     WorkspaceArchiveCategoryDestination `yaml:"archive" json:"archive"`
	// MaxBytesPerRun bounds the bytes one run removes (archived and
	// regenerable together); 0 means no bound.
	MaxBytesPerRun int64 `yaml:"max_bytes_per_run" json:"max_bytes_per_run"`
}

// ScratchCleanupFor returns the configured scratch cleanup of path.
func (p *Policy) ScratchCleanupFor(path string) (ScratchCleanup, bool) {
	for _, scratch := range p.ScratchCleanup {
		if scratch.Path == path {
			return scratch, true
		}
	}
	return ScratchCleanup{}, false
}

// ScratchRefusal names the policy fact that keeps one scratch entry where it
// is: a protected path or a KEEP record at, inside or above it. Empty means
// policy does not refuse it.
func (p *Policy) ScratchRefusal(path string) string {
	for _, protected := range p.Protect.Paths {
		if core.PathsOverlap(path, protected) {
			return fmt.Sprintf("overlaps protect.paths entry %q", protected)
		}
	}
	for _, keep := range p.WorkspaceArchiveKeep {
		if core.PathsOverlap(path, keep.Path) {
			return fmt.Sprintf("workspace_archive_keep %q is kept by %q (%s)", keep.Path, keep.Owner, keep.Reference)
		}
	}
	return ""
}

// MatchesAny reports whether name matches one of the globs.
func MatchesAny(name string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, name); matched {
			return true
		}
	}
	return false
}

func (p *Policy) normalizeScratchCleanup(expand func(string, string) string) {
	for i := range p.ScratchCleanup {
		scratch := &p.ScratchCleanup[i]
		field := fmt.Sprintf("scratch_cleanup[%d]", i)
		scratch.Path = expand(field+".path", scratch.Path)
		if scratch.Archive.Directory != "" {
			scratch.Archive.Directory = expand(field+".archive.directory", scratch.Archive.Directory)
		}
		if scratch.Idle == 0 {
			scratch.Idle = DefaultScratchIdle
		}
		if scratch.Every == 0 {
			scratch.Every = DefaultScratchEvery
		}
		if scratch.Skip == nil {
			scratch.Skip = []string{}
		}
		if scratch.Regenerable == nil {
			scratch.Regenerable = []string{}
		}
	}
	if p.ScratchCleanup == nil {
		p.ScratchCleanup = []ScratchCleanup{}
	}
}

func (p *Policy) validateScratchCleanup(errs *core.FieldErrors) {
	if len(p.ScratchCleanup) == 0 {
		return
	}
	if len(p.ScratchCleanup) > maxScratchCleanups {
		errs.Add("scratch_cleanup", "at most %d scratch directories are allowed", maxScratchCleanups)
	}
	if !p.Collectors.Processes || !core.IsCanonicalPath(p.Collectors.ProcRoot) {
		errs.Add("scratch_cleanup", "requires the process collector and a procfs root; live-use checks cannot be disabled")
	}
	seen := make(map[string]int, len(p.ScratchCleanup))
	for i, scratch := range p.ScratchCleanup {
		field := fmt.Sprintf("scratch_cleanup[%d]", i)
		switch {
		case !core.IsCanonicalPath(scratch.Path) || scratch.Path == "/":
			errs.Add(field+".path", "must be a canonical absolute directory path other than /, got %q", scratch.Path)
		default:
			if first, dup := seen[scratch.Path]; dup {
				errs.Add(field+".path", "duplicates scratch_cleanup[%d].path", first)
			}
			seen[scratch.Path] = i
			p.validateScratchPath(errs, field+".path", scratch.Path)
		}
		if scratch.Idle.Duration() < minScratchInterval {
			errs.Add(field+".idle", "must be at least %s, got %s", IdleDuration(minScratchInterval), scratch.Idle)
		}
		if scratch.Every.Duration() < minScratchInterval {
			errs.Add(field+".every", "must be at least %s, got %s", IdleDuration(minScratchInterval), scratch.Every)
		}
		for _, list := range []struct {
			name     string
			patterns []string
		}{{"skip", scratch.Skip}, {"regenerable", scratch.Regenerable}} {
			if len(list.patterns) > maxScratchPatterns {
				errs.Add(field+"."+list.name, "at most %d patterns are allowed", maxScratchPatterns)
			}
			for j, pattern := range list.patterns {
				if _, err := filepath.Match(pattern, "probe"); pattern == "" || err != nil {
					errs.Add(fmt.Sprintf("%s.%s[%d]", field, list.name, j), "must be a non-empty filepath.Match glob, got %q", pattern)
				}
			}
		}
		if p.validateArchiveDirectory(errs, field+".archive", scratch.Archive.Directory, scratch.Archive.ExpectMountSource, scratch.Archive.ExpectFSType) {
			dir := scratch.Archive.Directory
			for _, root := range p.Roots {
				if core.PathsOverlap(dir, root.Path) {
					errs.Add(field+".archive.directory", "must be outside every inventory root, overlaps %q", root.Path)
				}
			}
			for _, other := range p.ScratchCleanup {
				if core.PathsOverlap(dir, other.Path) {
					errs.Add(field+".archive.directory", "must be outside every scratch directory, overlaps %q", other.Path)
				}
			}
			if rawStateOrCredentialPath(dir) {
				errs.Add(field+".archive.directory", "raw runtime/session stores and credential containers cannot be archive destinations")
			}
		}
		if scratch.MaxBytesPerRun < 0 {
			errs.Add(field+".max_bytes_per_run", "must be zero (no bound) or positive, got %d", scratch.MaxBytesPerRun)
		}
	}
}

// validateScratchPath keeps a scratch directory apart from every other scope
// Janitor acts on, so no entry is ever claimed by two engines.
func (p *Policy) validateScratchPath(errs *core.FieldErrors, field, path string) {
	if rawStateOrCredentialPath(path) {
		errs.Add(field, "raw runtime/session stores and credential containers cannot be scratch directories")
	}
	for _, protected := range p.Protect.Paths {
		if core.PathWithin(path, protected) {
			errs.Add(field, "lies inside protect.paths entry %q", protected)
		}
	}
	for _, keep := range p.WorkspaceArchiveKeep {
		if core.PathWithin(path, keep.Path) {
			errs.Add(field, "lies inside workspace_archive_keep path %q", keep.Path)
		}
	}
	for _, root := range p.Roots {
		if core.PathsOverlap(path, root.Path) {
			errs.Add(field, "must not overlap inventory root %q; that root is already cleaned by plan/quarantine", root.Path)
		}
	}
	for _, scope := range []struct{ what, path string }{
		{"the quarantine directory", p.Retention.QuarantineDir},
		{"Gitmoot's managed state", p.Gitmoot.Home},
	} {
		if scope.path != "" && core.PathsOverlap(path, scope.path) {
			errs.Add(field, "must not overlap %s %q", scope.what, scope.path)
		}
	}
	for _, rule := range p.WorkspaceArchives {
		if core.PathsOverlap(path, rule.Path) || core.PathsOverlap(path, rule.Archive.Directory) {
			errs.Add(field, "must not overlap workspace_archives rule %q", rule.Name)
		}
	}
	for _, category := range p.WorkspaceArchiveCategories {
		if core.PathsOverlap(path, category.Archive.Directory) {
			errs.Add(field, "must not overlap category %q archive directory", category.Name)
		}
	}
	for _, cache := range p.Caches {
		if core.PathsOverlap(path, cache.Path) {
			errs.Add(field, "must not overlap cache rule %q", cache.Name)
		}
	}
}
