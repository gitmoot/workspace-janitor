package config

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"gopkg.in/yaml.v3"
)

const day = 24 * time.Hour

// IdleDuration is a duration written in Go syntax ("720h") or whole days
// ("30d").
type IdleDuration time.Duration

// Duration returns the underlying duration.
func (d IdleDuration) Duration() time.Duration { return time.Duration(d) }

// String renders whole days as "Nd" and anything else in Go syntax.
func (d IdleDuration) String() string {
	if d > 0 && time.Duration(d)%day == 0 {
		return strconv.FormatInt(int64(time.Duration(d)/day), 10) + "d"
	}
	return time.Duration(d).String()
}

func parseIdleDuration(s string) (IdleDuration, error) {
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.ParseInt(days, 10, 32)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid duration %q: use whole days such as \"30d\" or Go syntax such as \"720h\"", s)
		}
		return IdleDuration(time.Duration(n) * day), nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: use whole days such as \"30d\" or Go syntax such as \"720h\"", s)
	}
	return IdleDuration(parsed), nil
}

// UnmarshalYAML decodes a duration string, rejecting non-scalar nodes.
func (d *IdleDuration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: duration must be a string such as \"30d\"", value.Line)
	}
	parsed, err := parseIdleDuration(value.Value)
	if err != nil {
		return fmt.Errorf("line %d: %v", value.Line, err)
	}
	*d = parsed
	return nil
}

// MarshalYAML renders the duration as a string.
func (d IdleDuration) MarshalYAML() (any, error) { return d.String(), nil }

// MarshalJSON renders the duration as a string.
func (d IdleDuration) MarshalJSON() ([]byte, error) { return core.MarshalJSON(d.String()) }

// UnmarshalJSON decodes a duration string.
func (d *IdleDuration) UnmarshalJSON(data []byte) error {
	var s string
	if err := yaml.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := parseIdleDuration(s)
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

// WorkspaceArchiveCategoryKind names one owner-approved class of directories
// Janitor may archive without a per-item workspace_archives rule.
type WorkspaceArchiveCategoryKind string

const (
	// CategoryMergedWorktrees selects linked Git worktrees whose commits are
	// all on remote-tracking branches.
	CategoryMergedWorktrees WorkspaceArchiveCategoryKind = "merged_worktrees"
	// CategoryPushedClones selects standalone (non-bare) Git checkouts whose
	// commits are all on remote-tracking branches.
	CategoryPushedClones WorkspaceArchiveCategoryKind = "pushed_clones"
	// CategoryRootScratch selects non-Git directories directly inside a root.
	CategoryRootScratch WorkspaceArchiveCategoryKind = "root_scratch"
	// CategoryVersionedWork selects non-Git directories directly inside a
	// root whose names match Match and whose version is older than the
	// KeepNewest newest versions present (owner, 2026-11-04: Mac admin work
	// folders beyond the 3 newest versions).
	CategoryVersionedWork WorkspaceArchiveCategoryKind = "versioned_work"
	// CategoryOMPSessions selects idle OMP agent sessions in an
	// ".../.omp/agent/sessions" root (owner, 2026-11-08). A unit is
	// "<project>/<stem>": the session directory and its sibling
	// "<stem>.jsonl", archived, quarantined, restored and expired together
	// (a lone "<stem>.jsonl" is a unit by itself).
	CategoryOMPSessions WorkspaceArchiveCategoryKind = "omp_sessions"
	// CategoryGitmootJobLogs selects idle regular files directly inside a
	// ".../.gitmoot/logs/jobs" root (owner, 2026-11-08).
	CategoryGitmootJobLogs WorkspaceArchiveCategoryKind = "gitmoot_job_logs"
)

// stateRootShapes are the only raw runtime-state directory shapes a
// category may use as a root, each for its own kind.
var stateRootShapes = map[WorkspaceArchiveCategoryKind][]string{
	CategoryOMPSessions:    {".omp", "agent", "sessions"},
	CategoryGitmootJobLogs: {".gitmoot", "logs", "jobs"},
}

// StateStore reports whether the kind archives a raw runtime-state store
// that is otherwise never archived by category (OMP sessions, Gitmoot job
// logs). Only such a kind may name, and is restricted to, its exact root
// shape.
func (k WorkspaceArchiveCategoryKind) StateStore() bool {
	_, ok := stateRootShapes[k]
	return ok
}

// StateRootShape reports whether root is exactly the directory shape the
// state-store kind k is approved for, such as "/root/.omp/agent/sessions",
// with no other raw-state or credential component above it. Every other
// kind, and every other shape, is false.
func (k WorkspaceArchiveCategoryKind) StateRootShape(root string) bool {
	shape, ok := stateRootShapes[k]
	if !ok || !core.IsCanonicalPath(root) {
		return false
	}
	parts := strings.Split(root, "/")
	if len(parts) < len(shape)+2 || !slices.Equal(parts[len(parts)-len(shape):], shape) {
		return false
	}
	return !rawStateOrCredentialPath(strings.Join(parts[:len(parts)-len(shape)], "/"))
}

// UnitDepth is how far below a category root its units lie: 2 for OMP
// sessions ("<project>/<stem>"), 1 for every other kind.
func (k WorkspaceArchiveCategoryKind) UnitDepth() int {
	if k == CategoryOMPSessions {
		return 2
	}
	return 1
}

// ompSessionLog is the transcript suffix of an OMP session.
const ompSessionLog = ".jsonl"

// UnitCompanion is the sibling archived and moved with the unit at path: an
// OMP session directory's "<stem>.jsonl" (present or not). Everything else
// has none.
func (k WorkspaceArchiveCategoryKind) UnitCompanion(path string) string {
	if k != CategoryOMPSessions || strings.HasSuffix(path, ompSessionLog) {
		return ""
	}
	return path + ompSessionLog
}

// UnitMentions are the strings whose presence in a process's command line
// or environment keeps the OMP session at path local: its path (which the
// transcript path extends) and its session id, the text after the last '_'
// of "<timestamp>_<id>". Other kinds rely on descriptors alone.
func (k WorkspaceArchiveCategoryKind) UnitMentions(path string) []string {
	if k != CategoryOMPSessions {
		return nil
	}
	stem := strings.TrimSuffix(path, ompSessionLog)
	mentions := []string{stem}
	base := filepath.Base(stem)
	if i := strings.LastIndexByte(base, '_'); i >= 0 && len(base)-i-1 >= 8 {
		mentions = append(mentions, base[i+1:])
	} else if len(base) >= 8 {
		mentions = append(mentions, base)
	}
	return mentions
}

// ItemRoot is the root that holds path as one of the category's units: the
// grandparent for OMP sessions, the parent otherwise. ok is false when that
// directory is not one of the category's roots.
func (c WorkspaceArchiveCategory) ItemRoot(path string) (string, bool) {
	root := filepath.Dir(path)
	if c.Kind.UnitDepth() == 2 {
		root = filepath.Dir(root)
	}
	return root, slices.Contains(c.Roots, root)
}

// stateStoreUnit reports whether path lies at unit depth in a root of a
// configured state-store category (an OMP session or a Gitmoot job log), and
// that category's kind. The entry type is checked by the category run.
func (p *Policy) stateStoreUnit(path string) (WorkspaceArchiveCategoryKind, bool) {
	for _, category := range p.WorkspaceArchiveCategories {
		if !category.Kind.StateStore() {
			continue
		}
		if _, ok := category.ItemRoot(path); ok {
			return category.Kind, true
		}
	}
	return "", false
}

// GitmootJobLogRoots are the roots of configured gitmoot_job_logs
// categories: the only places inside Gitmoot's protected home whose direct
// regular files may be archived, quarantined and expired, each only through
// its verified category archive.
func (p *Policy) GitmootJobLogRoots() []string {
	var roots []string
	for _, category := range p.WorkspaceArchiveCategories {
		if category.Kind == CategoryGitmootJobLogs {
			roots = append(roots, category.Roots...)
		}
	}
	return roots
}

// GitmootJobLog reports whether path lies directly inside a configured
// gitmoot_job_logs root (the caller checks that it is a regular file).
func (p *Policy) GitmootJobLog(path string) bool {
	return slices.Contains(p.GitmootJobLogRoots(), filepath.Dir(path))
}

// ArchivedGitmootJobLog reports whether path is a Gitmoot job log that an
// active category archive receipt binds: a pinned rule synthesized by
// Janitor for exactly this path. Only such a log may leave Gitmoot's home.
func (p *Policy) ArchivedGitmootJobLog(path string) bool {
	if !p.GitmootJobLog(path) {
		return false
	}
	for _, rule := range p.WorkspaceArchives {
		if rule.Path == path && strings.HasPrefix(rule.Owner, CategoryOwnerPrefix) && rule.LocalExpiryEnabled {
			return true
		}
	}
	return false
}

// DefaultIdle is the idle period used when a category sets none.
func (k WorkspaceArchiveCategoryKind) DefaultIdle() time.Duration {
	if k == CategoryVersionedWork {
		return day
	}
	if k == CategoryMergedWorktrees || k.StateStore() {
		return 14 * 24 * time.Hour
	}
	return 30 * 24 * time.Hour
}

// MinIdle is the shortest idle period the owner approved for the kind
// (owner, 2026-10-29: merged worktrees 7d, other kinds 14d; 2026-11-08: OMP
// sessions and Gitmoot job logs 1d, the guard of the owner's manual session
// archives).
func (k WorkspaceArchiveCategoryKind) MinIdle() time.Duration {
	// Versioned work is selected by version, not age; one quiet day still
	// keeps a folder that is being written right now.
	if k == CategoryVersionedWork || k.StateStore() {
		return day
	}
	if k == CategoryMergedWorktrees {
		return 7 * 24 * time.Hour
	}
	return 14 * 24 * time.Hour
}

// Valid reports whether k is a known category kind.
func (k WorkspaceArchiveCategoryKind) Valid() bool {
	switch k {
	case CategoryMergedWorktrees, CategoryPushedClones, CategoryRootScratch, CategoryVersionedWork,
		CategoryOMPSessions, CategoryGitmootJobLogs:
		return true
	}
	return false
}

// Category defaults and bounds.
const (
	DefaultCategoryMaxItemsPerCycle = 20
	MaxCategoryItemsPerCycle        = 200
	DefaultCategoryMaxBytesPerItem  = int64(10) << 30
	maxWorkspaceArchiveCategories   = 16
)

// WorkspaceArchiveCategory is an owner-approved, opt-in archive category.
// Janitor itself selects matching depth-1 entries of Roots that have been
// idle for Idle, archives them copy-only and verified (the same Create as
// workspace_archives), and records the pinned manifest in its state database,
// never in this policy. Recorded archives then follow the ordinary
// workspace_archives Bind -> quarantine -> expiry flow with LocalRetention.
type WorkspaceArchiveCategory struct {
	Name  string                       `yaml:"name" json:"name"`
	Kind  WorkspaceArchiveCategoryKind `yaml:"kind" json:"kind"`
	Roots []string                     `yaml:"roots" json:"roots"`
	// Idle is measured from the newest modification anywhere in the tree.
	Idle    IdleDuration                        `yaml:"idle" json:"idle"`
	Archive WorkspaceArchiveCategoryDestination `yaml:"archive" json:"archive"`
	// LocalRetention is none, 30d or 90d after the archive was created. none
	// proposes quarantine as soon as the archive binds the local tree; the
	// quarantine retention still applies before deletion.
	LocalRetention   core.Retention `yaml:"local_retention" json:"local_retention"`
	MaxItemsPerCycle int            `yaml:"max_items_per_cycle" json:"max_items_per_cycle"`
	MaxBytesPerItem  int64          `yaml:"max_bytes_per_item" json:"max_bytes_per_item"`
	// Match and KeepNewest apply to versioned_work only. Match is a base-name
	// glob with exactly one '*'; the leading digits of the text it matches
	// are the version (admin-v*-work: "admin-v0116-reset-r5-work" is 116).
	// Every folder of the KeepNewest highest versions is kept.
	Match      string `yaml:"match,omitempty" json:"match,omitempty"`
	KeepNewest int    `yaml:"keep_newest,omitempty" json:"keep_newest,omitempty"`
}

// Version returns the version a versioned_work Match assigns to name, and
// whether name matches with a numeric version at all.
func (c WorkspaceArchiveCategory) Version(name string) (int64, bool) {
	prefix, suffix, ok := strings.Cut(c.Match, "*")
	if !ok || len(name) < len(prefix)+len(suffix) || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return 0, false
	}
	middle := name[len(prefix) : len(name)-len(suffix)]
	digits := 0
	for digits < len(middle) && middle[digits] >= '0' && middle[digits] <= '9' {
		digits++
	}
	if digits == 0 || digits > 18 {
		return 0, false
	}
	version, err := strconv.ParseInt(middle[:digits], 10, 64)
	return version, err == nil
}

// WorkspaceArchiveCategoryDestination is the category's archive directory.
// Manifests are never pinned here: Janitor records them in its state.
type WorkspaceArchiveCategoryDestination struct {
	Directory         string `yaml:"directory" json:"directory"`
	ExpectMountSource string `yaml:"expect_mount_source" json:"expect_mount_source"`
	ExpectFSType      string `yaml:"expect_fstype" json:"expect_fstype"`
}

// categoryName is shorter than a rule name so synthesized item names
// (category, base name and hash) stay within the rule name bound.
var categoryName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$`)

// WorkspaceArchiveCategory returns the named category, if configured.
func (p *Policy) WorkspaceArchiveCategory(name string) (WorkspaceArchiveCategory, bool) {
	for _, category := range p.WorkspaceArchiveCategories {
		if category.Name == name {
			return category, true
		}
	}
	return WorkspaceArchiveCategory{}, false
}

// CategoryArchiveRefusals lists the policy facts that keep path out of every
// archive category: KEEP records, protected paths, explicit release rules,
// report-only roots, configured roots and other cleanup or archive scopes it
// overlaps, and raw runtime/credential stores. Live evidence (processes,
// Git, Gitmoot, services) is checked separately by the collectors and the
// safety engine. The only raw-state paths a category may archive are the
// units of an omp_sessions or gitmoot_job_logs root; a Gitmoot job log is
// also exempt from Gitmoot's own home protection, and from nothing else.
func (p *Policy) CategoryArchiveRefusals(path string) []string {
	var out []string
	if !core.IsCanonicalPath(path) || path == "/" {
		return []string{fmt.Sprintf("%q is not a canonical directory path", path)}
	}
	stateKind, stateUnit := p.stateStoreUnit(path)
	gitmootLog := stateUnit && stateKind == CategoryGitmootJobLogs
	if strings.HasPrefix(filepath.Base(path), ".") {
		out = append(out, "dot-named entries are tool or configuration state, never category items")
	}
	if !stateUnit && rawStateOrCredentialPath(path) {
		out = append(out, "raw runtime/session stores and credential containers are never archived by category")
	}
	for _, keep := range p.WorkspaceArchiveKeep {
		if core.PathsOverlap(path, keep.Path) {
			out = append(out, fmt.Sprintf("unresolved KEEP: workspace_archive_keep %q is kept by %q (%s)", keep.Path, keep.Owner, keep.Reference))
		}
	}
	for _, protected := range p.Protect.Paths {
		if gitmootLog && protected == p.Gitmoot.Home {
			continue
		}
		if core.PathsOverlap(path, protected) {
			out = append(out, fmt.Sprintf("overlaps protect.paths entry %q", protected))
		}
	}
	for _, rule := range p.WorkspaceArchives {
		if core.PathsOverlap(path, rule.Path) && !strings.HasPrefix(rule.Owner, CategoryOwnerPrefix) {
			out = append(out, fmt.Sprintf("overlaps explicit workspace_archives rule %q", rule.Name))
		}
	}
	for _, export := range p.EvidenceExports {
		if core.PathsOverlap(path, export.Path) || core.PathsOverlap(path, export.SourceContainer) {
			out = append(out, fmt.Sprintf("overlaps evidence_exports rule %q", export.Name))
		}
	}
	for _, root := range p.Roots {
		if core.PathWithin(root.Path, path) {
			out = append(out, fmt.Sprintf("contains inventory root %q", root.Path))
		} else if root.ReportOnly && core.PathsOverlap(path, root.Path) {
			out = append(out, fmt.Sprintf("overlaps report_only root %q", root.Path))
		}
	}
	for _, cache := range p.Caches {
		if core.PathsOverlap(path, cache.Path) {
			out = append(out, fmt.Sprintf("overlaps cache rule %q", cache.Name))
		}
	}
	for _, scope := range []struct{ what, path string }{
		{"the quarantine directory", p.Retention.QuarantineDir},
		{"Gitmoot's managed state", p.Gitmoot.Home},
	} {
		if scope.path == "" || gitmootLog && scope.path == p.Gitmoot.Home {
			continue
		}
		if core.PathsOverlap(path, scope.path) {
			out = append(out, "overlaps "+scope.what)
		}
	}
	for _, category := range p.WorkspaceArchiveCategories {
		if core.PathsOverlap(path, category.Archive.Directory) {
			out = append(out, fmt.Sprintf("overlaps category %q archive directory", category.Name))
		}
		for _, root := range category.Roots {
			if core.PathWithin(root, path) {
				out = append(out, fmt.Sprintf("contains category %q root %q", category.Name, root))
			}
		}
	}
	if p.Report.ArchivesReleases() {
		if core.PathsOverlap(path, p.Report.Archive.Directory) {
			out = append(out, "overlaps the report archive directory")
		}
		for _, root := range p.Report.Roots {
			if core.PathWithin(root, path) {
				out = append(out, fmt.Sprintf("contains report root %q", root))
			}
		}
	}
	return out
}

// CategoryOwnerPrefix marks rules Janitor synthesized from its own category
// archive records rather than read from the policy file.
const CategoryOwnerPrefix = "category:"

func (p *Policy) normalizeWorkspaceArchiveCategories(expand func(string, string) string) {
	for i := range p.WorkspaceArchiveCategories {
		category := &p.WorkspaceArchiveCategories[i]
		field := fmt.Sprintf("workspace_archive_categories[%d]", i)
		for j := range category.Roots {
			category.Roots[j] = expand(fmt.Sprintf("%s.roots[%d]", field, j), category.Roots[j])
		}
		if category.Roots == nil {
			category.Roots = []string{}
		}
		if category.Archive.Directory != "" {
			category.Archive.Directory = expand(field+".archive.directory", category.Archive.Directory)
		}
		if category.Idle == 0 && category.Kind.Valid() {
			category.Idle = IdleDuration(category.Kind.DefaultIdle())
		}
		if category.LocalRetention == "" {
			category.LocalRetention = core.Retention30Days
		}
		if category.MaxItemsPerCycle == 0 {
			category.MaxItemsPerCycle = DefaultCategoryMaxItemsPerCycle
		}
		if category.MaxBytesPerItem == 0 {
			category.MaxBytesPerItem = DefaultCategoryMaxBytesPerItem
		}
	}
	if p.WorkspaceArchiveCategories == nil {
		p.WorkspaceArchiveCategories = []WorkspaceArchiveCategory{}
	}
}

func (p *Policy) validateWorkspaceArchiveCategories(errs *core.FieldErrors) {
	if len(p.WorkspaceArchiveCategories) == 0 {
		return
	}
	if len(p.WorkspaceArchiveCategories) > maxWorkspaceArchiveCategories {
		errs.Add("workspace_archive_categories", "at most %d categories are allowed", maxWorkspaceArchiveCategories)
	}
	if !p.Collectors.Processes || !p.Collectors.Git || !p.Collectors.Services {
		errs.Add("workspace_archive_categories", "requires the Git, process and service collectors; live-use and publication checks cannot be disabled")
	}
	names := make(map[string]int, len(p.WorkspaceArchiveCategories))
	kindRoots := make(map[string]int)
	for i, category := range p.WorkspaceArchiveCategories {
		field := fmt.Sprintf("workspace_archive_categories[%d]", i)
		if !categoryName.MatchString(category.Name) {
			errs.Add(field+".name", "must be 1-48 letters, digits, '_' or '-' starting with a letter or digit, got %q", category.Name)
		} else if first, dup := names[category.Name]; dup {
			errs.Add(field+".name", "duplicates workspace_archive_categories[%d].name %q", first, category.Name)
		} else {
			names[category.Name] = i
		}
		if !category.Kind.Valid() {
			errs.Add(field+".kind", "must be merged_worktrees, pushed_clones, root_scratch, versioned_work, omp_sessions or gitmoot_job_logs, got %q", category.Kind)
		} else if category.Idle.Duration() < category.Kind.MinIdle() {
			errs.Add(field+".idle", "must be at least %s for %s, got %s", IdleDuration(category.Kind.MinIdle()), category.Kind, category.Idle)
		}
		if category.Kind == CategoryVersionedWork {
			if strings.Count(category.Match, "*") != 1 || strings.ContainsAny(category.Match, "/?[\\") || category.Match == "*" {
				errs.Add(field+".match", "must be a base-name pattern with exactly one '*' and a fixed prefix or suffix, got %q", category.Match)
			}
			if category.KeepNewest < 1 || category.KeepNewest > 100 {
				errs.Add(field+".keep_newest", "must be between 1 and 100, got %d", category.KeepNewest)
			}
		} else if category.Match != "" || category.KeepNewest != 0 {
			errs.Add(field, "match and keep_newest apply to versioned_work only")
		}
		if len(category.Roots) == 0 {
			errs.Add(field+".roots", "must name at least one configured inventory root")
		}
		for j, root := range category.Roots {
			rootField := fmt.Sprintf("%s.roots[%d]", field, j)
			p.validateCategoryRoot(errs, rootField, root, category.Kind)
			key := string(category.Kind) + "\x00" + root
			if first, dup := kindRoots[key]; dup {
				errs.Add(rootField, "duplicates workspace_archive_categories[%d]: one %s category per root", first, category.Kind)
			} else {
				kindRoots[key] = i
			}
		}
		if p.validateArchiveDirectory(errs, field+".archive", category.Archive.Directory, category.Archive.ExpectMountSource, category.Archive.ExpectFSType) {
			// Category roots are inventory roots, so this also keeps the
			// archive out of every category's selection.
			for _, root := range p.Roots {
				if core.PathsOverlap(category.Archive.Directory, root.Path) {
					errs.Add(field+".archive.directory", "must be outside every inventory root, overlaps %q", root.Path)
				}
			}
			if rawStateOrCredentialPath(category.Archive.Directory) {
				errs.Add(field+".archive.directory", "raw runtime/session stores and credential containers cannot be archive destinations")
			}
		}
		switch category.LocalRetention {
		case core.RetentionNone, core.Retention30Days, core.Retention90Days:
		default:
			errs.Add(field+".local_retention", "must be none, 30d or 90d, got %q", category.LocalRetention)
		}
		if category.MaxItemsPerCycle < 1 || category.MaxItemsPerCycle > MaxCategoryItemsPerCycle {
			errs.Add(field+".max_items_per_cycle", "must be between 1 and %d, got %d", MaxCategoryItemsPerCycle, category.MaxItemsPerCycle)
		}
		if category.MaxBytesPerItem <= 0 {
			errs.Add(field+".max_bytes_per_item", "must be greater than zero, got %d", category.MaxBytesPerItem)
		}
	}
}

// validateCategoryRoot requires an exact, mutable inventory root that is not
// itself protected or kept. A raw runtime-state root is refused, except the
// exact store shape of an omp_sessions or gitmoot_job_logs kind; only a
// Gitmoot job-log root may lie inside Gitmoot's own home protection.
func (p *Policy) validateCategoryRoot(errs *core.FieldErrors, field, root string, kind WorkspaceArchiveCategoryKind) {
	if !core.IsCanonicalPath(root) || root == "/" {
		errs.Add(field, "must be a canonical absolute directory path other than /, got %q", root)
		return
	}
	stateRoot := kind.StateRootShape(root)
	if kind.StateStore() && !stateRoot {
		shape := strings.Join(stateRootShapes[kind], "/")
		errs.Add(field, "%s roots must be exactly a .../%s directory, got %q", kind, shape, root)
	}
	configured := false
	for _, candidate := range p.Roots {
		if candidate.Path != root {
			continue
		}
		configured = true
		if candidate.ReportOnly {
			errs.Add(field, "is a report_only root")
		}
		if max(candidate.MaxDepth, 1) < kind.UnitDepth() {
			errs.Add(field, "%s units lie %d levels below the root; its inventory root needs max_depth of at least %d", kind, kind.UnitDepth(), kind.UnitDepth())
		}
	}
	if !configured {
		errs.Add(field, "must be a configured inventory root, got %q", root)
	}
	for _, protected := range p.Protect.Paths {
		if stateRoot && kind == CategoryGitmootJobLogs && protected == p.Gitmoot.Home {
			continue
		}
		if core.PathWithin(root, protected) {
			errs.Add(field, "lies inside protect.paths entry %q", protected)
		}
	}
	for _, keep := range p.WorkspaceArchiveKeep {
		if core.PathWithin(root, keep.Path) {
			errs.Add(field, "lies inside workspace_archive_keep path %q", keep.Path)
		}
	}
	if !stateRoot && rawStateOrCredentialPath(root) {
		errs.Add(field, "raw runtime/session stores and credential containers cannot be category roots")
	}
}
