package config

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// StaleReleaseAction says what Janitor does with an item its owner released
// in reply to the stale-workspace report.
type StaleReleaseAction string

const (
	// StaleReleaseNone records the release and lists it for the operator.
	StaleReleaseNone StaleReleaseAction = "none"
	// StaleReleaseArchive sends a released item through the category archive
	// path on the next cycle: verified copy, pinned receipt, Bind, quarantine.
	StaleReleaseArchive StaleReleaseAction = "archive"
)

// ReportReleaseCategory is the reserved category name of archives created for
// released report items. Their receipts live with the category receipts.
const ReportReleaseCategory = "report-release"

// UnknownOwner is the owner of a report entry no registration or producer
// evidence attributes. It is never a role and never means disposable.
const UnknownOwner = "unknown"

// Stale report defaults and bounds.
const (
	DefaultStaleReportIdle = IdleDuration(14 * 24 * time.Hour)
	minStaleReportIdle     = 24 * time.Hour
)

var roleName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ValidRole reports whether role is a routable role name. "unknown" is the
// explicit no-owner group, never a role.
func ValidRole(role string) bool { return roleName.MatchString(role) && role != UnknownOwner }

// StaleReport is the opt-in weekly stale-workspace report: depth-1 entries of
// Roots unchanged for Idle and not in use, grouped by owning role. Owners
// reply release or keep; a release is archived only when ReleaseAction is
// archive, through the same verified, pinned path as archive categories.
type StaleReport struct {
	Enabled bool     `yaml:"enabled" json:"enabled"`
	Roots   []string `yaml:"roots" json:"roots"`
	// Idle is measured from the newest modification anywhere in the tree.
	Idle IdleDuration `yaml:"idle" json:"idle"`
	// CoordinatorRole receives every entry whose owner is unknown and is the
	// only role that may reply for them.
	CoordinatorRole string             `yaml:"coordinator_role" json:"coordinator_role"`
	ReleaseAction   StaleReleaseAction `yaml:"release_action" json:"release_action"`
	// Archive, LocalRetention and the per-cycle and per-item bounds apply
	// only to release_action archive, exactly as for archive categories.
	Archive          WorkspaceArchiveCategoryDestination `yaml:"archive" json:"archive"`
	LocalRetention   core.Retention                      `yaml:"local_retention" json:"local_retention"`
	MaxItemsPerCycle int                                 `yaml:"max_items_per_cycle" json:"max_items_per_cycle"`
	MaxBytesPerItem  int64                               `yaml:"max_bytes_per_item" json:"max_bytes_per_item"`
}

func defaultStaleReport() StaleReport {
	return StaleReport{
		Roots:            []string{},
		Idle:             DefaultStaleReportIdle,
		ReleaseAction:    StaleReleaseNone,
		LocalRetention:   core.Retention30Days,
		MaxItemsPerCycle: DefaultCategoryMaxItemsPerCycle,
		MaxBytesPerItem:  DefaultCategoryMaxBytesPerItem,
	}
}

// ArchivesReleases reports whether released items are archived by the cycle.
func (r StaleReport) ArchivesReleases() bool {
	return r.Enabled && r.ReleaseAction == StaleReleaseArchive
}

// ReleaseCategory is the archive category a released item of kind is
// archived and bound under. It exists only while releases are archived.
func (r StaleReport) ReleaseCategory(kind WorkspaceArchiveCategoryKind) (WorkspaceArchiveCategory, bool) {
	if !r.ArchivesReleases() || !kind.Valid() {
		return WorkspaceArchiveCategory{}, false
	}
	return WorkspaceArchiveCategory{
		Name: ReportReleaseCategory, Kind: kind, Roots: r.Roots, Idle: r.Idle, Archive: r.Archive,
		LocalRetention: r.LocalRetention, MaxItemsPerCycle: r.MaxItemsPerCycle, MaxBytesPerItem: r.MaxBytesPerItem,
	}, true
}

// ArchiveCategory resolves a category receipt's category: a configured
// category, or the release category of the stale report.
func (p *Policy) ArchiveCategory(name, kind string) (WorkspaceArchiveCategory, bool) {
	if name == ReportReleaseCategory {
		return p.Report.ReleaseCategory(WorkspaceArchiveCategoryKind(kind))
	}
	return p.WorkspaceArchiveCategory(name)
}

// HasArchiveCategories reports whether any category receipt can carry local
// expiry authority under this policy.
func (p *Policy) HasArchiveCategories() bool {
	return len(p.WorkspaceArchiveCategories) != 0 || p.Report.ArchivesReleases()
}

// StaleReportExclusion names the policy decision that already settles path,
// so the stale report does not ask its owner again: a protected path, a KEEP
// record, an explicit archive, export or cache rule, Janitor's or Gitmoot's
// own state, or tool configuration. Empty means the report may list it.
func (p *Policy) StaleReportExclusion(path string) string {
	if strings.HasPrefix(filepath.Base(path), ".") {
		return "dot-named entries are tool or configuration state"
	}
	if rawStateOrCredentialPath(path) {
		return "raw runtime/session stores and credential containers"
	}
	for _, keep := range p.WorkspaceArchiveKeep {
		if core.PathsOverlap(path, keep.Path) {
			return fmt.Sprintf("workspace_archive_keep %q by %q", keep.Path, keep.Owner)
		}
	}
	for _, protected := range p.Protect.Paths {
		if core.PathsOverlap(path, protected) {
			return fmt.Sprintf("protect.paths entry %q", protected)
		}
	}
	for _, rule := range p.WorkspaceArchives {
		if core.PathsOverlap(path, rule.Path) && !strings.HasPrefix(rule.Owner, CategoryOwnerPrefix) {
			return fmt.Sprintf("explicit workspace_archives rule %q", rule.Name)
		}
	}
	for _, export := range p.EvidenceExports {
		if core.PathsOverlap(path, export.Path) || core.PathsOverlap(path, export.SourceContainer) {
			return fmt.Sprintf("evidence_exports rule %q", export.Name)
		}
	}
	for _, cache := range p.Caches {
		if core.PathsOverlap(path, cache.Path) {
			return fmt.Sprintf("cache rule %q", cache.Name)
		}
	}
	for _, scope := range []struct{ what, path string }{
		{"the quarantine directory", p.Retention.QuarantineDir},
		{"Gitmoot's managed state", p.Gitmoot.Home},
		{"the report archive directory", p.Report.Archive.Directory},
	} {
		if scope.path != "" && core.PathsOverlap(path, scope.path) {
			return scope.what
		}
	}
	for _, category := range p.WorkspaceArchiveCategories {
		if core.PathsOverlap(path, category.Archive.Directory) {
			return fmt.Sprintf("category %q archive directory", category.Name)
		}
	}
	return ""
}

func (p *Policy) normalizeStaleReport(expand func(string, string) string) {
	r := &p.Report
	for i := range r.Roots {
		r.Roots[i] = expand(fmt.Sprintf("report.roots[%d]", i), r.Roots[i])
	}
	if r.Roots == nil {
		r.Roots = []string{}
	}
	if r.Archive.Directory != "" {
		r.Archive.Directory = expand("report.archive.directory", r.Archive.Directory)
	}
}

func (p *Policy) validateStaleReport(errs *core.FieldErrors) {
	r := p.Report
	switch r.ReleaseAction {
	case StaleReleaseNone, StaleReleaseArchive:
	default:
		errs.Add("report.release_action", "must be none or archive, got %q", r.ReleaseAction)
	}
	for i, category := range p.WorkspaceArchiveCategories {
		if category.Name == ReportReleaseCategory {
			errs.Add(fmt.Sprintf("workspace_archive_categories[%d].name", i), "%q is reserved for archives of released report items", ReportReleaseCategory)
		}
	}
	if r.Idle.Duration() < minStaleReportIdle {
		errs.Add("report.idle", "must be at least %s, got %s", IdleDuration(minStaleReportIdle), r.Idle)
	}
	if !r.Enabled {
		if r.ReleaseAction == StaleReleaseArchive {
			errs.Add("report.release_action", "archive requires report.enabled")
		}
		return
	}
	if !ValidRole(r.CoordinatorRole) {
		errs.Add("report.coordinator_role", "must name the role that receives unknown-owner entries: 1-64 letters, digits, '.', '_' or '-' (not %q), got %q", UnknownOwner, r.CoordinatorRole)
	}
	if len(r.Roots) == 0 {
		errs.Add("report.roots", "must name at least one configured inventory root")
	}
	seen := make(map[string]int, len(r.Roots))
	for i, root := range r.Roots {
		field := fmt.Sprintf("report.roots[%d]", i)
		if first, dup := seen[root]; dup {
			errs.Add(field, "duplicates report.roots[%d]", first)
			continue
		}
		seen[root] = i
		if r.ReleaseAction == StaleReleaseArchive {
			// Released items are archived from these roots: hold them to
			// the category root rules.
			p.validateCategoryRoot(errs, field, root)
			continue
		}
		configured := false
		for _, candidate := range p.Roots {
			configured = configured || candidate.Path == root
		}
		if !core.IsCanonicalPath(root) || root == "/" {
			errs.Add(field, "must be a canonical absolute directory path other than /, got %q", root)
		} else if !configured {
			errs.Add(field, "must be a configured inventory root, got %q", root)
		}
	}
	if r.ReleaseAction != StaleReleaseArchive {
		return
	}
	if !p.Collectors.Processes || !p.Collectors.Git || !p.Collectors.Services {
		errs.Add("report.release_action", "archive requires the Git, process and service collectors; live-use and publication checks cannot be disabled")
	}
	if p.validateArchiveDirectory(errs, "report.archive", r.Archive.Directory, r.Archive.ExpectMountSource, r.Archive.ExpectFSType) {
		for _, root := range p.Roots {
			if core.PathsOverlap(r.Archive.Directory, root.Path) {
				errs.Add("report.archive.directory", "must be outside every inventory root, overlaps %q", root.Path)
			}
		}
		if rawStateOrCredentialPath(r.Archive.Directory) {
			errs.Add("report.archive.directory", "raw runtime/session stores and credential containers cannot be archive destinations")
		}
	}
	switch r.LocalRetention {
	case core.RetentionNone, core.Retention30Days, core.Retention90Days:
	default:
		errs.Add("report.local_retention", "must be none, 30d or 90d, got %q", r.LocalRetention)
	}
	if r.MaxItemsPerCycle < 1 || r.MaxItemsPerCycle > MaxCategoryItemsPerCycle {
		errs.Add("report.max_items_per_cycle", "must be between 1 and %d, got %d", MaxCategoryItemsPerCycle, r.MaxItemsPerCycle)
	}
	if r.MaxBytesPerItem <= 0 {
		errs.Add("report.max_bytes_per_item", "must be greater than zero, got %d", r.MaxBytesPerItem)
	}
}
