package config

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// WorkspaceArchiveRule names one released directory whose owner approved a
// copy-only verified archive. It never authorizes removing the directory:
// local removal stays with the ordinary quarantine and expiry engine.
type WorkspaceArchiveRule struct {
	Name    string `yaml:"name" json:"name"`
	Path    string `yaml:"path" json:"path"`
	Owner   string `yaml:"owner" json:"owner"`
	Release string `yaml:"release" json:"release"`
	// DependentRoots are scanned for gitdir files, object alternates and
	// symlinks that depend on Path. Empty means every inventory root.
	DependentRoots []string                    `yaml:"dependent_roots" json:"dependent_roots"`
	Archive        WorkspaceArchiveDestination `yaml:"archive" json:"archive"`
}

// WorkspaceArchiveDestination is an existing, independently protected
// directory. Expected mount facts are optional; when set, a mismatch or an
// unmounted destination refuses the archive instead of writing locally.
type WorkspaceArchiveDestination struct {
	Directory         string `yaml:"directory" json:"directory"`
	ExpectMountSource string `yaml:"expect_mount_source" json:"expect_mount_source"`
	ExpectFSType      string `yaml:"expect_fstype" json:"expect_fstype"`
	Manifest          string `yaml:"manifest" json:"manifest"`
	ManifestSHA256    string `yaml:"manifest_sha256" json:"manifest_sha256"`
}

// WorkspaceArchiveKeep records an owner's KEEP decision. Any workspace archive
// at, inside or containing a kept path is an unresolved KEEP/release conflict;
// only removing the keep record (the custodian's resolution) clears it.
type WorkspaceArchiveKeep struct {
	Path      string `yaml:"path" json:"path"`
	Owner     string `yaml:"owner" json:"owner"`
	Reference string `yaml:"reference" json:"reference"`
}

// workspaceArchiveName keeps archive file names plain, so a rule name can
// never escape or alias the archive directory.
var workspaceArchiveName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// WorkspaceArchiveManifestPath is the only manifest location a rule may pin.
func WorkspaceArchiveManifestPath(rule WorkspaceArchiveRule) string {
	return filepath.Join(rule.Archive.Directory, rule.Name+".manifest.json")
}

func (p *Policy) normalizeWorkspaceArchives(expand func(string, string) string) {
	for i := range p.WorkspaceArchives {
		rule := &p.WorkspaceArchives[i]
		field := fmt.Sprintf("workspace_archives[%d]", i)
		rule.Path = expand(field+".path", rule.Path)
		rule.Archive.Directory = expand(field+".archive.directory", rule.Archive.Directory)
		if rule.Archive.Manifest != "" {
			rule.Archive.Manifest = expand(field+".archive.manifest", rule.Archive.Manifest)
		}
		for j := range rule.DependentRoots {
			rule.DependentRoots[j] = expand(fmt.Sprintf("%s.dependent_roots[%d]", field, j), rule.DependentRoots[j])
		}
		if rule.DependentRoots == nil {
			rule.DependentRoots = []string{}
		}
	}
	for i := range p.WorkspaceArchiveKeep {
		p.WorkspaceArchiveKeep[i].Path = expand(fmt.Sprintf("workspace_archive_keep[%d].path", i), p.WorkspaceArchiveKeep[i].Path)
	}
	if p.WorkspaceArchives == nil {
		p.WorkspaceArchives = []WorkspaceArchiveRule{}
	}
	if p.WorkspaceArchiveKeep == nil {
		p.WorkspaceArchiveKeep = []WorkspaceArchiveKeep{}
	}
}

func (p *Policy) validateWorkspaceArchives(errs *core.FieldErrors) {
	if len(p.WorkspaceArchives) > 64 {
		errs.Add("workspace_archives", "at most 64 workspace archives are allowed")
	}
	if len(p.WorkspaceArchives) > 0 && !p.Collectors.Processes {
		errs.Add("workspace_archives", "requires the process collector; live-use checks cannot be disabled")
	}
	for i, keep := range p.WorkspaceArchiveKeep {
		field := fmt.Sprintf("workspace_archive_keep[%d]", i)
		if !core.IsCanonicalPath(keep.Path) {
			errs.Add(field+".path", "must be a canonical absolute path, got %q", keep.Path)
		}
		if strings.TrimSpace(keep.Owner) == "" || strings.TrimSpace(keep.Reference) == "" {
			errs.Add(field, "requires the keeping owner and a reference to the KEEP decision")
		}
	}
	names := make(map[string]int, len(p.WorkspaceArchives))
	for i, rule := range p.WorkspaceArchives {
		field := fmt.Sprintf("workspace_archives[%d]", i)
		if !workspaceArchiveName.MatchString(rule.Name) {
			errs.Add(field+".name", "must be 1-128 letters, digits, '.', '_' or '-' starting with a letter or digit, got %q", rule.Name)
		} else if first, dup := names[rule.Name]; dup {
			errs.Add(field+".name", "duplicates workspace_archives[%d].name %q", first, rule.Name)
		} else {
			names[rule.Name] = i
		}
		if strings.TrimSpace(rule.Owner) == "" || strings.TrimSpace(rule.Release) == "" {
			errs.Add(field, "requires the releasing owner and a release reference")
		}
		if !core.IsCanonicalPath(rule.Path) || rule.Path == "/" {
			errs.Add(field+".path", "must be a canonical absolute directory path, got %q", rule.Path)
		} else {
			p.validateWorkspaceArchiveSource(errs, i, field, rule)
		}
		for j, root := range rule.DependentRoots {
			if !core.IsCanonicalPath(root) {
				errs.Add(fmt.Sprintf("%s.dependent_roots[%d]", field, j), "must be a canonical absolute path, got %q", root)
			}
		}
		if rawStateOrCredentialPath(rule.Path) || rawStateOrCredentialPath(rule.Archive.Directory) {
			errs.Add(field, "raw runtime/session stores and credential containers cannot be workspace archive sources or destinations")
		}
		p.validateWorkspaceArchiveDestination(errs, field, rule)
	}
}

// validateWorkspaceArchiveSource refuses every path whose release is not
// exclusive and uncontested.
func (p *Policy) validateWorkspaceArchiveSource(errs *core.FieldErrors, index int, field string, rule WorkspaceArchiveRule) {
	for j := range index {
		if other := p.WorkspaceArchives[j]; core.PathsOverlap(rule.Path, other.Path) {
			errs.Add(field+".path", "is the same as or overlaps workspace_archives[%d].path %q; one path needs exactly one release", j, other.Path)
		}
	}
	inRoot := false
	for _, root := range p.Roots {
		inRoot = inRoot || (rule.Path != root.Path && core.PathWithin(rule.Path, root.Path))
		if root.ReportOnly && core.PathsOverlap(rule.Path, root.Path) {
			errs.Add(field+".path", "overlaps report_only root %q", root.Path)
		}
	}
	if !inRoot {
		errs.Add(field+".path", "must be inside a configured inventory root")
	}
	for _, protected := range p.Protect.Paths {
		if core.PathsOverlap(rule.Path, protected) {
			errs.Add(field+".path", "overlaps protect.paths entry %q", protected)
		}
	}
	for j, keep := range p.WorkspaceArchiveKeep {
		if core.PathsOverlap(rule.Path, keep.Path) {
			errs.Add(field+".path", "unresolved KEEP/release conflict: workspace_archive_keep[%d] %q is kept by %q (%s); only the custodian can resolve it", j, keep.Path, keep.Owner, keep.Reference)
		}
	}
}

func (p *Policy) validateWorkspaceArchiveDestination(errs *core.FieldErrors, field string, rule WorkspaceArchiveRule) {
	dir := rule.Archive.Directory
	if !core.IsCanonicalPath(dir) || dir == "/" {
		errs.Add(field+".archive.directory", "must be a canonical absolute directory path, got %q", dir)
		return
	}
	for _, other := range p.WorkspaceArchives {
		if core.PathsOverlap(dir, other.Path) {
			errs.Add(field+".archive.directory", "overlaps workspace archive source %q", other.Path)
		}
	}
	for _, export := range p.EvidenceExports {
		if core.PathsOverlap(dir, export.SourceContainer) {
			errs.Add(field+".archive.directory", "overlaps an evidence export source container")
		}
	}
	if core.PathsOverlap(dir, p.Retention.QuarantineDir) {
		errs.Add(field+".archive.directory", "archive cannot share a cleanup receipt container")
	}
	if core.PathsOverlap(dir, p.Gitmoot.Home) {
		errs.Add(field+".archive.directory", "archive cannot overlap Gitmoot's managed state")
	}
	for _, cache := range p.Caches {
		if core.PathsOverlap(dir, cache.Path) {
			errs.Add(field+".archive.directory", "archive overlaps a cache cleanup scope")
		}
	}
	protectedArchive := false
	for _, protected := range p.Protect.Paths {
		protectedArchive = protectedArchive || core.PathWithin(dir, protected)
	}
	if !protectedArchive {
		errs.Add(field+".archive.directory", "must also be covered by an independent protect.paths rule that survives removal of this archive rule")
	}
	for _, value := range []struct{ name, value string }{
		{"expect_mount_source", rule.Archive.ExpectMountSource},
		{"expect_fstype", rule.Archive.ExpectFSType},
	} {
		if strings.ContainsAny(value.value, " \t\n") {
			errs.Add(field+".archive."+value.name, "must not contain whitespace; mountinfo escapes it as octal")
		}
	}
	if rule.Archive.Manifest != "" {
		if rule.Archive.Manifest != WorkspaceArchiveManifestPath(rule) {
			errs.Add(field+".archive.manifest", "must name %s.manifest.json directly inside archive.directory", rule.Name)
		}
		if len(rule.Archive.ManifestSHA256) != 64 || strings.Trim(rule.Archive.ManifestSHA256, "0123456789abcdef") != "" {
			errs.Add(field+".archive.manifest_sha256", "must bind the manifest with its lowercase SHA256")
		}
	} else if rule.Archive.ManifestSHA256 != "" {
		errs.Add(field+".archive.manifest_sha256", "requires an exact manifest path")
	}
}
