package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// EvidenceExportRule names one owner-confirmed, credential-free regular export
// file, never a raw session store, database, directory, or checkout.
type EvidenceExportRule struct {
	Name               string                   `yaml:"name" json:"name"`
	Class              string                   `yaml:"class" json:"class"`
	Path               string                   `yaml:"path" json:"path"`
	Owner              string                   `yaml:"owner" json:"owner"`
	Approval           string                   `yaml:"approval" json:"approval"`
	CompletedAt        time.Time                `yaml:"completed_at" json:"completed_at"`
	CredentialFree     bool                     `yaml:"credential_free" json:"credential_free"`
	SourceContainer    string                   `yaml:"source_container" json:"source_container"`
	SourceLifetime     string                   `yaml:"source_lifetime" json:"source_lifetime"`
	LocalRetention     core.Retention           `yaml:"local_retention" json:"local_retention"`
	LocalExpiryEnabled bool                     `yaml:"local_expiry_enabled" json:"local_expiry_enabled"`
	MaxBytes           int64                    `yaml:"max_bytes" json:"max_bytes"`
	Archive            ExportArchiveDestination `yaml:"archive" json:"archive"`
}

type ExportArchiveDestination struct {
	Directory      string         `yaml:"directory" json:"directory"`
	Owner          string         `yaml:"owner" json:"owner"`
	Approval       string         `yaml:"approval" json:"approval"`
	Lifetime       string         `yaml:"lifetime" json:"lifetime"`
	Retention      core.Retention `yaml:"retention" json:"retention"`
	DeleteEnabled  bool           `yaml:"delete_enabled" json:"delete_enabled"`
	Manifest       string         `yaml:"manifest" json:"manifest"`
	ManifestSHA256 string         `yaml:"manifest_sha256" json:"manifest_sha256"`
}

func (p *Policy) normalizeEvidenceExports(expand func(string, string) string) {
	for i := range p.EvidenceExports {
		rule := &p.EvidenceExports[i]
		field := fmt.Sprintf("evidence_exports[%d]", i)
		rule.Path = expand(field+".path", rule.Path)
		rule.SourceContainer = expand(field+".source_container", rule.SourceContainer)
		rule.Archive.Directory = expand(field+".archive.directory", rule.Archive.Directory)
		if rule.Archive.Manifest != "" {
			rule.Archive.Manifest = expand(field+".archive.manifest", rule.Archive.Manifest)
		}
		if rule.LocalRetention == "" {
			rule.LocalRetention = core.Retention30Days
		}
		if rule.Archive.Retention == "" {
			rule.Archive.Retention = core.RetentionPermanent
		}
		if rule.MaxBytes == 0 {
			rule.MaxBytes = 1 << 30
		}
	}
}

func (p *Policy) validateEvidenceExports(errs *core.FieldErrors) {
	if len(p.EvidenceExports) > 64 {
		errs.Add("evidence_exports", "at most 64 exact exports are allowed")
	}
	if len(p.EvidenceExports) > 0 && (!p.Collectors.Git || !p.Collectors.Processes || !p.Collectors.Services) {
		errs.Add("evidence_exports", "requires Git, process, and service collectors")
	}
	names, paths := map[string]bool{}, map[string]bool{}
	for i, rule := range p.EvidenceExports {
		field := fmt.Sprintf("evidence_exports[%d]", i)
		if strings.TrimSpace(rule.Name) == "" || names[rule.Name] {
			errs.Add(field+".name", "must be nonempty and unique")
		}
		names[rule.Name] = true
		if !core.IsCanonicalPath(rule.Path) || paths[rule.Path] {
			errs.Add(field+".path", "must be a unique canonical absolute file path")
		}
		paths[rule.Path] = true
		configured := false
		for _, root := range p.Roots {
			configured = configured || (rule.Path != root.Path && core.PathWithin(rule.Path, root.Path))
		}
		if !configured {
			errs.Add(field+".path", "must be inside a configured inventory root")
		}
		if rawStateOrCredentialPath(rule.Path) || rawStateOrCredentialPath(rule.Archive.Directory) {
			errs.Add(field, "raw runtime/session stores and credential containers cannot be export sources or archive destinations")
		}
		if core.PathsOverlap(rule.Archive.Directory, p.Retention.QuarantineDir) {
			errs.Add(field+".archive.directory", "archive cannot share a cleanup receipt container")
		}
		for _, cache := range p.Caches {
			if core.PathsOverlap(rule.Archive.Directory, cache.Path) {
				errs.Add(field+".archive.directory", "archive overlaps a cache cleanup scope")
			}
		}
		for _, other := range p.EvidenceExports {
			if core.PathsOverlap(rule.Archive.Directory, other.SourceContainer) {
				errs.Add(field+".archive.directory", "archive overlaps an export source container")
			}
		}
		protectedArchive := false
		for _, protected := range p.Protect.Paths {
			protectedArchive = protectedArchive || core.PathWithin(rule.Archive.Directory, protected)
		}
		if !protectedArchive {
			errs.Add(field+".archive.directory", "must also be covered by an independent protect.paths rule that survives removal of this export rule")
		}
		if !core.IsCanonicalPath(rule.SourceContainer) || rule.Path == rule.SourceContainer || !core.PathWithin(rule.Path, rule.SourceContainer) {
			errs.Add(field+".source_container", "must be a canonical containing directory distinct from the exact export")
		}
		switch rule.Class {
		case "completed_report", "review_evidence", "session_export", "evidence_export":
		default:
			errs.Add(field+".class", "must name a completed_report, review_evidence, session_export, or evidence_export")
		}
		if strings.TrimSpace(rule.Owner) == "" || strings.TrimSpace(rule.Approval) == "" || rule.CompletedAt.IsZero() || !rule.CredentialFree {
			errs.Add(field, "requires owner, saved approval, verified completion time, and explicit credential_free confirmation")
		}
		if rule.CompletedAt.After(time.Now().UTC()) {
			errs.Add(field+".completed_at", "cannot be in the future")
		}
		if rule.LocalRetention != core.Retention30Days && rule.LocalRetention != core.Retention90Days && rule.LocalRetention != core.RetentionPermanent {
			errs.Add(field+".local_retention", "must retain exports for at least 30d (30d, 90d, or permanent)")
		}
		if rule.LocalExpiryEnabled && rule.LocalRetention == core.RetentionPermanent {
			errs.Add(field+".local_expiry_enabled", "cannot expire permanent local retention")
		}
		if rule.MaxBytes <= 0 || rule.MaxBytes > 1<<30 {
			errs.Add(field+".max_bytes", "must be positive and at most 1 GiB per export")
		}
		if !core.IsCanonicalPath(rule.Archive.Directory) || core.PathsOverlap(rule.SourceContainer, rule.Archive.Directory) {
			errs.Add(field+".archive.directory", "must be canonical and outside the source container, without overlapping it")
		}
		if strings.TrimSpace(rule.SourceLifetime) == "" || strings.TrimSpace(rule.Archive.Lifetime) == "" || rule.SourceLifetime == rule.Archive.Lifetime {
			errs.Add(field+".archive.lifetime", "source and archive need distinct explicit owner-confirmed lifetimes")
		}
		if strings.TrimSpace(rule.Archive.Owner) == "" || strings.TrimSpace(rule.Archive.Approval) == "" {
			errs.Add(field+".archive", "requires the archive owner and saved destination approval")
		}
		if rule.Archive.DeleteEnabled || rule.Archive.Retention != core.RetentionPermanent {
			errs.Add(field+".archive", "archive deletion is disabled; archive retention must be permanent")
		}
		if rule.Archive.Manifest != "" {
			if !core.IsCanonicalPath(rule.Archive.Manifest) || !core.PathWithin(rule.Archive.Manifest, rule.Archive.Directory) || filepath.Base(rule.Archive.Manifest) != "manifest.json" {
				errs.Add(field+".archive.manifest", "must name manifest.json inside the approved archive directory")
			}
			if len(rule.Archive.ManifestSHA256) != 64 || strings.Trim(rule.Archive.ManifestSHA256, "0123456789abcdef") != "" {
				errs.Add(field+".archive.manifest_sha256", "must bind the manifest with its lowercase SHA256")
			}
		} else if rule.Archive.ManifestSHA256 != "" {
			errs.Add(field+".archive.manifest_sha256", "requires an exact manifest path")
		}
	}
}

func rawStateOrCredentialPath(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		switch part {
		case ".omp", ".claude", ".codex", ".gitmoot", ".ssh", ".gnupg", ".git", "tokens":
			return true
		}
	}
	return false
}
