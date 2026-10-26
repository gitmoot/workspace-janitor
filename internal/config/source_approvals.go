package config

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// SourceNameApprovalPolicy never approves a workspace for disposal. It permits
// only reviewed ordinary source bytes to satisfy one protected-name match.
// The operator controls both the authorized reviewers and their exact records.
type SourceNameApprovalPolicy struct {
	Generation string               `yaml:"generation" json:"generation"`
	Reviewers  []string             `yaml:"reviewers" json:"reviewers"`
	Files      []SourceNameApproval `yaml:"files" json:"files"`
}

// SourceNameApproval binds a review to its original checkout, origin remote,
// published blob, exact content and policy generation. Records are references,
// not file contents; neither a scan nor Git tracking creates an approval.
type SourceNameApproval struct {
	Repository  string    `yaml:"repository" json:"repository"`
	Remote      string    `yaml:"remote" json:"remote"`
	Path        string    `yaml:"path" json:"path"`
	Commit      string    `yaml:"commit" json:"commit"`
	Blob        string    `yaml:"blob" json:"blob"`
	SHA256      string    `yaml:"sha256" json:"sha256"`
	NamePattern string    `yaml:"name_pattern" json:"name_pattern"`
	Reviewer    string    `yaml:"reviewer" json:"reviewer"`
	Record      string    `yaml:"record" json:"record"`
	Generation  string    `yaml:"generation" json:"generation"`
	ReviewedAt  time.Time `yaml:"reviewed_at" json:"reviewed_at"`
	ExpiresAt   time.Time `yaml:"expires_at" json:"expires_at"`
}

// SourceApprovalPath excludes secret containers, databases and metadata even if
// somebody supplies an approval for them. A source extension is only a negative
// filter: it is never evidence that the file's bytes have been reviewed.
func SourceApprovalPath(path string) bool {
	if path == "" || filepath.IsAbs(path) || filepath.Clean(path) != path || path == "." || path == ".." || strings.HasPrefix(path, "../") || strings.ContainsAny(path, "\x00\r\n\\") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if strings.HasPrefix(part, ".") {
			return false
		}
	}
	name := strings.ToLower(filepath.Base(path))
	for _, pattern := range []string{"*.pem", "*.key", "*.kdbx", "id_rsa*", "id_ed25519*", ".env", ".env.*"} {
		if matched, _ := filepath.Match(pattern, name); matched {
			return false
		}
	}
	if core.IsDatabasePath(path) {
		return false
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".go", ".rs", ".py", ".ts", ".tsx", ".js", ".jsx", ".c", ".cc", ".cpp", ".h", ".hpp", ".java", ".kt", ".swift", ".md", ".rst":
		return true
	}
	return false
}

func sourceApprovalHex(value string, sizes ...int) bool {
	validLength := false
	for _, size := range sizes {
		validLength = validLength || len(value) == size
	}
	if !validLength || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (p *Policy) validateSourceNameApprovals(errs *core.FieldErrors) {
	approvals := p.SourceNameApprovals
	if approvals == nil {
		return
	}
	if strings.TrimSpace(approvals.Generation) == "" || len(approvals.Generation) > 128 {
		errs.Add("source_name_approvals.generation", "must name a nonempty policy generation of at most 128 bytes")
	}
	if len(approvals.Files) > 64 || len(approvals.Reviewers) > 64 {
		errs.Add("source_name_approvals", "at most 64 reviewed files and 64 reviewers are allowed")
	}
	reviewers := make(map[string]bool, len(approvals.Reviewers))
	for i, reviewer := range approvals.Reviewers {
		if strings.TrimSpace(reviewer) == "" || len(reviewer) > 256 || reviewers[reviewer] {
			errs.Add(fmt.Sprintf("source_name_approvals.reviewers[%d]", i), "must be a unique nonempty authorized issuer of at most 256 bytes")
		}
		reviewers[reviewer] = true
	}
	seen := make(map[string]bool, len(approvals.Files))
	for i, approval := range approvals.Files {
		field := fmt.Sprintf("source_name_approvals.files[%d]", i)
		if !core.IsCanonicalPath(approval.Repository) {
			errs.Add(field+".repository", "must be the canonical absolute original checkout path")
		}
		if !SourceApprovalPath(approval.Path) {
			errs.Add(field+".path", "must be an exact relative ordinary source/documentation path, not a secret container or database")
		}
		remote, err := url.Parse(approval.Remote)
		if !core.IsCanonicalPath(approval.Remote) && (err != nil || remote.Scheme != "https" || remote.Host == "" || remote.User != nil || remote.RawQuery != "" || remote.Fragment != "" || remote.Path == "") {
			errs.Add(field+".remote", "must be an exact credential-free HTTPS origin URL or canonical local origin path")
		}
		if !sourceApprovalHex(approval.Commit, 40, 64) || !sourceApprovalHex(approval.Blob, len(approval.Commit)) || !sourceApprovalHex(approval.SHA256, 64) {
			errs.Add(field, "requires full lowercase Git commit/blob object IDs and a SHA-256 content digest")
		}
		matched, err := filepath.Match(approval.NamePattern, filepath.Base(approval.Path))
		configured := false
		for _, pattern := range p.Protect.NamePatterns {
			configured = configured || pattern == approval.NamePattern
		}
		if err != nil || !matched || !configured {
			errs.Add(field+".name_pattern", "must name an existing protected-name pattern matching this file")
		}
		if !reviewers[approval.Reviewer] || strings.TrimSpace(approval.Reviewer) == "" {
			errs.Add(field+".reviewer", "must be an explicitly authorized source-name reviewer")
		}
		if strings.TrimSpace(approval.Record) == "" || len(approval.Record) > 2048 || strings.ContainsAny(approval.Record, "\x00\r\n") {
			errs.Add(field+".record", "must reference the exact authorized source-content review, without embedding contents")
		}
		if approval.Generation != approvals.Generation {
			errs.Add(field+".generation", "must match the current source-name approval policy generation")
		}
		if approval.ReviewedAt.IsZero() || !approval.ExpiresAt.After(approval.ReviewedAt) {
			errs.Add(field+".expires_at", "must be later than an explicit reviewed_at timestamp")
		}
		key := approval.Repository + "\x00" + approval.Path + "\x00" + approval.NamePattern
		if seen[key] {
			errs.Add(field, "duplicates an approval for the same repository, file and protected-name pattern")
		}
		seen[key] = true
	}
}
