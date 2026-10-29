// Package workspacearchive stores copy-only, verified tar archives of released
// directories. It never deletes the source or an archive; local removal stays
// with the existing quarantine and expiry engine.
package workspacearchive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

// ManifestVersion is the only manifest layout Check accepts.
const ManifestVersion = 1

// Member types recorded in a manifest. Other file types are refused.
const (
	TypeDirectory = "dir"
	TypeFile      = "file"
	TypeSymlink   = "symlink"
)

// Member is one archived tree entry. Path is relative to the archived
// directory; the directory itself is ".".
type Member struct {
	Path       string `json:"path"`
	Type       string `json:"type"`
	Size       int64  `json:"size"`
	Mode       uint32 `json:"mode"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	ModifiedNS int64  `json:"mtime_ns"`
	Linkname   string `json:"linkname,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
}

// Bundle records the verified Git history of a linked worktree, whose tree
// holds only a pointer to history kept elsewhere.
type Bundle struct {
	File          string `json:"file"`
	Bytes         int64  `json:"bytes"`
	SHA256        string `json:"sha256"`
	Head          string `json:"head"`
	WorktreeAdmin string `json:"worktree_admin"`
	AdminLocked   bool   `json:"admin_locked"`
}

// Manifest is the durable receipt of one verified archive.
type Manifest struct {
	Version          int                         `json:"version"`
	Name             string                      `json:"name"`
	SourcePath       string                      `json:"source_path"`
	Source           core.FilesystemID           `json:"source"`
	RuleSHA256       string                      `json:"rule_sha256"`
	Rule             config.WorkspaceArchiveRule `json:"rule"`
	ArchiveDirectory core.FilesystemID           `json:"archive_directory"`
	MountSource      string                      `json:"mount_source"`
	FSType           string                      `json:"fstype"`
	TarFile          string                      `json:"tar_file"`
	TarBytes         int64                       `json:"tar_bytes"`
	StreamSHA256     string                      `json:"stream_sha256"`
	ReadbackSHA256   string                      `json:"readback_sha256"`
	ContentBytes     int64                       `json:"content_bytes"`
	Members          []Member                    `json:"members"`
	Bundle           *Bundle                     `json:"bundle,omitempty"`
	CreatedAt        time.Time                   `json:"created_at"`
	VerifiedAt       time.Time                   `json:"verified_at"`
}

// Binding is what an operator pins as archive.manifest/manifest_sha256.
type Binding struct {
	Manifest       string `json:"manifest"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

// Scope supplies the host observations Create and Inspect need. Every
// location is explicit so tests can point at isolated fixtures.
type Scope struct {
	// ProcRoot is procfs ("/proc" in production).
	ProcRoot string
	// SearchRoots are walked for external dependents of the source.
	SearchRoots []string
	// SensitiveNames are additional base-name patterns (filepath.Match)
	// that keep an item local, normally policy protect.name_patterns.
	SensitiveNames []string
	// MaxEntries bounds the archived tree and each dependent walk; an
	// exceeded bound refuses rather than archiving a partial view.
	MaxEntries int
	// Dependents, when set, replaces the per-tree walk of SearchRoots with a
	// snapshot index built once (BuildDependentIndex) and shared by many
	// trees. Pointers created after the snapshot are not seen.
	Dependents *DependentIndex
}

// Inspection is the refusal-free result of the pre-archive checks.
type Inspection struct {
	Source         core.FilesystemID `json:"source"`
	Members        int               `json:"members"`
	ContentBytes   int64             `json:"content_bytes"`
	LinkedWorktree bool              `json:"linked_worktree"`
	MountSource    string            `json:"mount_source"`
	FSType         string            `json:"fstype"`
}

// File names inside the archive directory; Create never replaces them.
func TarName(rule config.WorkspaceArchiveRule) string    { return rule.Name + ".tar" }
func BundleName(rule config.WorkspaceArchiveRule) string { return rule.Name + ".bundle" }
func ManifestName(rule config.WorkspaceArchiveRule) string {
	return rule.Name + ".manifest.json"
}

// RuleHash binds name, path, owner, release and destination. The pinned
// receipt, dependent scan scope, live mount expectations and local expiry
// settings are excluded: they are checked afresh and changing them does not
// change the archive.
func RuleHash(rule config.WorkspaceArchiveRule) string {
	data, _ := json.Marshal(archiveRule(rule))
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func archiveRule(rule config.WorkspaceArchiveRule) config.WorkspaceArchiveRule {
	rule.Archive.Manifest, rule.Archive.ManifestSHA256 = "", ""
	rule.Archive.ExpectMountSource, rule.Archive.ExpectFSType = "", ""
	rule.DependentRoots = []string{}
	rule.LocalRetention, rule.LocalExpiryEnabled = "", false
	return rule
}

// PolicyScope is the host scope a policy grants one rule: its dependent roots
// (every inventory root when unset), protect.name_patterns and the deep-size
// entry bound.
func PolicyScope(policy config.Policy, rule config.WorkspaceArchiveRule) Scope {
	scope := Scope{ProcRoot: policy.Collectors.ProcRoot, SearchRoots: append([]string(nil), rule.DependentRoots...),
		SensitiveNames: policy.Protect.NamePatterns, MaxEntries: policy.Limits.DeepSizeMaxEntries}
	if len(scope.SearchRoots) == 0 {
		for _, root := range policy.Roots {
			scope.SearchRoots = append(scope.SearchRoots, root.Path)
		}
	}
	return scope
}

// ScratchManifestVersion is the only scratch manifest layout accepted.
const ScratchManifestVersion = 1

// ScratchEntry is one observed depth-1 entry of a scratch directory.
type ScratchEntry struct {
	Name string `json:"name"`
	// Type is the entry's own member type (dir, file or symlink).
	Type     string            `json:"type"`
	Identity core.FilesystemID `json:"identity"`
	Members  int               `json:"members"`
	// SizeBytes sums the sizes of the regular files in the entry.
	SizeBytes int64 `json:"size_bytes"`
	// NewestNS is the newest mtime or ctime of any member.
	NewestNS int64 `json:"newest_ns"`
	// Sensitive names the first member whose name matches the built-in
	// secret screen or protect.name_patterns: the entry stays local.
	Sensitive string `json:"sensitive,omitempty"`
	// Refusal explains why the entry cannot be archived or deleted
	// faithfully: a socket, fifo or device, a mount crossing, extended
	// attributes or Git history outside it.
	Refusal string `json:"refusal,omitempty"`

	inv scratchInventory
}

// ScratchManifest is the durable receipt of one scratch run's verified
// archive. Member paths start with their entry name.
type ScratchManifest struct {
	Version          int               `json:"version"`
	RunID            string            `json:"run_id"`
	ScratchDirectory string            `json:"scratch_directory"`
	Entries          []string          `json:"entries"`
	ArchiveDirectory core.FilesystemID `json:"archive_directory"`
	MountSource      string            `json:"mount_source"`
	FSType           string            `json:"fstype"`
	TarFile          string            `json:"tar_file"`
	TarBytes         int64             `json:"tar_bytes"`
	StreamSHA256     string            `json:"stream_sha256"`
	ReadbackSHA256   string            `json:"readback_sha256"`
	ContentBytes     int64             `json:"content_bytes"`
	Members          []Member          `json:"members"`
	CreatedAt        time.Time         `json:"created_at"`
	VerifiedAt       time.Time         `json:"verified_at"`
}

// ScratchArchiveName names one run's archive files.
func ScratchArchiveName(runID string) string { return "scratch-" + runID }
