package core

import (
	"fmt"
	"strings"
	"time"
)

// EntryKind is the filesystem shape of a discovered entry.
type EntryKind string

const (
	EntryKindDirectory EntryKind = "directory"
	EntryKindFile      EntryKind = "file"
	EntryKindSymlink   EntryKind = "symlink"
	EntryKindSpecial   EntryKind = "special"
	EntryKindUnknown   EntryKind = "unknown"
)

var entryKinds = []EntryKind{EntryKindDirectory, EntryKindFile, EntryKindSymlink, EntryKindSpecial, EntryKindUnknown}

// Valid reports whether k is a known entry kind.
func (k EntryKind) Valid() bool { return validEnum(k, entryKinds) }

// ArtifactClass is what an entry appears to be. It is a description, never an
// authorization: classification alone never permits a mutation.
type ArtifactClass string

const (
	ClassPrimaryProject    ArtifactClass = "primary_project"
	ClassTaskWorktree      ArtifactClass = "task_worktree"
	ClassGeneratedArtifact ArtifactClass = "generated_artifact"
	ClassCache             ArtifactClass = "cache"
	ClassBackup            ArtifactClass = "backup"
	ClassOperationalTool   ArtifactClass = "operational_tool"
	ClassEvidence          ArtifactClass = "durable_evidence"
	ClassUnknown           ArtifactClass = "unknown"
)

var artifactClasses = []ArtifactClass{
	ClassPrimaryProject, ClassTaskWorktree, ClassGeneratedArtifact, ClassCache,
	ClassBackup, ClassOperationalTool, ClassEvidence, ClassUnknown,
}

// Valid reports whether c is a known artifact class.
func (c ArtifactClass) Valid() bool { return validEnum(c, artifactClasses) }

// ParseArtifactClass converts s into an ArtifactClass. Stored classes are
// parsed rather than cast so a corrupt row fails instead of decoding to a
// class the planner never produced.
func ParseArtifactClass(s string) (ArtifactClass, error) {
	return parseEnum(s, artifactClasses, "artifact class")
}

// EvidenceSource names the collector that produced an observation.
type EvidenceSource string

const (
	SourceFilesystem EvidenceSource = "filesystem"
	SourceGit        EvidenceSource = "git"
	SourceProcess    EvidenceSource = "process"
	SourceService    EvidenceSource = "service"
	SourceScheduler  EvidenceSource = "scheduler"
	SourceJob        EvidenceSource = "job"
	SourceCacheTool  EvidenceSource = "cache_tool"
	SourcePolicy     EvidenceSource = "policy"
	SourceModel      EvidenceSource = "model"
	SourceOperator   EvidenceSource = "operator"
)

var evidenceSources = []EvidenceSource{
	SourceFilesystem, SourceGit, SourceProcess, SourceService, SourceScheduler,
	SourceJob, SourceCacheTool, SourcePolicy, SourceModel, SourceOperator,
}

// Valid reports whether s is a known evidence source.
func (s EvidenceSource) Valid() bool { return validEnum(s, evidenceSources) }

// ProtectionKind enumerates the deterministic guards of the safety contract.
// A protection is never overridable by a model answer.
type ProtectionKind string

const (
	ProtectActiveProcess      ProtectionKind = "active_process"
	ProtectRegisteredAgent    ProtectionKind = "registered_agent"
	ProtectOwningJob          ProtectionKind = "owning_job"
	ProtectDirtyRepository    ProtectionKind = "dirty_repository"
	ProtectStashedWork        ProtectionKind = "stashed_work"
	ProtectUnpublishedCommits ProtectionKind = "unpublished_commits"
	ProtectBrokenGitMetadata  ProtectionKind = "broken_git_metadata"
	ProtectLockHeld           ProtectionKind = "lock_held"
	ProtectServiceReference   ProtectionKind = "service_reference"
	ProtectSensitiveContent   ProtectionKind = "sensitive_content"
	ProtectLiveDatabase       ProtectionKind = "live_database"
	ProtectDurableEvidence    ProtectionKind = "durable_evidence"
	ProtectSymlinkEscape      ProtectionKind = "symlink_escape"
	ProtectIdentityChanged    ProtectionKind = "identity_changed"
	ProtectInsufficientSpace  ProtectionKind = "insufficient_space"
	ProtectCrossFilesystem    ProtectionKind = "cross_filesystem"
	ProtectCollectorFailure   ProtectionKind = "collector_failure"
	ProtectPolicyProtected    ProtectionKind = "policy_protected"
)

var protectionKinds = []ProtectionKind{
	ProtectActiveProcess, ProtectRegisteredAgent, ProtectOwningJob, ProtectDirtyRepository,
	ProtectStashedWork, ProtectUnpublishedCommits, ProtectBrokenGitMetadata, ProtectLockHeld,
	ProtectServiceReference, ProtectSensitiveContent, ProtectLiveDatabase, ProtectDurableEvidence,
	ProtectSymlinkEscape, ProtectIdentityChanged, ProtectInsufficientSpace, ProtectCrossFilesystem,
	ProtectCollectorFailure, ProtectPolicyProtected,
}

// ProtectionKinds returns every protection kind in the contract. The safety
// engine uses it to prove that each kind has remediation text, so a new
// protection cannot ship as a refusal with no way out.
func ProtectionKinds() []ProtectionKind { return copyEnum(protectionKinds) }

// Valid reports whether k is a known protection kind.
func (k ProtectionKind) Valid() bool { return validEnum(k, protectionKinds) }

// FilesystemID is the stable identity of a path. It is revalidated before any
// mutation: a changed device or inode means the target is not what was planned.
type FilesystemID struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

// String renders the identity as "device:inode".
func (f FilesystemID) String() string { return fmt.Sprintf("%d:%d", f.Device, f.Inode) }

// Zero reports whether the identity is unset.
func (f FilesystemID) Zero() bool { return f.Device == 0 && f.Inode == 0 }

// Ownership records the POSIX owner and mode of an entry.
type Ownership struct {
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	Mode string `json:"mode"`
}

// GitState is the Git view of an entry. A nil GitState means "not a Git
// working tree"; a non-nil value with Degraded set means the collector could
// not finish and the entry must be treated as unknown, never as clean.
type GitState struct {
	RepoRoot           string `json:"repo_root"`
	WorktreeOf         string `json:"worktree_of,omitempty"`
	Bare               bool   `json:"bare"`
	Remote             string `json:"remote,omitempty"`
	Branch             string `json:"branch,omitempty"`
	Head               string `json:"head,omitempty"`
	UpstreamKnown      bool   `json:"upstream_known"`
	DirtyFiles         int    `json:"dirty_files"`
	Stashes            int    `json:"stashes"`
	UnpublishedCommits int    `json:"unpublished_commits"`
	Locked             bool   `json:"locked"`
	Degraded           bool   `json:"degraded"`
	DegradedReason     string `json:"degraded_reason,omitempty"`
}

// Clean reports whether the working tree holds no unpublished local work.
// A degraded collection is never clean.
func (g *GitState) Clean() bool {
	if g == nil {
		return false
	}
	return !g.Degraded && g.DirtyFiles == 0 && g.Stashes == 0 && g.UnpublishedCommits == 0 && !g.Locked
}

// Evidence is one observation about an entry, attributed to its collector.
type Evidence struct {
	Source     EvidenceSource `json:"source"`
	Signal     string         `json:"signal"`
	Detail     string         `json:"detail,omitempty"`
	ObservedAt time.Time      `json:"observed_at"`
}

// Validate checks a single evidence record.
func (e Evidence) Validate(field string) FieldErrors {
	var errs FieldErrors
	if !e.Source.Valid() {
		errs.Add(field+".source", "unknown evidence source %q", string(e.Source))
	}
	if strings.TrimSpace(e.Signal) == "" {
		errs.Add(field+".signal", "must not be empty")
	}
	if e.ObservedAt.IsZero() {
		errs.Add(field+".observed_at", "must be set")
	}
	return errs
}

// Protection is a deterministic reason an entry may not be mutated.
type Protection struct {
	Kind   ProtectionKind `json:"kind"`
	Reason string         `json:"reason"`
	Source EvidenceSource `json:"source"`
	// Remediation tells the operator what would clear this protection. A
	// refusal without it is a dead end, so the safety engine fills it for
	// every protection it reports.
	Remediation string `json:"remediation,omitempty"`
	Blocking    bool   `json:"blocking"`
}

// Validate checks a single protection record.
func (p Protection) Validate(field string) FieldErrors {
	var errs FieldErrors
	if !p.Kind.Valid() {
		errs.Add(field+".kind", "unknown protection kind %q", string(p.Kind))
	}
	if !p.Source.Valid() {
		errs.Add(field+".source", "unknown evidence source %q", string(p.Source))
	}
	if strings.TrimSpace(p.Reason) == "" {
		errs.Add(field+".reason", "must not be empty")
	}
	return errs
}

// Entry is one discovered path together with everything known about it.
type Entry struct {
	ContractVersion int             `json:"contract_version"`
	Path            string          `json:"path"`
	Root            string          `json:"root"`
	Kind            EntryKind       `json:"kind"`
	FilesystemID    FilesystemID    `json:"filesystem_id"`
	Ownership       Ownership       `json:"ownership"`
	SizeBytes       int64           `json:"size_bytes"`
	SizeIsDeep      bool            `json:"size_is_deep"`
	ModifiedAt      time.Time       `json:"modified_at"`
	AccessedAt      time.Time       `json:"accessed_at"`
	SymlinkTarget   string          `json:"symlink_target,omitempty"`
	CanonicalPath   string          `json:"canonical_path,omitempty"`
	Destination     string          `json:"destination,omitempty"`
	Fingerprint     string          `json:"fingerprint,omitempty"`
	Class           ArtifactClass   `json:"class"`
	Git             *GitState       `json:"git,omitempty"`
	Evidence        []Evidence      `json:"evidence,omitempty"`
	Protections     []Protection    `json:"protections,omitempty"`
	Recommendation  *Recommendation `json:"recommendation,omitempty"`
	ObservedAt      time.Time       `json:"observed_at"`
}

// Protected reports whether any blocking protection applies. Callers must
// treat a protected entry as immutable regardless of any recommendation.
func (e *Entry) Protected() bool {
	for _, p := range e.Protections {
		if p.Blocking {
			return true
		}
	}
	return false
}

// Normalize fills the contract version and forces every timestamp to UTC so
// stored and emitted documents are byte-stable across machines.
func (e *Entry) Normalize() {
	if e.ContractVersion == 0 {
		e.ContractVersion = ContractVersion
	}
	if e.Class == "" {
		e.Class = ClassUnknown
	}
	if e.Kind == "" {
		e.Kind = EntryKindUnknown
	}
	e.ModifiedAt = e.ModifiedAt.UTC()
	e.AccessedAt = e.AccessedAt.UTC()
	e.ObservedAt = e.ObservedAt.UTC()
	for i := range e.Evidence {
		e.Evidence[i].ObservedAt = e.Evidence[i].ObservedAt.UTC()
	}
	if e.Recommendation != nil {
		e.Recommendation.DecidedAt = e.Recommendation.DecidedAt.UTC()
	}
}

// Validate reports every field-level problem with the entry.
func (e *Entry) Validate() error {
	var errs FieldErrors
	if e.ContractVersion != ContractVersion {
		errs.Add("contract_version", "must be %d, got %d", ContractVersion, e.ContractVersion)
	}
	if !isAbsClean(e.Path) {
		errs.Add("path", "must be an absolute, cleaned path, got %q", e.Path)
	}
	if !isAbsClean(e.Root) {
		errs.Add("root", "must be an absolute, cleaned path, got %q", e.Root)
	}
	if !e.Kind.Valid() {
		errs.Add("kind", "unknown entry kind %q", string(e.Kind))
	}
	if !e.Class.Valid() {
		errs.Add("class", "unknown artifact class %q", string(e.Class))
	}
	if e.SizeBytes < 0 {
		errs.Add("size_bytes", "must not be negative, got %d", e.SizeBytes)
	}
	if e.ObservedAt.IsZero() {
		errs.Add("observed_at", "must be set")
	}
	for i, ev := range e.Evidence {
		errs = append(errs, ev.Validate(fmt.Sprintf("evidence[%d]", i))...)
	}
	for i, p := range e.Protections {
		errs = append(errs, p.Validate(fmt.Sprintf("protections[%d]", i))...)
	}
	if e.Recommendation != nil {
		errs = append(errs, e.Recommendation.Validate("recommendation")...)
	}
	return errs.ErrorOrNil()
}
