// Package exportarchive stores exact, owner-approved evidence exports. It never
// deletes source data or expires archives; existing cleanup owns local expiry.
package exportarchive

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

type FileState struct {
	Identity core.FilesystemID `json:"identity"`
	// Mount IDs are boot-local and used only for current alias/race checks.
	MountID        uint64 `json:"-"`
	Size           int64  `json:"size"`
	AllocatedBytes int64  `json:"allocated_bytes"`
	Mode           uint32 `json:"mode"`
	UID            uint32 `json:"uid"`
	GID            uint32 `json:"gid"`
	ModifiedNS     int64  `json:"modified_ns"`
	ChangedNS      int64  `json:"changed_ns"`
	Links          uint64 `json:"links"`
}

type Manifest struct {
	Version               int                       `json:"version"`
	SourcePath            string                    `json:"source_path"`
	Source                FileState                 `json:"source"`
	SourceSHA256          string                    `json:"source_sha256"`
	RuleSHA256            string                    `json:"rule_sha256"`
	Rule                  config.EvidenceExportRule `json:"rule"`
	ArchiveDirectory      core.FilesystemID         `json:"archive_directory"`
	ArchiveAllocatedBytes int64                     `json:"archive_allocated_bytes"`
	ArchiveBytes          int64                     `json:"archive_bytes"`
	ArchiveSHA256         string                    `json:"archive_sha256"`
	CreatedAt             time.Time                 `json:"created_at"`
	RestoredAt            time.Time                 `json:"restored_at"`
}

// RuleHash excludes the resulting receipt binding and the independently gated
// expiry switch. Changing owners, paths, completion or retention invalidates it.
func RuleHash(rule config.EvidenceExportRule) string {
	data, _ := json.Marshal(archiveRule(rule))
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func archiveRule(rule config.EvidenceExportRule) config.EvidenceExportRule {
	rule.Archive.Manifest, rule.Archive.ManifestSHA256 = "", ""
	rule.LocalExpiryEnabled = false
	return rule
}

func sameMetadata(a, b FileState) bool {
	return a.Identity == b.Identity && a.Size == b.Size && a.Mode == b.Mode && a.UID == b.UID && a.GID == b.GID && a.ModifiedNS == b.ModifiedNS && a.Links == b.Links
}
