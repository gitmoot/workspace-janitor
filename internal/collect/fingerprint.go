package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// Fingerprint is a stable digest of the metadata that decides whether an
// entry has changed since a previous scan.
//
// It covers identity, type, size, mode, modification time, link target, and
// the Git facts a decision depends on. It deliberately excludes evidence,
// protections, and observation timestamps: those change every scan and would
// make every entry look modified.
func Fingerprint(entry core.Entry) string {
	h := sha256.New()
	write := func(format string, args ...any) {
		fmt.Fprintf(h, format+"\x00", args...)
	}
	write("path=%s", entry.Path)
	write("kind=%s", entry.Kind)
	write("device=%d", entry.FilesystemID.Device)
	write("inode=%d", entry.FilesystemID.Inode)
	write("uid=%d", entry.Ownership.UID)
	write("gid=%d", entry.Ownership.GID)
	write("mode=%s", entry.Ownership.Mode)
	write("size=%d", entry.SizeBytes)
	write("deep=%t", entry.SizeIsDeep)
	write("modified=%d", entry.ModifiedAt.UTC().UnixNano())
	write("link=%s", entry.SymlinkTarget)
	if entry.Git == nil {
		write("git=none")
	} else {
		write("git=%s|%s|%d|%d|%d|%t|%t",
			entry.Git.Head, entry.Git.Branch, entry.Git.DirtyFiles, entry.Git.Stashes,
			entry.Git.UnpublishedCommits, entry.Git.Locked, entry.Git.Degraded)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// applyFingerprints stamps each entry's fingerprint and compares it with the
// prior scan, so a later slice can reuse unchanged metadata and so a changed
// identity is visible rather than inferred.
func applyFingerprints(entries []core.Entry, prior []core.Entry, priorScanID string, now time.Time) {
	previous := make(map[string]core.Entry, len(prior))
	for _, entry := range prior {
		previous[entry.Path] = entry
	}
	for i := range entries {
		entry := &entries[i]
		entry.Fingerprint = Fingerprint(*entry)
		if priorScanID == "" {
			continue
		}
		before, ok := previous[entry.Path]
		if !ok {
			addEvidence(entry, core.Evidence{
				Source:     core.SourceFilesystem,
				Signal:     "new_since_prior_scan",
				Detail:     "not present in scan " + priorScanID,
				ObservedAt: now,
			})
			continue
		}
		signal := "changed_since_prior_scan"
		if before.Fingerprint != "" && before.Fingerprint == entry.Fingerprint {
			signal = "unchanged_since_prior_scan"
		}
		addEvidence(entry, core.Evidence{
			Source:     core.SourceFilesystem,
			Signal:     signal,
			Detail:     "compared with scan " + priorScanID,
			ObservedAt: now,
		})
		if before.FilesystemID != entry.FilesystemID && !before.FilesystemID.Zero() {
			addEvidence(entry, core.Evidence{
				Source:     core.SourceFilesystem,
				Signal:     "identity_changed_since_prior_scan",
				Detail:     fmt.Sprintf("identity was %s, now %s", before.FilesystemID, entry.FilesystemID),
				ObservedAt: now,
			})
		}
	}
}
