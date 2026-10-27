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
	return fingerprint(entry, true)
}

// SnapshotFingerprint validates a persisted digest against its own saved
// metadata, then returns the current digest of that same immutable snapshot.
// It never borrows observations from the live object. Before Git activity was
// included in digests, receipts already saved LastActivity; only that known
// historical format with a known activity baseline can be upgraded in memory.
// Unknown digests or missing legacy evidence cannot authorize mutation.
func SnapshotFingerprint(entry core.Entry) (string, bool) {
	current := Fingerprint(entry)
	if entry.Fingerprint == "" || entry.Fingerprint == current {
		return current, true
	}
	if entry.ContractVersion != core.ContractVersion || entry.Git == nil ||
		entry.Git.LastActivity.IsZero() || entry.ExportArchive != nil || entry.WorkspaceArchive != nil {
		return "", false
	}
	if entry.Fingerprint != fingerprint(entry, false) {
		return "", false
	}
	return current, true
}

func fingerprint(entry core.Entry, gitActivity bool) string {
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
	if !entry.LatestModifiedAt.IsZero() {
		write("latest_modified=%d", entry.LatestModifiedAt.UTC().UnixNano())
	}
	write("link=%s", entry.SymlinkTarget)
	if entry.ExportArchive != nil {
		write("export_archive=%s|%s", entry.ExportArchive.Manifest, entry.ExportArchive.ManifestSHA256)
	}
	if entry.WorkspaceArchive != nil {
		b := entry.WorkspaceArchive
		write("workspace_archive=%s|%s|%d|%s|%d", b.Manifest, b.ManifestSHA256, b.MemberCount, b.TreeDigest, b.CreatedAt.UTC().UnixNano())
	}
	if entry.Git == nil {
		write("git=none")
	} else {
		// Publication, bareness, worktree ownership, and the remote all
		// feed protections, so a change in any of them must change the
		// fingerprint. Measuring publication at the same HEAD removes the
		// unknown-publication protection; if that were excluded here, the
		// entry would still compare as unchanged.
		write("git=%s|%s|%d|%d|%d|%t|%t|%t|%t|%t|%s|%s",
			entry.Git.Head, entry.Git.Branch, entry.Git.DirtyFiles, entry.Git.Stashes,
			entry.Git.UnpublishedCommits, entry.Git.Locked, entry.Git.Degraded,
			entry.Git.UpstreamKnown, entry.Git.PublicationKnown, entry.Git.Bare, entry.Git.WorktreeOf, entry.Git.Remote)
		if gitActivity {
			write("git_activity=%d", entry.Git.LastActivity.UTC().UnixNano())
		}
		if entry.Git.SourceApprovalFingerprint != "" {
			write("source_approvals=%s", entry.Git.SourceApprovalFingerprint)
		}
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
		beforeFingerprint, known := SnapshotFingerprint(before)
		if before.Fingerprint != "" && known && beforeFingerprint == entry.Fingerprint {
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
