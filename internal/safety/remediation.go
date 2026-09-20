package safety

import "github.com/gitmoot/workspace-janitor/internal/core"

// remediations maps each protection to the action that would clear it.
//
// A refusal without a remedy is a dead end: the operator is told no and left
// to guess. Every protection the engine can raise has an entry here, which
// TestEveryProtectionKindHasRemediation enforces.
var remediations = map[core.ProtectionKind]string{
	core.ProtectActiveProcess:      "stop the process using this path, or exclude the path, then scan again",
	core.ProtectRegisteredAgent:    "release or finish the registered agent holding this directory, then scan again",
	core.ProtectOwningJob:          "wait for the owning job to finish, or cancel it, then scan again",
	core.ProtectDirtyRepository:    "commit, stash, or discard the uncommitted changes, then scan again",
	core.ProtectStashedWork:        "apply or drop the stash entries, then scan again",
	core.ProtectUnpublishedCommits: "push the local commits, or set an upstream so publication can be verified, then scan again",
	core.ProtectBrokenGitMetadata:  "repair the repository metadata (for example a dangling .git pointer), then scan again",
	core.ProtectLockHeld:           "let the Git operation finish and remove the stale lock file, then scan again",
	core.ProtectServiceReference:   "remove the systemd, cron, or PM2 reference to this path, then scan again",
	core.ProtectSensitiveContent:   "move the credential material elsewhere, or adjust protect.name_patterns if the match is wrong",
	core.ProtectLiveDatabase:       "stop the database writer and move the file deliberately; the janitor will not move a live database",
	core.ProtectDurableEvidence:    "copy the evidence to a durable location first; it is never cleaned up in place",
	core.ProtectSymlinkEscape:      "resolve the symlink, or enable follow_symlinks for a root that fully contains its target",
	core.ProtectIdentityChanged:    "re-scan and re-plan: the path changed after it was planned, so the plan no longer describes it",
	core.ProtectInsufficientSpace:  "free space on the destination filesystem, or lower safety.min_free_bytes deliberately",
	core.ProtectCrossFilesystem:    "point retention.quarantine_dir at the same filesystem, or set safety.allow_cross_filesystem_quarantine",
	core.ProtectCollectorFailure:   "re-run the scan so the failed collector can observe this path; unknown state is treated as unsafe",
	core.ProtectPolicyProtected:    "adjust protect.paths if this location should not be protected; core locations stay protected regardless",
}

// Remediation returns what would clear a protection of this kind.
func Remediation(kind core.ProtectionKind) string {
	if text, ok := remediations[kind]; ok {
		return text
	}
	// An unmapped kind must still produce something actionable rather than
	// an empty field that would fail verdict validation.
	return "inspect the reported evidence for this protection and resolve it, then scan again"
}
