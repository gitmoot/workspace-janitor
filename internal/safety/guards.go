package safety

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// databaseExtensions are file types that may be an open database. Moving a
// live database file out from under its writer corrupts it.
var databaseExtensions = map[string]struct{}{
	".db": {}, ".db3": {}, ".sqlite": {}, ".sqlite3": {}, ".mdb": {}, ".ldb": {},
}

// guardCollectedProtections carries forward every blocking protection the
// collectors recorded. The engine re-derives what it can from evidence, but
// a collector-observed protection is authoritative on its own.
func guardCollectedProtections(in Input) []core.Protection {
	var out []core.Protection
	for _, protection := range in.Entry.Protections {
		if !protection.Blocking {
			continue
		}
		if protection.Remediation == "" {
			protection.Remediation = Remediation(protection.Kind)
		}
		out = append(out, protection)
	}
	return out
}

// guardUnknownEvidence fails closed on anything a collector could not see.
// Unknown state is not absence of risk: it is absence of knowledge.
func guardUnknownEvidence(in Input) []core.Protection {
	var out []core.Protection
	for _, evidence := range in.Entry.Evidence {
		if !strings.HasPrefix(evidence.Signal, "unknown:") {
			continue
		}
		detail := evidence.Detail
		if detail == "" {
			detail = strings.TrimPrefix(evidence.Signal, "unknown:")
		}
		out = append(out, protect(core.ProtectCollectorFailure, evidence.Source,
			fmt.Sprintf("unresolved observation %q: %s", strings.TrimPrefix(evidence.Signal, "unknown:"), detail)))
	}
	return out
}

// guardFilesystemIdentity refuses a path whose identity is unknown. Without
// device and inode there is nothing to revalidate against at apply time.
func guardFilesystemIdentity(in Input) []core.Protection {
	if in.Entry.FilesystemID.Zero() {
		return []core.Protection{protect(core.ProtectCollectorFailure, core.SourceFilesystem,
			"filesystem identity is unknown, so the target cannot be revalidated before a mutation")}
	}
	return nil
}

// guardGitState derives Git protections from the recorded state rather than
// trusting that a collector already added them.
func guardGitState(in Input) []core.Protection {
	state := in.Entry.Git
	if state == nil {
		return nil
	}
	var out []core.Protection
	if state.Degraded {
		reason := state.DegradedReason
		if reason == "" {
			reason = "Git state could not be collected"
		}
		out = append(out, protect(core.ProtectBrokenGitMetadata, core.SourceGit, reason))
	}
	if state.DirtyFiles > 0 {
		out = append(out, protect(core.ProtectDirtyRepository, core.SourceGit,
			fmt.Sprintf("%d uncommitted change(s)", state.DirtyFiles)))
	}
	if state.Stashes > 0 {
		out = append(out, protect(core.ProtectStashedWork, core.SourceGit,
			fmt.Sprintf("%d stash entr(ies)", state.Stashes)))
	}
	if state.Locked {
		out = append(out, protect(core.ProtectLockHeld, core.SourceGit, "a Git lock file is present"))
	}
	switch {
	case state.Degraded:
		// Publication cannot be judged from a degraded collection, and the
		// degraded protection above already covers it.
	case !state.UpstreamKnown && !state.Bare:
		out = append(out, protect(core.ProtectUnpublishedCommits, core.SourceGit,
			"no upstream is configured, so local commits cannot be shown as published"))
	case state.UnpublishedCommits > 0:
		out = append(out, protect(core.ProtectUnpublishedCommits, core.SourceGit,
			fmt.Sprintf("%d commit(s) ahead of upstream", state.UnpublishedCommits)))
	}
	return out
}

// guardSymlinkContainment refuses a symlink whose resolution is unknown or
// leaves the configured root: following it could mutate anything.
func guardSymlinkContainment(in Input) []core.Protection {
	if in.Entry.Kind != core.EntryKindSymlink {
		return nil
	}
	switch {
	case in.Entry.CanonicalPath == "":
		return []core.Protection{protect(core.ProtectSymlinkEscape, core.SourceFilesystem,
			fmt.Sprintf("symlink %s was not resolved, so its target is unknown", in.Entry.Path))}
	case in.Entry.Root == "":
		// Containment is judged against a root. Without one there is
		// nothing to judge against, and an unjudgeable symlink protects the
		// path like any other unknown.
		return []core.Protection{protect(core.ProtectSymlinkEscape, core.SourceFilesystem,
			fmt.Sprintf("symlink %s has no recorded discovery root, so containment of %s cannot be judged",
				in.Entry.Path, in.Entry.CanonicalPath))}
	case !pathWithin(in.Entry.CanonicalPath, in.Entry.Root):
		return []core.Protection{protect(core.ProtectSymlinkEscape, core.SourceFilesystem,
			fmt.Sprintf("symlink %s resolves to %s, outside root %s", in.Entry.Path, in.Entry.CanonicalPath, in.Entry.Root))}
	}
	return nil
}

// guardProtectedPaths refuses any overlap with a protected location, in
// either direction: the entry inside a protected path, or a protected path
// inside the entry.
func guardProtectedPaths(in Input) []core.Protection {
	var out []core.Protection
	protected := append([]string{}, in.Policy.ProtectedPaths...)
	for _, own := range []string{in.Policy.StateDir, in.Policy.QuarantineDir} {
		if own != "" {
			protected = append(protected, own)
		}
	}
	for _, candidate := range protected {
		if candidate == "" || !overlaps(in.Entry.Path, candidate) {
			continue
		}
		reason := fmt.Sprintf("%s is a protected location", candidate)
		if in.Entry.Path != candidate && pathWithin(candidate, in.Entry.Path) {
			reason = fmt.Sprintf("%s contains the protected location %s", in.Entry.Path, candidate)
		}
		out = append(out, protect(core.ProtectPolicyProtected, core.SourcePolicy, reason))
	}
	return out
}

// guardSensitiveNames refuses names that look like credential material. The
// value is never read: the name alone is enough to refuse.
func guardSensitiveNames(in Input) []core.Protection {
	name := filepath.Base(in.Entry.Path)
	var out []core.Protection
	for _, pattern := range in.Policy.NamePatterns {
		matched, err := filepath.Match(pattern, name)
		if err != nil {
			// An unusable pattern is an unknown, not an all-clear.
			out = append(out, protect(core.ProtectCollectorFailure, core.SourcePolicy,
				fmt.Sprintf("protected-name pattern %q is invalid: %v", pattern, err)))
			continue
		}
		if matched {
			out = append(out, protect(core.ProtectSensitiveContent, core.SourcePolicy,
				fmt.Sprintf("%s matches protected name pattern %q", name, pattern)))
		}
	}
	return out
}

// guardLiveDatabases refuses database files, which may have an open writer.
func guardLiveDatabases(in Input) []core.Protection {
	if in.Entry.Kind != core.EntryKindFile {
		return nil
	}
	ext := strings.ToLower(filepath.Ext(in.Entry.Path))
	if _, ok := databaseExtensions[ext]; !ok {
		return nil
	}
	return []core.Protection{protect(core.ProtectLiveDatabase, core.SourceFilesystem,
		fmt.Sprintf("%s looks like a database file and may have an open writer", filepath.Base(in.Entry.Path)))}
}

// guardDurableEvidence refuses anything classified as durable evidence. A
// correct cleanup of a container must never be what destroys the only copy
// of a record.
func guardDurableEvidence(in Input) []core.Protection {
	if in.Entry.Class != core.ClassEvidence {
		return nil
	}
	return []core.Protection{protect(core.ProtectDurableEvidence, core.SourceFilesystem,
		fmt.Sprintf("%s is classified as durable evidence", in.Entry.Path))}
}

// guardJobOwnership refuses a path a running, queued, or blocked job owns.
func guardJobOwnership(in Input) []core.Protection {
	var out []core.Protection
	for _, job := range in.Jobs {
		if !job.State.Owning() || job.Path == "" {
			continue
		}
		if !overlaps(in.Entry.Path, job.Path) {
			continue
		}
		owner := job.Owner
		if owner == "" {
			owner = "an external scheduler"
		}
		out = append(out, protect(core.ProtectOwningJob, core.SourceJob,
			fmt.Sprintf("job %s (%s, owned by %s) claims %s", job.ID, job.State, owner, job.Path)))
	}
	return out
}

// guardQuarantineFilesystem refuses a destination on another filesystem
// unless an explicit copy policy allows it: a cross-device move is a copy
// and delete, which is not atomic and not reversible by rename.
func guardQuarantineFilesystem(in Input) []core.Protection {
	if in.Target == nil {
		return nil
	}
	if !in.Target.Known {
		detail := in.Target.Detail
		if detail == "" {
			detail = "the destination could not be inspected"
		}
		return []core.Protection{protect(core.ProtectCollectorFailure, core.SourceFilesystem,
			fmt.Sprintf("destination %s is unusable: %s", in.Target.Dir, detail))}
	}
	if in.Policy.AllowCrossFilesystemCopy || in.Entry.FilesystemID.Zero() {
		return nil
	}
	if in.Target.Device == in.Entry.FilesystemID.Device {
		return nil
	}
	return []core.Protection{protect(core.ProtectCrossFilesystem, core.SourceFilesystem,
		fmt.Sprintf("destination %s is on device %d, the item is on device %d, and no cross-filesystem copy policy is configured",
			in.Target.Dir, in.Target.Device, in.Entry.FilesystemID.Device))}
}

// guardFreeSpace refuses a mutation that would leave the destination
// filesystem without the configured headroom.
func guardFreeSpace(in Input) []core.Protection {
	if in.Target == nil || !in.Target.Known {
		// An unknown destination is already refused by the filesystem guard.
		return nil
	}
	// A same-filesystem quarantine is a rename: it consumes no space, so
	// there is nothing to measure. Only a cross-device copy does, and that
	// already requires an explicit policy.
	sameFilesystem := !in.Entry.FilesystemID.Zero() && in.Target.Device == in.Entry.FilesystemID.Device
	if sameFilesystem {
		return nil
	}
	// A copy needs the real size. A directory measured by lstat reports
	// about one block regardless of what it contains, so accepting that
	// number would approve copying an arbitrarily large tree into a
	// filesystem that cannot hold it.
	if in.Entry.Kind == core.EntryKindDirectory && !in.Entry.SizeIsDeep {
		return []core.Protection{protect(core.ProtectInsufficientSpace, core.SourceFilesystem,
			fmt.Sprintf("%s would be copied to %s on another filesystem, but its size is unmeasured: "+
				"the recorded %d byte(s) is directory metadata, not the size of its contents",
				in.Entry.Path, in.Target.Dir, in.Entry.SizeBytes))}
	}
	required := in.Entry.SizeBytes + in.Policy.MinFreeBytes
	if in.Target.FreeBytes >= required {
		return nil
	}
	return []core.Protection{protect(core.ProtectInsufficientSpace, core.SourceFilesystem,
		fmt.Sprintf("destination %s has %d free byte(s); %d are required for %d byte(s) plus %d byte(s) of headroom",
			in.Target.Dir, in.Target.FreeBytes, required, in.Entry.SizeBytes, in.Policy.MinFreeBytes))}
}
