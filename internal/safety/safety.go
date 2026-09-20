// Package safety decides whether a path may be mutated.
//
// It is the only authority on that question. Classification, policy, and any
// model answer are inputs to planning; none of them can clear a protection
// this package raises. Three rules hold throughout:
//
//   - Deterministic. The same evidence always produces the same typed
//     verdict, with protections in the same order.
//   - Fail closed. Evidence that is missing, degraded, or unknown protects
//     the path. Absence of a signal is never read as absence of risk.
//   - Revalidated. A verdict describes the moment it was computed. Every
//     mutation must re-run the guards immediately beforehand, because the
//     filesystem can change between planning and applying.
package safety

import (
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// Policy is the subset of configuration the engine consults.
//
// It can only add protection. There is deliberately no field that disables a
// core invariant: doing that would require a separately named unsafe build
// mode, which this release does not provide.
type Policy struct {
	ProtectedPaths           []string
	NamePatterns             []string
	StateDir                 string
	QuarantineDir            string
	AllowCrossFilesystemCopy bool
	MinFreeBytes             int64
}

// JobState is the lifecycle state of a job that may own a path.
type JobState string

const (
	JobRunning JobState = "running"
	JobQueued  JobState = "queued"
	JobBlocked JobState = "blocked"
	JobDone    JobState = "done"
)

// Owning reports whether a job in this state still owns its path.
func (s JobState) Owning() bool {
	switch s {
	case JobRunning, JobQueued, JobBlocked:
		return true
	default:
		return false
	}
}

// JobRef is one job's claim on a path, supplied by an external scheduler.
type JobRef struct {
	ID    string
	State JobState
	Path  string
	Owner string
}

// Target describes where a quarantine or relocation would put an item.
//
// Known is false when the destination could not be inspected; that is an
// unknown, and unknowns protect the path rather than being ignored.
type Target struct {
	Dir       string
	Device    uint64
	FreeBytes int64
	Known     bool
	Detail    string
}

// Input is everything one evaluation may consider.
type Input struct {
	Entry  core.Entry
	Policy Policy
	Jobs   []JobRef
	// Target is the destination a mutation would use. Nil means no mutation
	// destination is in play, so destination guards do not apply.
	Target *Target
	Now    time.Time
}

func (in Input) now() time.Time {
	if in.Now.IsZero() {
		return time.Now().UTC()
	}
	return in.Now.UTC()
}

// guard is one deterministic check. Guards are registered in this package
// and are not configurable: policy adds protections, it never removes them.
type guard struct {
	name  string
	check func(Input) []core.Protection
}

// guards is the complete set of core invariants, in registration order.
var guards = []guard{
	{"collected_protections", guardCollectedProtections},
	{"unknown_evidence", guardUnknownEvidence},
	{"filesystem_identity", guardFilesystemIdentity},
	{"git_state", guardGitState},
	{"symlink_containment", guardSymlinkContainment},
	{"protected_paths", guardProtectedPaths},
	{"sensitive_names", guardSensitiveNames},
	{"live_databases", guardLiveDatabases},
	{"durable_evidence", guardDurableEvidence},
	{"job_ownership", guardJobOwnership},
	{"quarantine_filesystem", guardQuarantineFilesystem},
	{"free_space", guardFreeSpace},
}

// GuardNames lists every core invariant this build enforces.
func GuardNames() []string {
	names := make([]string, len(guards))
	for i, g := range guards {
		names[i] = g.name
	}
	return names
}

// Evaluate produces the safety verdict for one entry.
func Evaluate(in Input) core.Verdict { return evaluateWith(in, guards) }

// evaluateWith runs a specific guard set. Tests use it to remove one guard
// at a time and prove that each is load-bearing.
func evaluateWith(in Input, active []guard) core.Verdict {
	verdict := core.Verdict{
		Path:        in.Entry.Path,
		EvaluatedAt: in.now(),
		Guards:      make([]string, 0, len(active)),
	}
	for _, g := range active {
		verdict.Guards = append(verdict.Guards, g.name)
		for _, protection := range g.check(in) {
			if protection.Remediation == "" {
				protection.Remediation = Remediation(protection.Kind)
			}
			addProtection(&verdict, protection)
		}
	}
	verdict.Normalize()
	return verdict
}

// ClampRecommendation forces a recommendation to obey the verdict.
//
// A model may propose anything; this is where its proposal stops mattering.
// A mutating action on a refused path becomes "investigate", the retention
// is cleared, and the refusal is recorded in the reasons so the downgrade is
// visible rather than silent.
func ClampRecommendation(verdict core.Verdict, rec core.Recommendation) core.Recommendation {
	if verdict.Allows(rec.Action) {
		return rec
	}
	clamped := rec
	clamped.Action = core.ActionInvestigate
	clamped.Retention = core.RetentionNone
	clamped.Reasons = append(append([]string{}, rec.Reasons...),
		"safety engine refused "+string(rec.Action)+": "+verdict.Summary())
	return clamped
}

func addProtection(verdict *core.Verdict, protection core.Protection) {
	for _, existing := range verdict.Protections {
		if existing.Kind == protection.Kind && existing.Reason == protection.Reason {
			return
		}
	}
	verdict.Protections = append(verdict.Protections, protection)
}

func protect(kind core.ProtectionKind, source core.EvidenceSource, reason string) core.Protection {
	return core.Protection{
		Kind:        kind,
		Reason:      reason,
		Source:      source,
		Remediation: Remediation(kind),
		Blocking:    true,
	}
}

// pathWithin and overlaps delegate to the shared containment rules, which
// handle the root directory correctly.
func pathWithin(path, target string) bool { return core.PathWithin(path, target) }

func overlaps(a, b string) bool { return core.PathsOverlap(a, b) }
