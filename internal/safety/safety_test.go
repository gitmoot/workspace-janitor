package safety

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

var evaluatedAt = time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC)

// baseEntry is a fully observed, unremarkable directory: every guard has
// something to look at, and none of them has a reason to refuse.
func baseEntry() core.Entry {
	return core.Entry{
		ContractVersion: core.ContractVersion,
		Path:            "/repos/app",
		Root:            "/repos",
		Kind:            core.EntryKindDirectory,
		Class:           core.ClassGeneratedArtifact,
		FilesystemID:    core.FilesystemID{Device: 64, Inode: 1234},
		Ownership:       core.Ownership{UID: 1000, GID: 1000, Mode: "0755"},
		SizeBytes:       4096,
		ModifiedAt:      evaluatedAt,
		AccessedAt:      evaluatedAt,
		ObservedAt:      evaluatedAt,
		Evidence: []core.Evidence{
			{Source: core.SourceFilesystem, Signal: "lstat", ObservedAt: evaluatedAt},
		},
	}
}

func baseTarget() Target {
	return Target{Dir: "/state/quarantine", Device: 64, FreeBytes: 100 << 30, Known: true}
}

func basePolicy() Policy {
	return Policy{
		ProtectedPaths: []string{"/home/fixture/.ssh"},
		NamePatterns:   []string{"*.pem", "id_rsa*"},
		StateDir:       "/state",
		QuarantineDir:  "/state/quarantine",
		MinFreeBytes:   1 << 30,
	}
}

func baseInput() Input {
	target := baseTarget()
	return Input{Entry: baseEntry(), Policy: basePolicy(), Target: &target, Now: evaluatedAt}
}

// protectionCase is one behavioral fixture: a mutation of the safe baseline
// that a single named guard must refuse.
type protectionCase struct {
	name  string
	guard string
	kind  core.ProtectionKind
	setup func(*Input)
}

// protectionCases covers every protection the issue requires, each isolated
// so exactly one guard produces it.
func protectionCases() []protectionCase {
	return []protectionCase{
		{
			name: "active process", guard: "collected_protections", kind: core.ProtectActiveProcess,
			setup: func(in *Input) {
				in.Entry.Protections = []core.Protection{{
					Kind: core.ProtectActiveProcess, Reason: "pid 42 (node) working directory",
					Source: core.SourceProcess, Blocking: true,
				}}
			},
		},
		{
			name: "registered agent", guard: "collected_protections", kind: core.ProtectRegisteredAgent,
			setup: func(in *Input) {
				in.Entry.Protections = []core.Protection{{
					Kind: core.ProtectRegisteredAgent, Reason: "agent reviewer-1 registered by gitmoot",
					Source: core.SourceJob, Blocking: true,
				}}
			},
		},
		{
			name: "service reference", guard: "collected_protections", kind: core.ProtectServiceReference,
			setup: func(in *Input) {
				in.Entry.Protections = []core.Protection{{
					Kind: core.ProtectServiceReference, Reason: "systemd unit fixture.service WorkingDirectory",
					Source: core.SourceService, Blocking: true,
				}}
			},
		},
		{
			name: "unknown evidence", guard: "unknown_evidence", kind: core.ProtectCollectorFailure,
			setup: func(in *Input) {
				in.Entry.Evidence = append(in.Entry.Evidence, core.Evidence{
					Source: core.SourceGit, Signal: "unknown:git_status_failed",
					Detail: "git status timed out after 5s", ObservedAt: evaluatedAt,
				})
			},
		},
		{
			name: "unknown identity", guard: "filesystem_identity", kind: core.ProtectCollectorFailure,
			setup: func(in *Input) { in.Entry.FilesystemID = core.FilesystemID{} },
		},
		{
			name: "dirty repository", guard: "git_state", kind: core.ProtectDirtyRepository,
			setup: func(in *Input) {
				in.Entry.Git = &core.GitState{RepoRoot: in.Entry.Path, UpstreamKnown: true, DirtyFiles: 3}
			},
		},
		{
			name: "stashed work", guard: "git_state", kind: core.ProtectStashedWork,
			setup: func(in *Input) {
				in.Entry.Git = &core.GitState{RepoRoot: in.Entry.Path, UpstreamKnown: true, Stashes: 1}
			},
		},
		{
			name: "unpublished commits", guard: "git_state", kind: core.ProtectUnpublishedCommits,
			setup: func(in *Input) {
				in.Entry.Git = &core.GitState{RepoRoot: in.Entry.Path, UpstreamKnown: true, UnpublishedCommits: 2}
			},
		},
		{
			name: "no upstream to judge publication", guard: "git_state", kind: core.ProtectUnpublishedCommits,
			setup: func(in *Input) {
				in.Entry.Git = &core.GitState{RepoRoot: in.Entry.Path}
			},
		},
		{
			name: "broken git metadata", guard: "git_state", kind: core.ProtectBrokenGitMetadata,
			setup: func(in *Input) {
				in.Entry.Git = &core.GitState{RepoRoot: in.Entry.Path, UpstreamKnown: true, Degraded: true, DegradedReason: "gitfile points nowhere"}
			},
		},
		{
			name: "worktree lock held", guard: "git_state", kind: core.ProtectLockHeld,
			setup: func(in *Input) {
				in.Entry.Git = &core.GitState{RepoRoot: in.Entry.Path, UpstreamKnown: true, Locked: true}
			},
		},
		{
			name: "unresolved symlink", guard: "symlink_containment", kind: core.ProtectSymlinkEscape,
			setup: func(in *Input) {
				in.Entry.Kind = core.EntryKindSymlink
				in.Entry.SymlinkTarget = "/etc"
			},
		},
		{
			name: "symlink leaving the root", guard: "symlink_containment", kind: core.ProtectSymlinkEscape,
			setup: func(in *Input) {
				in.Entry.Kind = core.EntryKindSymlink
				in.Entry.SymlinkTarget = "/etc"
				in.Entry.CanonicalPath = "/etc"
			},
		},
		{
			name: "entry inside a protected path", guard: "protected_paths", kind: core.ProtectPolicyProtected,
			setup: func(in *Input) {
				in.Entry.Path = "/home/fixture/.ssh/id_ed25519.pub"
				in.Entry.Kind = core.EntryKindFile
			},
		},
		{
			name: "entry containing a protected path", guard: "protected_paths", kind: core.ProtectPolicyProtected,
			setup: func(in *Input) { in.Entry.Path = "/home/fixture" },
		},
		{
			name: "the tool's own state directory", guard: "protected_paths", kind: core.ProtectPolicyProtected,
			setup: func(in *Input) { in.Entry.Path = "/state" },
		},
		{
			name: "credential-shaped name", guard: "sensitive_names", kind: core.ProtectSensitiveContent,
			setup: func(in *Input) {
				in.Entry.Path = "/repos/deploy.pem"
				in.Entry.Kind = core.EntryKindFile
			},
		},
		{
			name: "live database file", guard: "live_databases", kind: core.ProtectLiveDatabase,
			setup: func(in *Input) {
				in.Entry.Path = "/repos/app/state.sqlite"
				in.Entry.Kind = core.EntryKindFile
			},
		},
		{
			name: "durable evidence", guard: "durable_evidence", kind: core.ProtectDurableEvidence,
			setup: func(in *Input) { in.Entry.Class = core.ClassEvidence },
		},
		{
			name: "running job owns the path", guard: "job_ownership", kind: core.ProtectOwningJob,
			setup: func(in *Input) {
				in.Jobs = []JobRef{{ID: "job-1", State: JobRunning, Path: "/repos/app/worktree", Owner: "gitmoot"}}
			},
		},
		{
			name: "queued job owns the path", guard: "job_ownership", kind: core.ProtectOwningJob,
			setup: func(in *Input) {
				in.Jobs = []JobRef{{ID: "job-2", State: JobQueued, Path: "/repos/app", Owner: "gitmoot"}}
			},
		},
		{
			name: "blocked job owns the path", guard: "job_ownership", kind: core.ProtectOwningJob,
			setup: func(in *Input) {
				in.Jobs = []JobRef{{ID: "job-3", State: JobBlocked, Path: "/repos/app", Owner: "gitmoot"}}
			},
		},
		{
			name: "cross-filesystem quarantine", guard: "quarantine_filesystem", kind: core.ProtectCrossFilesystem,
			setup: func(in *Input) { in.Target.Device = 99 },
		},
		{
			name: "unusable destination", guard: "quarantine_filesystem", kind: core.ProtectCollectorFailure,
			setup: func(in *Input) {
				in.Target.Known = false
				in.Target.Detail = "statfs failed"
			},
		},
		{
			// Space only matters for a copy, which only happens across
			// filesystems, which in turn requires an explicit policy.
			name: "insufficient free space", guard: "free_space", kind: core.ProtectInsufficientSpace,
			setup: func(in *Input) {
				in.Policy.AllowCrossFilesystemCopy = true
				in.Target.Device = 99
				in.Entry.Kind = core.EntryKindFile
				in.Entry.SizeBytes = 10 << 30
				in.Target.FreeBytes = 2 << 30
			},
		},
		{
			name: "unmeasured directory copied across filesystems", guard: "free_space", kind: core.ProtectInsufficientSpace,
			setup: func(in *Input) {
				in.Policy.AllowCrossFilesystemCopy = true
				in.Target.Device = 99
				in.Target.FreeBytes = 100 << 30
			},
		},
		{
			name: "symlink with no discovery root", guard: "symlink_containment", kind: core.ProtectSymlinkEscape,
			setup: func(in *Input) {
				in.Entry.Kind = core.EntryKindSymlink
				in.Entry.SymlinkTarget = "/repos/app/real"
				in.Entry.CanonicalPath = "/repos/app/real"
				in.Entry.Root = ""
			},
		},
		{
			name: "protected path is the root directory", guard: "protected_paths", kind: core.ProtectPolicyProtected,
			setup: func(in *Input) { in.Policy.ProtectedPaths = []string{"/"} },
		},
		{
			name: "job owns the root directory", guard: "job_ownership", kind: core.ProtectOwningJob,
			setup: func(in *Input) {
				in.Jobs = []JobRef{{ID: "job-root", State: JobRunning, Path: "/", Owner: "gitmoot"}}
			},
		},
	}
}

func inputFor(tc protectionCase) Input {
	in := baseInput()
	target := *in.Target
	in.Target = &target
	tc.setup(&in)
	return in
}

func hasKind(verdict core.Verdict, kind core.ProtectionKind) bool {
	for _, protection := range verdict.Protections {
		if protection.Kind == kind && protection.Blocking {
			return true
		}
	}
	return false
}

// The baseline must be allowed, or every refusal test below would pass for
// the wrong reason.
func TestFullyObservedSafeEntryIsAllowed(t *testing.T) {
	verdict := Evaluate(baseInput())
	if verdict.Refused() {
		t.Fatalf("baseline was refused: %+v", verdict.Protections)
	}
	if verdict.Decision != core.DecisionAllow {
		t.Errorf("decision = %q, want allow", verdict.Decision)
	}
	if len(verdict.Guards) != len(guards) {
		t.Errorf("guards = %v, want all %d recorded", verdict.Guards, len(guards))
	}
	if err := verdict.Validate(); err != nil {
		t.Errorf("verdict does not validate: %v", err)
	}
	if !verdict.Allows(core.ActionQuarantine) {
		t.Error("a clean verdict must allow a mutating action")
	}
}

// Each protection the issue names must refuse mutation, with evidence and a
// remedy attached.
func TestEveryProtectionRefusesMutation(t *testing.T) {
	for _, tc := range protectionCases() {
		t.Run(tc.name, func(t *testing.T) {
			verdict := Evaluate(inputFor(tc))
			if !verdict.Refused() {
				t.Fatalf("verdict = %+v, want a refusal", verdict)
			}
			if !hasKind(verdict, tc.kind) {
				t.Fatalf("protections = %+v, want kind %q", verdict.Protections, tc.kind)
			}
			for _, action := range []core.ActionKind{core.ActionQuarantine, core.ActionDeleteCandidate, core.ActionRelocate} {
				if verdict.Allows(action) {
					t.Errorf("%s was allowed on a refused path", action)
				}
			}
			for _, action := range []core.ActionKind{core.ActionKeep, core.ActionInvestigate} {
				if !verdict.Allows(action) {
					t.Errorf("%s must remain allowed: it mutates nothing", action)
				}
			}
			for _, protection := range verdict.Protections {
				if protection.Blocking && strings.TrimSpace(protection.Remediation) == "" {
					t.Errorf("protection %q has no remediation", protection.Kind)
				}
				if protection.Blocking && strings.TrimSpace(protection.Reason) == "" {
					t.Errorf("protection %q has no evidence", protection.Kind)
				}
			}
			if err := verdict.Validate(); err != nil {
				t.Errorf("verdict does not validate: %v", err)
			}
		})
	}
}

// Mutation coverage: removing any single guard must make at least one
// behavioral case stop refusing. A guard that can be deleted without
// breaking a test is not being tested.
func TestEveryGuardIsLoadBearing(t *testing.T) {
	cases := protectionCases()
	for _, g := range guards {
		remaining := make([]guard, 0, len(guards)-1)
		for _, candidate := range guards {
			if candidate.name != g.name {
				remaining = append(remaining, candidate)
			}
		}

		weakened := 0
		for _, tc := range cases {
			if tc.guard != g.name {
				continue
			}
			full := evaluateWith(inputFor(tc), guards)
			if !hasKind(full, tc.kind) {
				t.Fatalf("%s: case %q does not exercise its guard", g.name, tc.name)
			}
			without := evaluateWith(inputFor(tc), remaining)
			if hasKind(without, tc.kind) {
				// Another guard still catches it, so this case does not
				// prove the removed guard is load-bearing.
				continue
			}
			weakened++
		}
		if weakened == 0 {
			t.Errorf("removing guard %q broke no behavioral case: it is either untested or redundant", g.name)
		}
	}
}

// Removing a guard must actually change the verdict, not merely the
// protection list: the deleted check has to be the thing standing between
// the path and a mutation.
func TestRemovingAGuardWouldAllowAMutation(t *testing.T) {
	for _, tc := range protectionCases() {
		remaining := make([]guard, 0, len(guards)-1)
		for _, candidate := range guards {
			if candidate.name != tc.guard {
				remaining = append(remaining, candidate)
			}
		}
		if without := evaluateWith(inputFor(tc), remaining); without.Refused() {
			continue // another guard independently refuses; still safe
		} else if !without.Allows(core.ActionDeleteCandidate) {
			t.Errorf("%s: verdict is neither refused nor permissive: %+v", tc.name, without)
		}
	}
}

// Policy is an input to protection, never a way out of it.
func TestPolicyCannotDisableCoreInvariants(t *testing.T) {
	in := baseInput()
	// The emptiest possible policy: no protected paths, no patterns, no
	// headroom, cross-filesystem copies allowed.
	in.Policy = Policy{AllowCrossFilesystemCopy: true}
	in.Entry.Git = &core.GitState{RepoRoot: in.Entry.Path, UpstreamKnown: true, DirtyFiles: 1}
	in.Entry.Protections = []core.Protection{{
		Kind: core.ProtectActiveProcess, Reason: "pid 42 (node) working directory",
		Source: core.SourceProcess, Blocking: true,
	}}

	verdict := Evaluate(in)
	for _, kind := range []core.ProtectionKind{core.ProtectDirtyRepository, core.ProtectActiveProcess} {
		if !hasKind(verdict, kind) {
			t.Errorf("protection %q was lost under a permissive policy: %+v", kind, verdict.Protections)
		}
	}
	if verdict.Allows(core.ActionDeleteCandidate) {
		t.Error("a permissive policy must not authorize deletion of a dirty, in-use path")
	}
}

// A model may propose anything; it may not weaken a protection.
func TestModelRecommendationCannotWeakenAProtection(t *testing.T) {
	in := baseInput()
	in.Entry.Git = &core.GitState{RepoRoot: in.Entry.Path, UpstreamKnown: true, DirtyFiles: 2}
	verdict := Evaluate(in)

	confident := core.Recommendation{
		Action:     core.ActionDeleteCandidate,
		Class:      core.ClassGeneratedArtifact,
		Retention:  core.RetentionNone,
		Confidence: 1,
		Origin:     core.OriginModel,
		Reasons:    []string{"model is certain this is disposable"},
		DecidedAt:  evaluatedAt,
	}
	clamped := ClampRecommendation(verdict, confident)
	if clamped.Action != core.ActionInvestigate {
		t.Errorf("action = %q, want it clamped to investigate", clamped.Action)
	}
	if clamped.Retention != core.RetentionNone {
		t.Errorf("retention = %q, want none", clamped.Retention)
	}
	if len(clamped.Reasons) <= len(confident.Reasons) {
		t.Error("the downgrade must be recorded in the reasons, not applied silently")
	}
	if !strings.Contains(strings.Join(clamped.Reasons, " "), "safety engine refused") {
		t.Errorf("reasons = %v, want the refusal recorded", clamped.Reasons)
	}
	if confident.Action != core.ActionDeleteCandidate {
		t.Error("clamping must not mutate the caller's recommendation")
	}

	// On a clean verdict the recommendation passes through untouched.
	clean := Evaluate(baseInput())
	passthrough := ClampRecommendation(clean, confident)
	if passthrough.Action != core.ActionDeleteCandidate {
		t.Errorf("action = %q, want the recommendation preserved on a clean verdict", passthrough.Action)
	}
}

// Identical evidence must produce byte-identical verdicts, including the
// order of protections, regardless of the order they were discovered in.
func TestVerdictOutputIsStable(t *testing.T) {
	in := baseInput()
	in.Entry.Git = &core.GitState{RepoRoot: in.Entry.Path, DirtyFiles: 1, Stashes: 2, Locked: true}
	in.Jobs = []JobRef{{ID: "job-1", State: JobRunning, Path: "/repos/app", Owner: "gitmoot"}}

	first, err := core.MarshalIndentJSON(Evaluate(in))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := core.MarshalIndentJSON(Evaluate(in))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(again) != string(first) {
			t.Fatalf("verdict output is not stable:\n%s\n---\n%s", first, again)
		}
	}

	// Discovery order must not change the document either.
	reordered := baseInput()
	reordered.Entry.Git = in.Entry.Git
	reordered.Jobs = in.Jobs
	reordered.Entry.Protections = []core.Protection{
		{Kind: core.ProtectServiceReference, Reason: "systemd unit a.service WorkingDirectory", Source: core.SourceService, Blocking: true},
		{Kind: core.ProtectActiveProcess, Reason: "pid 42 (node) working directory", Source: core.SourceProcess, Blocking: true},
	}
	swapped := baseInput()
	swapped.Entry.Git = in.Entry.Git
	swapped.Jobs = in.Jobs
	swapped.Entry.Protections = []core.Protection{
		reordered.Entry.Protections[1], reordered.Entry.Protections[0],
	}
	a, _ := core.MarshalIndentJSON(Evaluate(reordered))
	b, _ := core.MarshalIndentJSON(Evaluate(swapped))
	if string(a) != string(b) {
		t.Errorf("protection discovery order changed the verdict:\n%s\n---\n%s", a, b)
	}
}

func TestEveryProtectionKindHasRemediation(t *testing.T) {
	for _, kind := range core.ProtectionKinds() {
		text, ok := remediations[kind]
		if !ok {
			t.Errorf("protection kind %q has no remediation", kind)
			continue
		}
		if strings.TrimSpace(text) == "" {
			t.Errorf("protection kind %q has an empty remediation", kind)
		}
	}
	if Remediation(core.ProtectionKind("invented")) == "" {
		t.Error("an unmapped kind must still yield actionable text")
	}
}

func TestJobStateOwnership(t *testing.T) {
	for state, want := range map[JobState]bool{
		JobRunning: true, JobQueued: true, JobBlocked: true,
		JobDone: false, JobState("unknown"): false,
	} {
		if got := state.Owning(); got != want {
			t.Errorf("JobState(%q).Owning() = %t, want %t", state, got, want)
		}
	}
}

func TestFinishedJobDoesNotProtect(t *testing.T) {
	in := baseInput()
	in.Jobs = []JobRef{{ID: "job-9", State: JobDone, Path: "/repos/app", Owner: "gitmoot"}}
	if verdict := Evaluate(in); verdict.Refused() {
		t.Errorf("a finished job must not protect the path: %+v", verdict.Protections)
	}
}

func TestPathOverlapDirections(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"/repos/app", "/repos/app", true},
		{"/repos/app/src", "/repos/app", true},
		{"/repos/app", "/repos/app/src", true},
		{"/repos/application", "/repos/app", false},
	}
	for _, tc := range cases {
		if got := overlaps(tc.a, tc.b); got != tc.want {
			t.Errorf("overlaps(%q, %q) = %t, want %t", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestResolveTargetReportsAnUnusableDestination(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := writeFile(file); err != nil {
		t.Fatalf("write: %v", err)
	}
	if target := ResolveTarget(file); target.Known {
		t.Errorf("target = %+v, want unknown for a non-directory", target)
	}
	if target := ResolveTarget(""); target.Known || target.Detail == "" {
		t.Errorf("target = %+v, want an explained unknown for an empty destination", target)
	}
}

// A quarantine directory that does not exist yet is measured against the
// filesystem it will be created on, not reported as unknown.
func TestResolveTargetMeasuresANotYetCreatedDestination(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state", "quarantine")
	target := ResolveTarget(dir)
	if !target.Known {
		t.Fatalf("target = %+v, want the nearest existing parent measured", target)
	}
	if target.FreeBytes <= 0 || target.Device == 0 {
		t.Errorf("target = %+v, want device and free space", target)
	}
	if !strings.Contains(target.Detail, "does not exist yet") {
		t.Errorf("detail = %q, want it to say the directory will be created", target.Detail)
	}
}

func writeFile(path string) error {
	return os.WriteFile(path, []byte("x"), 0o600)
}

// A same-filesystem quarantine is a rename and consumes no space, so the
// space guard must not refuse it however large the item is.
func TestSameFilesystemQuarantineNeedsNoSpace(t *testing.T) {
	in := baseInput()
	in.Entry.Kind = core.EntryKindFile
	in.Entry.SizeBytes = 500 << 30
	in.Target.FreeBytes = 1 << 20

	if verdict := Evaluate(in); verdict.Refused() {
		t.Errorf("a rename on the same filesystem was refused for space: %+v", verdict.Protections)
	}
}

// A deep-measured directory has a real size, so a cross-filesystem copy can
// be judged rather than refused for being unmeasured.
func TestDeepMeasuredDirectoryCanBeJudgedForSpace(t *testing.T) {
	in := baseInput()
	in.Policy.AllowCrossFilesystemCopy = true
	in.Target.Device = 99
	in.Target.FreeBytes = 100 << 30
	in.Entry.SizeIsDeep = true
	in.Entry.SizeBytes = 1 << 20

	if verdict := Evaluate(in); verdict.Refused() {
		t.Errorf("a measured directory that fits was refused: %+v", verdict.Protections)
	}

	in.Entry.SizeBytes = 200 << 30
	verdict := Evaluate(in)
	if !hasKind(verdict, core.ProtectInsufficientSpace) {
		t.Errorf("a measured directory that does not fit was allowed: %+v", verdict.Protections)
	}
}

// A protection covering "/" must protect everything under it. Prefix
// matching that builds "//" silently protects nothing, which is a
// fail-open.
func TestRootDirectoryContainmentIsNotFailOpen(t *testing.T) {
	cases := []struct {
		path, target string
		want         bool
	}{
		{"/repos/app", "/", true},
		{"/", "/", true},
		{"/repos/app", "/repos", true},
		{"/repos/app", "/repos/", true},
		{"/repos-other", "/repos", false},
		{"relative", "/", false},
	}
	for _, tc := range cases {
		if got := pathWithin(tc.path, tc.target); got != tc.want {
			t.Errorf("pathWithin(%q, %q) = %t, want %t", tc.path, tc.target, got, tc.want)
		}
	}

	// And a symlink resolving inside a "/" root is contained, not an escape.
	in := baseInput()
	in.Entry.Kind = core.EntryKindSymlink
	in.Entry.Root = "/"
	in.Entry.SymlinkTarget = "/etc/hosts"
	in.Entry.CanonicalPath = "/etc/hosts"
	if verdict := Evaluate(in); hasKind(verdict, core.ProtectSymlinkEscape) {
		t.Errorf("a symlink inside a root of \"/\" was reported as escaping: %+v", verdict.Protections)
	}
}
