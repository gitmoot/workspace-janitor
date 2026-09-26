package plan

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/safety"
)

var plannedAt = time.Date(2026, 7, 8, 9, 10, 11, 0, time.UTC)

// fixturePolicy is the documented default policy over a fixture home. Tests
// never read the operator's real configuration.
func fixturePolicy() config.Policy {
	paths := config.Paths{
		Home:          "/home/fixture",
		ConfigDir:     "/home/fixture/.config/workspace-janitor",
		StateDir:      "/home/fixture/.local/state/workspace-janitor",
		CacheDir:      "/home/fixture/.cache/workspace-janitor",
		QuarantineDir: "/home/fixture/.local/state/workspace-janitor/quarantine",
	}
	policy := config.DefaultPolicy(paths)
	policy.CanonicalRoots = []config.CanonicalRoot{
		{Class: core.ClassPrimaryProject, Path: "/home/fixture/repos"},
	}
	return policy
}

// entryAt builds a fully observed directory entry, which is the normal
// case: an entry with unknown evidence is refused by the safety engine and
// would mask what the planner did.
func entryAt(path string, options ...func(*core.Entry)) core.Entry {
	entry := core.Entry{
		ContractVersion: core.ContractVersion,
		Path:            path,
		Root:            "/home/fixture",
		Kind:            core.EntryKindDirectory,
		Class:           core.ClassUnknown,
		FilesystemID:    core.FilesystemID{Device: 64, Inode: uint64(len(path)) + 1000},
		Ownership:       core.Ownership{UID: 1000, GID: 1000, Mode: "0755"},
		SizeBytes:       4096,
		ModifiedAt:      plannedAt,
		AccessedAt:      plannedAt,
		ObservedAt:      plannedAt,
		Fingerprint:     "fingerprint-" + path,
		Evidence: []core.Evidence{
			{Source: core.SourceFilesystem, Signal: "lstat", ObservedAt: plannedAt},
		},
	}
	for _, option := range options {
		option(&entry)
	}
	return entry
}

func withGit(state *core.GitState) func(*core.Entry) {
	return func(e *core.Entry) { e.Git = state }
}

func withClass(class core.ArtifactClass) func(*core.Entry) {
	return func(e *core.Entry) { e.Class = class }
}

func cleanTarget() *safety.Target {
	return &safety.Target{Dir: "/home/fixture/.local/state/workspace-janitor/quarantine",
		Device: 64, FreeBytes: 500 << 30, Known: true}
}

func buildPlan(t *testing.T, entries []core.Entry, policy config.Policy, advisor Advisor) Result {
	t.Helper()
	result, err := Build(context.Background(), Input{
		ScanID:  "scan-1",
		Entries: entries,
		Policy:  policy,
		Safety: safety.Policy{
			ProtectedPaths: policy.Protect.Paths,
			NamePatterns:   policy.Protect.NamePatterns,
			StateDir:       "/home/fixture/.local/state/workspace-janitor",
			QuarantineDir:  policy.Retention.QuarantineDir,
			MinFreeBytes:   policy.Safety.MinFreeBytes,
		},
		Target:  cleanTarget(),
		Now:     plannedAt,
		Advisor: advisor,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return result
}

func actionFor(t *testing.T, result Result, path string) core.Action {
	t.Helper()
	for _, action := range result.Plan.Actions {
		if action.Path == path {
			return action
		}
	}
	t.Fatalf("no action for %s", path)
	return core.Action{}
}

// The policy fixtures the issue asks for: home top level, canonical repos,
// review clones, generated artifacts, caches, backups, and unknown paths.
func TestPolicyFixturesProduceTheExpectedActions(t *testing.T) {
	policy := fixturePolicy()
	entries := []core.Entry{
		entryAt("/home/fixture/repos/app", withGit(&core.GitState{
			RepoRoot: "/home/fixture/repos/app", Branch: "main", UpstreamKnown: true, PublicationKnown: true,
		})),
		entryAt("/home/fixture/scratch/clone", withGit(&core.GitState{
			RepoRoot: "/home/fixture/scratch/clone", Branch: "main", UpstreamKnown: true, PublicationKnown: true,
		})),
		entryAt("/home/fixture/repos/app-wt-review", withGit(&core.GitState{
			RepoRoot: "/home/fixture/repos/app-wt-review", WorktreeOf: "/home/fixture/repos/app",
			Branch: "review", UpstreamKnown: true, PublicationKnown: true,
			LastActivity: plannedAt.Add(-WorktreeIdle - time.Hour),
		})),
		entryAt("/home/fixture/repos/app-wt-current", withGit(&core.GitState{
			RepoRoot: "/home/fixture/repos/app-wt-current", WorktreeOf: "/home/fixture/repos/app",
			Branch: "current", UpstreamKnown: true, PublicationKnown: true,
			LastActivity: plannedAt.Add(-time.Hour),
		})),
		entryAt("/home/fixture/repos/app-wt-local", withGit(&core.GitState{
			RepoRoot: "/home/fixture/repos/app-wt-local", WorktreeOf: "/home/fixture/repos/app",
			Branch: "local", UpstreamKnown: true, PublicationKnown: true, UnpublishedCommits: 1,
			LastActivity: plannedAt.Add(-WorktreeIdle - time.Hour),
		})),
		entryAt("/home/fixture/repos/app/node_modules"),
		entryAt("/home/fixture/.cache"),
		entryAt("/home/fixture/.pytest_cache"),
		entryAt("/home/fixture/backups"),
		entryAt("/home/fixture/mystery"),
		entryAt("/home/fixture/incidents", withClass(core.ClassEvidence)),
	}

	result := buildPlan(t, entries, policy, nil)
	want := map[string]struct {
		kind  core.ActionKind
		class core.ArtifactClass
	}{
		"/home/fixture/repos/app":              {core.ActionKeep, core.ClassPrimaryProject},
		"/home/fixture/scratch/clone":          {core.ActionRelocate, core.ClassPrimaryProject},
		"/home/fixture/repos/app-wt-review":    {core.ActionQuarantine, core.ClassTaskWorktree},
		"/home/fixture/repos/app-wt-current":   {core.ActionInvestigate, core.ClassTaskWorktree},
		"/home/fixture/repos/app-wt-local":     {core.ActionKeep, core.ClassTaskWorktree},
		"/home/fixture/repos/app/node_modules": {core.ActionQuarantine, core.ClassGeneratedArtifact},
		"/home/fixture/.cache":                 {core.ActionInvestigate, core.ClassCache},
		"/home/fixture/.pytest_cache":          {core.ActionQuarantine, core.ClassCache},
		"/home/fixture/backups":                {core.ActionKeep, core.ClassBackup},
		"/home/fixture/mystery":                {core.ActionInvestigate, core.ClassUnknown},
		"/home/fixture/incidents":              {core.ActionKeep, core.ClassEvidence},
	}
	for path, expected := range want {
		action := actionFor(t, result, path)
		if action.Kind != expected.kind {
			t.Errorf("%s: action = %q, want %q (reasons: %v)", path, action.Kind, expected.kind, action.Reasons)
		}
		if action.Class != expected.class {
			t.Errorf("%s: class = %q, want %q", path, action.Class, expected.class)
		}
		if len(action.Rules) == 0 || len(action.Reasons) == 0 {
			t.Errorf("%s: action carries no rules or reasons: %+v", path, action)
		}
	}

	relocated := actionFor(t, result, "/home/fixture/scratch/clone")
	if relocated.Destination != "/home/fixture/repos/clone" {
		t.Errorf("relocate destination = %q, want the canonical root", relocated.Destination)
	}
}

// The default policy must never recommend deleting anything directly.
func TestDefaultPolicyRecommendsNoDirectDelete(t *testing.T) {
	policy := fixturePolicy()
	entries := []core.Entry{
		entryAt("/home/fixture/repos/app/node_modules"),
		entryAt("/home/fixture/.cache"),
		entryAt("/home/fixture/backups"),
		entryAt("/home/fixture/mystery"),
		entryAt("/home/fixture/dist"),
		entryAt("/home/fixture/target"),
	}
	for _, action := range buildPlan(t, entries, policy, nil).Plan.Actions {
		if action.Kind == core.ActionDeleteCandidate {
			t.Errorf("%s was recommended for direct deletion by the default policy: %+v", action.Path, action)
		}
	}

	// An operator can still ask for one explicitly; that is their decision,
	// not a default.
	explicit := fixturePolicy()
	explicit.Caches = []config.CacheRule{{
		Name: "scratch", Path: "/home/fixture/.cache",
		Action: core.ActionDeleteCandidate, Retention: core.RetentionNone,
	}}
	action := actionFor(t, buildPlan(t, []core.Entry{entryAt("/home/fixture/.cache")}, explicit, nil), "/home/fixture/.cache")
	if action.Kind != core.ActionDeleteCandidate {
		t.Errorf("an explicit delete rule was not honoured: %+v", action)
	}
}

// Rule files are unordered input: reordering them must not change a single
// decision.
func TestReorderingPolicyDoesNotChangeSemantics(t *testing.T) {
	policy := fixturePolicy()
	policy.Caches = []config.CacheRule{
		{Name: "a", Path: "/home/fixture/.cache", Action: core.ActionQuarantine, Retention: core.Retention30Days},
		{Name: "b", Path: "/home/fixture/.cache/go-build", Action: core.ActionQuarantine, Retention: core.Retention7Days},
		{Name: "c", Path: "/home/fixture/scratch", Action: core.ActionInvestigate, Retention: core.RetentionNone},
	}
	policy.Protect.Paths = append(policy.Protect.Paths, "/home/fixture/keepme", "/home/fixture/also-keep")

	entries := []core.Entry{
		entryAt("/home/fixture/.cache"),
		entryAt("/home/fixture/.cache/go-build"),
		entryAt("/home/fixture/scratch"),
		entryAt("/home/fixture/keepme"),
		entryAt("/home/fixture/mystery"),
	}

	baseline, err := core.MarshalJSON(actionsOf(buildPlan(t, entries, policy, nil)))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	random := rand.New(rand.NewPCG(7, 11))
	for i := 0; i < 20; i++ {
		shuffled := fixturePolicy()
		shuffled.Caches = append([]config.CacheRule(nil), policy.Caches...)
		random.Shuffle(len(shuffled.Caches), func(a, b int) {
			shuffled.Caches[a], shuffled.Caches[b] = shuffled.Caches[b], shuffled.Caches[a]
		})
		shuffled.Protect.Paths = append([]string(nil), policy.Protect.Paths...)
		random.Shuffle(len(shuffled.Protect.Paths), func(a, b int) {
			shuffled.Protect.Paths[a], shuffled.Protect.Paths[b] = shuffled.Protect.Paths[b], shuffled.Protect.Paths[a]
		})
		shuffledEntries := append([]core.Entry(nil), entries...)
		random.Shuffle(len(shuffledEntries), func(a, b int) {
			shuffledEntries[a], shuffledEntries[b] = shuffledEntries[b], shuffledEntries[a]
		})

		again, err := core.MarshalJSON(actionsOf(buildPlan(t, shuffledEntries, shuffled, nil)))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(again) != string(baseline) {
			t.Fatalf("reordering policy or entries changed the plan:\n%s\n---\n%s", baseline, again)
		}
	}
}

// actionsOf strips the fields that are expected to differ between runs so
// two plans can be compared by their decisions.
func actionsOf(result Result) []core.Action {
	out := append([]core.Action(nil), result.Plan.Actions...)
	for i := range out {
		out[i].ID = ""
		out[i].PlanID = ""
		out[i].CreatedAt = time.Time{}
	}
	return out
}

// Two rules of equal precedence that disagree resolve to the safer action,
// and the disagreement is recorded rather than arbitrated silently.
func TestConflictingRulesResolveToTheSaferAction(t *testing.T) {
	policy := fixturePolicy()
	policy.Caches = []config.CacheRule{
		{Name: "aggressive", Path: "/home/fixture/.cache", Action: core.ActionDeleteCandidate, Retention: core.RetentionNone},
		{Name: "cautious", Path: "/home/fixture/.cache", Action: core.ActionInvestigate, Retention: core.RetentionNone},
	}

	action := actionFor(t, buildPlan(t, []core.Entry{entryAt("/home/fixture/.cache")}, policy, nil), "/home/fixture/.cache")
	if action.Kind != core.ActionInvestigate {
		t.Fatalf("action = %q, want the safer investigate", action.Kind)
	}
	conflict := false
	for _, rejected := range action.Rejected {
		if rejected.Conflict && rejected.Kind == core.ActionDeleteCandidate {
			conflict = true
			if !strings.Contains(rejected.Reason, "safer") {
				t.Errorf("conflict reason = %q, want it to say why the other rule won", rejected.Reason)
			}
		}
	}
	if !conflict {
		t.Errorf("the losing rule was not reported as a conflict: %+v", action.Rejected)
	}
}

// Risk ordering is what makes "safer" meaningful, so it is asserted
// directly rather than only through its consequences.
func TestSaferAlwaysPicksTheLessDestructiveAction(t *testing.T) {
	order := []core.ActionKind{
		core.ActionKeep, core.ActionInvestigate, core.ActionRelocate,
		core.ActionQuarantine, core.ActionDeleteCandidate,
	}
	for i, safer := range order {
		for _, riskier := range order[i+1:] {
			if got := riskier.Safer(safer); got != safer {
				t.Errorf("%s.Safer(%s) = %s, want %s", riskier, safer, got, safer)
			}
			if got := safer.Safer(riskier); got != safer {
				t.Errorf("%s.Safer(%s) = %s, want %s", safer, riskier, got, safer)
			}
		}
	}
	if core.ActionKind("invented").RiskRank() <= core.ActionDeleteCandidate.RiskRank() {
		t.Error("an unrecognised action must rank as the most dangerous, not the safest")
	}
}

// A refusal from the safety engine outranks every rule.
func TestSafetyRefusalOutranksEveryRule(t *testing.T) {
	policy := fixturePolicy()
	policy.Caches = []config.CacheRule{{
		Name: "aggressive", Path: "/home/fixture/.cache",
		Action: core.ActionDeleteCandidate, Retention: core.RetentionNone,
	}}
	dirty := entryAt("/home/fixture/.cache", withGit(&core.GitState{
		RepoRoot: "/home/fixture/.cache", UpstreamKnown: true, PublicationKnown: true, DirtyFiles: 2,
	}))

	result := buildPlan(t, []core.Entry{dirty}, policy, nil)
	action := actionFor(t, result, "/home/fixture/.cache")
	if action.Kind != core.ActionKeep {
		t.Fatalf("action = %q, want keep: the safety engine refused", action.Kind)
	}
	if action.Retention != core.RetentionNone {
		t.Errorf("retention = %q, want none for a kept path", action.Retention)
	}
	if len(result.Verdicts) != 1 || !result.Verdicts[0].Refused() {
		t.Fatalf("verdicts = %+v, want a refusal", result.Verdicts)
	}
}

// stubAdvisor stands in for the model classifier of a later slice.
type stubAdvisor struct {
	name    string
	answers map[string]core.Recommendation
	seen    []string
	err     error
}

func (s *stubAdvisor) Name() string { return s.name }

func (s *stubAdvisor) Classify(_ context.Context, entries []core.Entry) (map[string]core.Recommendation, error) {
	for _, entry := range entries {
		s.seen = append(s.seen, entry.Path)
	}
	return s.answers, s.err
}

// The advisor sees only what the rules could not decide, and only after
// they have run.
func TestAdvisorRunsAfterRulesAndOnlyOnAmbiguousEntries(t *testing.T) {
	policy := fixturePolicy()
	entries := []core.Entry{
		entryAt("/home/fixture/.cache"),
		entryAt("/home/fixture/mystery"),
		entryAt("/home/fixture/repos/app", withGit(&core.GitState{
			RepoRoot: "/home/fixture/repos/app", UpstreamKnown: true, PublicationKnown: true,
		})),
	}
	advisor := &stubAdvisor{name: "jev", answers: map[string]core.Recommendation{}}

	buildPlan(t, entries, policy, advisor)
	if len(advisor.seen) != 1 || advisor.seen[0] != "/home/fixture/mystery" {
		t.Errorf("advisor saw %v, want only the unclassified entry", advisor.seen)
	}
}

// An advisor may make a decision safer and nothing else.
func TestAdvisorCanOnlyLowerRisk(t *testing.T) {
	policy := fixturePolicy()
	mystery := entryAt("/home/fixture/mystery")

	riskier := &stubAdvisor{name: "jev", answers: map[string]core.Recommendation{
		"/home/fixture/mystery": {
			Action: core.ActionDeleteCandidate, Class: core.ClassCache,
			Retention: core.RetentionNone, Confidence: 1, Origin: core.OriginModel,
			Reasons: []string{"model says disposable"}, DecidedAt: plannedAt,
		},
	}}
	action := actionFor(t, buildPlan(t, []core.Entry{mystery}, policy, riskier), "/home/fixture/mystery")
	if action.Kind != core.ActionInvestigate {
		t.Errorf("action = %q, want the rules' investigate to stand", action.Kind)
	}
	rejected := false
	for _, alternative := range action.Rejected {
		if alternative.Kind == core.ActionDeleteCandidate && strings.Contains(alternative.Rule, "advisor") {
			rejected = true
		}
	}
	if !rejected {
		t.Errorf("the advisor's riskier proposal was not recorded as rejected: %+v", action.Rejected)
	}

	safer := &stubAdvisor{name: "jev", answers: map[string]core.Recommendation{
		"/home/fixture/mystery": {
			Action: core.ActionKeep, Class: core.ClassOperationalTool,
			Confidence: 0.8, Origin: core.OriginModel,
			Reasons: []string{"model recognises operator tooling"}, DecidedAt: plannedAt,
		},
	}}
	action = actionFor(t, buildPlan(t, []core.Entry{mystery}, policy, safer), "/home/fixture/mystery")
	if action.Kind != core.ActionKeep {
		t.Errorf("action = %q, want the advisor's safer keep", action.Kind)
	}
	if !containsString(action.Rules, "advisor:jev") {
		t.Errorf("rules = %v, want the advisor credited", action.Rules)
	}
}

// A relocation could rank safer than a rule's quarantine, but the
// advisor has no destination to supply. It must be rejected before
// becoming an invalid plan action.
func TestAdvisorCannotProposeRelocation(t *testing.T) {
	entry := entryAt("/home/fixture/mystery")
	policy := fixturePolicy()
	policy.Caches = []config.CacheRule{{
		Name: "mystery", Path: entry.Path,
		Action: core.ActionQuarantine, Retention: core.Retention30Days,
	}}
	advisor := &stubAdvisor{name: "other", answers: map[string]core.Recommendation{
		entry.Path: {
			Action: core.ActionRelocate, Class: core.ClassCache,
			Retention: core.RetentionNone, Confidence: 0.9,
			Origin: core.OriginModel, Reasons: []string{"move this"}, DecidedAt: plannedAt,
		},
	}}
	result := buildPlan(t, []core.Entry{entry}, policy, advisor)
	action := actionFor(t, result, entry.Path)
	if action.Kind != core.ActionQuarantine {
		t.Errorf("action = %q, want the rules' quarantine", action.Kind)
	}
	found := false
	for _, rejected := range action.Rejected {
		if rejected.Kind == core.ActionRelocate && rejected.Rule == "advisor:other" {
			found = true
		}
	}
	if !found {
		t.Errorf("unsupported relocation not recorded as rejected: %+v", action.Rejected)
	}
}

// A safer accepted answer carries its own confidence and class through
// both the action and the trace; rules-only ambiguity remains conservative.
func TestAcceptedAdviceClassAndConfidenceAgreeWithTrace(t *testing.T) {
	entry := entryAt("/home/fixture/mystery")
	advisor := &stubAdvisor{name: "jev", answers: map[string]core.Recommendation{
		entry.Path: {
			Action: core.ActionKeep, Class: core.ClassOperationalTool,
			Confidence: 0.95, Origin: core.OriginModel,
			Reasons: []string{"operator tooling"}, DecidedAt: plannedAt,
		},
	}}
	result := buildPlan(t, []core.Entry{entry}, fixturePolicy(), advisor)
	action := actionFor(t, result, entry.Path)
	if action.Kind != core.ActionKeep || action.Confidence != 0.95 || action.Class != core.ClassOperationalTool {
		t.Fatalf("accepted action = %+v", action)
	}
	if len(result.Traces) != 1 || result.Traces[0].Class != action.Class || result.Traces[0].Action != action.Kind {
		t.Errorf("trace = %+v, action = %+v", result.Traces, action)
	}
}

// An advisor can be implemented by something other than Jev. Invalid
// recommendations must never cause the complete rules plan to fail.
func TestMalformedAdvisorConfidenceLeavesRulesPlan(t *testing.T) {
	entry := entryAt("/home/fixture/mystery")
	for _, tc := range []struct {
		name       string
		confidence float64
	}{
		{name: "above one", confidence: 1.5},
		{name: "not a number", confidence: math.NaN()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			advisor := &stubAdvisor{name: "other", answers: map[string]core.Recommendation{
				entry.Path: {
					Action: core.ActionKeep, Class: core.ClassOperationalTool,
					Confidence: tc.confidence, Origin: core.OriginModel,
					Reasons: []string{"unsafe advisor value"}, DecidedAt: plannedAt,
				},
			}}
			result := buildPlan(t, []core.Entry{entry}, fixturePolicy(), advisor)
			action := actionFor(t, result, entry.Path)
			if action.Kind != core.ActionInvestigate || action.Confidence != ambiguousConfidence ||
				containsString(action.Rules, "advisor:other") {
				t.Errorf("malformed advice changed the rules plan: %+v", action)
			}
		})
	}
}

// Invalid retention in an external advisor's otherwise safer answer
// cannot abort plan validation; the rules' action remains reviewable.
func TestMalformedAdvisorRetentionLeavesRulesPlan(t *testing.T) {
	entry := entryAt("/home/fixture/mystery")
	advisor := &stubAdvisor{name: "other", answers: map[string]core.Recommendation{
		entry.Path: {
			Action: core.ActionKeep, Class: core.ClassOperationalTool,
			Retention: core.Retention("bogus"), Confidence: 0.9,
			Origin: core.OriginModel, Reasons: []string{"bad retention"}, DecidedAt: plannedAt,
		},
	}}
	result := buildPlan(t, []core.Entry{entry}, fixturePolicy(), advisor)
	action := actionFor(t, result, entry.Path)
	if action.Kind != core.ActionInvestigate || action.Retention != core.RetentionNone ||
		containsString(action.Rules, "advisor:other") {
		t.Errorf("malformed advice changed the rules plan: %+v", action)
	}
}

// An advisor that agrees with the rules is still credited, so the trace
// says why the entry stayed where it was.
func TestAgreeingAdviceIsCreditedWithoutChangingTheAction(t *testing.T) {
	policy := fixturePolicy()
	unsure := &stubAdvisor{name: "jev", answers: map[string]core.Recommendation{
		"/home/fixture/mystery": {
			Action: core.ActionInvestigate, Class: core.ClassCache,
			Retention: core.RetentionNone, Confidence: 0.4, Origin: core.OriginModel,
			Reasons: []string{"confidence 0.40 is below the 0.70 threshold"}, DecidedAt: plannedAt,
		},
	}}
	action := actionFor(t, buildPlan(t, []core.Entry{entryAt("/home/fixture/mystery")}, policy, unsure), "/home/fixture/mystery")
	if action.Kind != core.ActionInvestigate {
		t.Fatalf("action = %q, want investigate", action.Kind)
	}
	if len(action.Rules) != len(action.Reasons) {
		t.Fatalf("rules %v and reasons %v are not aligned", action.Rules, action.Reasons)
	}
	credited := false
	for i, rule := range action.Rules {
		if rule == "advisor:jev" && strings.Contains(action.Reasons[i], "below the 0.70 threshold") {
			credited = true
		}
	}
	if !credited {
		t.Errorf("rules %v / reasons %v do not credit the advisor with its reason", action.Rules, action.Reasons)
	}
	if action.Class != core.ClassCache {
		t.Errorf("class = %q, want the advisor's label on an unchanged action", action.Class)
	}
	if len(action.Rejected) != 0 {
		t.Errorf("an agreeing advisor was recorded as rejected: %+v", action.Rejected)
	}
}

// A failing advisor must not change what the rules decided.
func TestAdvisorFailureLeavesTheRulesDecision(t *testing.T) {
	policy := fixturePolicy()
	advisor := &stubAdvisor{name: "jev", err: errors.New("no credentials")}
	action := actionFor(t, buildPlan(t, []core.Entry{entryAt("/home/fixture/mystery")}, policy, advisor), "/home/fixture/mystery")
	if action.Kind != core.ActionInvestigate {
		t.Errorf("action = %q, want the rules' decision to stand", action.Kind)
	}
}

// A plan is bound to its scan, its evidence, and its policy.
func TestPlanBindingRejectsChangedInputs(t *testing.T) {
	policy := fixturePolicy()
	entries := []core.Entry{entryAt("/home/fixture/.cache"), entryAt("/home/fixture/mystery")}
	result := buildPlan(t, entries, policy, nil)

	if err := VerifyBinding(result.Plan, "scan-1", entries, policy); err != nil {
		t.Fatalf("an unchanged binding must verify: %v", err)
	}
	if err := VerifyBinding(result.Plan, "scan-2", entries, policy); !errors.Is(err, ErrBindingMismatch) {
		t.Errorf("error = %v, want a mismatch for a different scan", err)
	}

	changed := append([]core.Entry(nil), entries...)
	changed[0].Fingerprint = "fingerprint-changed"
	if err := VerifyBinding(result.Plan, "scan-1", changed, policy); !errors.Is(err, ErrBindingMismatch) {
		t.Errorf("error = %v, want a mismatch for changed evidence", err)
	}

	fewer := entries[:1]
	if err := VerifyBinding(result.Plan, "scan-1", fewer, policy); !errors.Is(err, ErrBindingMismatch) {
		t.Errorf("error = %v, want a mismatch when an entry disappeared", err)
	}

	otherPolicy := fixturePolicy()
	otherPolicy.Retention.Default = core.Retention7Days
	if err := VerifyBinding(result.Plan, "scan-1", entries, otherPolicy); !errors.Is(err, ErrBindingMismatch) {
		t.Errorf("error = %v, want a mismatch for a changed policy", err)
	}
}

// The same inputs must always produce the same plan id and the same
// document, which is what makes a plan reproducible and reusable.
func TestPlanIsDeterministic(t *testing.T) {
	policy := fixturePolicy()
	entries := []core.Entry{entryAt("/home/fixture/.cache"), entryAt("/home/fixture/mystery")}

	first := buildPlan(t, entries, policy, nil)
	for i := 0; i < 5; i++ {
		again := buildPlan(t, entries, policy, nil)
		if again.Plan.ID != first.Plan.ID {
			t.Fatalf("plan id changed between runs: %s and %s", first.Plan.ID, again.Plan.ID)
		}
		a, _ := core.MarshalJSON(first.Plan)
		b, _ := core.MarshalJSON(again.Plan)
		if string(a) != string(b) {
			t.Fatalf("plan document changed between runs:\n%s\n---\n%s", a, b)
		}
	}
}

func TestBuildRequiresAScan(t *testing.T) {
	if _, err := Build(context.Background(), Input{Entries: []core.Entry{entryAt("/home/fixture/mystery")}}); err == nil {
		t.Fatal("expected a plan with no scan to be rejected")
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// A directory with a project marker but no Git metadata is still a
// primary project. The marker list is configuration, so it has to be
// backed by evidence a collector actually produces.
func TestProjectMarkerEvidenceClassifiesAPrimaryProject(t *testing.T) {
	policy := fixturePolicy()
	entry := entryAt("/home/fixture/repos/module")
	entry.Evidence = append(entry.Evidence, core.Evidence{
		Source: core.SourceFilesystem, Signal: "project_marker",
		Detail: "go.mod", ObservedAt: plannedAt,
	})

	action := actionFor(t, buildPlan(t, []core.Entry{entry}, policy, nil), "/home/fixture/repos/module")
	if action.Class != core.ClassPrimaryProject {
		t.Errorf("class = %q, want primary_project from the marker evidence (rules %v)", action.Class, action.Rules)
	}
	if action.Kind != core.ActionKeep {
		t.Errorf("action = %q, want keep", action.Kind)
	}
}

// A canonical root inside the entry would make relocation a move into
// itself, which cannot succeed and would be destructive to attempt.
func TestRelocateIsRefusedWhenTheDestinationIsInsideTheEntry(t *testing.T) {
	policy := fixturePolicy()
	policy.CanonicalRoots = []config.CanonicalRoot{
		{Class: core.ClassPrimaryProject, Path: "/home/fixture/project/repos"},
	}
	entry := entryAt("/home/fixture/project", withGit(&core.GitState{
		RepoRoot: "/home/fixture/project", UpstreamKnown: true, PublicationKnown: true,
	}))

	action := actionFor(t, buildPlan(t, []core.Entry{entry}, policy, nil), "/home/fixture/project")
	if action.Kind == core.ActionRelocate {
		t.Fatalf("a self-relocation was proposed: %s -> %s", action.Path, action.Destination)
	}
	if action.Kind != core.ActionInvestigate {
		t.Errorf("action = %q, want investigate", action.Kind)
	}
	if action.Destination != "" {
		t.Errorf("destination = %q, want none", action.Destination)
	}
}

// Two projects that would relocate onto the same destination collide, so
// neither is proposed and the collision is reported.
func TestCollidingRelocationsAreDowngradedAndReported(t *testing.T) {
	policy := fixturePolicy()
	first := entryAt("/home/fixture/a/dup", withGit(&core.GitState{
		RepoRoot: "/home/fixture/a/dup", UpstreamKnown: true, PublicationKnown: true,
	}))
	second := entryAt("/home/fixture/b/dup", withGit(&core.GitState{
		RepoRoot: "/home/fixture/b/dup", UpstreamKnown: true, PublicationKnown: true,
	}))
	unique := entryAt("/home/fixture/c/solo", withGit(&core.GitState{
		RepoRoot: "/home/fixture/c/solo", UpstreamKnown: true, PublicationKnown: true,
	}))

	result := buildPlan(t, []core.Entry{first, second, unique}, policy, nil)
	for _, path := range []string{"/home/fixture/a/dup", "/home/fixture/b/dup"} {
		action := actionFor(t, result, path)
		if action.Kind != core.ActionInvestigate {
			t.Errorf("%s: action = %q, want investigate after a destination collision", path, action.Kind)
		}
		if action.Destination != "" {
			t.Errorf("%s: destination = %q, want it cleared", path, action.Destination)
		}
		reported := false
		for _, rejected := range action.Rejected {
			if rejected.Conflict && strings.Contains(rejected.Reason, "collide") {
				reported = true
			}
		}
		if !reported {
			t.Errorf("%s: the collision was not reported: %+v", path, action.Rejected)
		}
	}

	solo := actionFor(t, result, "/home/fixture/c/solo")
	if solo.Kind != core.ActionRelocate || solo.Destination != "/home/fixture/repos/solo" {
		t.Errorf("an uncontested relocation was disturbed: %+v", solo)
	}
}

// Rules and reasons are paired by index in every explanation, so they must
// stay the same length however a decision was reached.
func TestRulesAndReasonsStayAligned(t *testing.T) {
	policy := fixturePolicy()
	policy.Caches = []config.CacheRule{
		{Name: "aaa-first", Path: "/home/fixture/.cache", Action: core.ActionQuarantine, Retention: core.Retention30Days},
		{Name: "zzz-second", Path: "/home/fixture/.cache", Action: core.ActionQuarantine, Retention: core.Retention30Days},
	}
	advisor := &stubAdvisor{name: "jev", answers: map[string]core.Recommendation{
		"/home/fixture/mystery": {
			Action: core.ActionKeep, Class: core.ClassOperationalTool, Confidence: 0.8,
			Origin: core.OriginModel, DecidedAt: plannedAt,
			Reasons: []string{"first reason", "second reason"},
		},
	}}

	entries := []core.Entry{
		entryAt("/home/fixture/.cache"),
		entryAt("/home/fixture/mystery"),
		entryAt("/home/fixture/repos/app", withGit(&core.GitState{
			RepoRoot: "/home/fixture/repos/app", UpstreamKnown: true, PublicationKnown: true,
		})),
	}
	for _, action := range buildPlan(t, entries, policy, advisor).Plan.Actions {
		if len(action.Rules) != len(action.Reasons) {
			t.Errorf("%s: %d rules but %d reasons, so an explanation would misattribute them:\n rules: %v\n reasons: %v",
				action.Path, len(action.Rules), len(action.Reasons), action.Rules, action.Reasons)
		}
	}
}

// A destination that already exists cannot be relocated onto, even when no
// other action wants it.
func TestRelocationOntoAnExistingPathIsReported(t *testing.T) {
	policy := fixturePolicy()
	existing := entryAt("/home/fixture/repos/dup")
	candidate := entryAt("/home/fixture/a/dup", withGit(&core.GitState{
		RepoRoot: "/home/fixture/a/dup", UpstreamKnown: true, PublicationKnown: true,
	}))

	result := buildPlan(t, []core.Entry{existing, candidate}, policy, nil)
	action := actionFor(t, result, "/home/fixture/a/dup")
	if action.Kind != core.ActionInvestigate {
		t.Fatalf("action = %q, want investigate: the destination is occupied", action.Kind)
	}
	if action.Destination != "" {
		t.Errorf("destination = %q, want it cleared", action.Destination)
	}
	reported := false
	for _, rejected := range action.Rejected {
		if rejected.Conflict && strings.Contains(rejected.Reason, "already exists") {
			reported = true
		}
	}
	if !reported {
		t.Errorf("the occupied destination was not reported: %+v", action.Rejected)
	}

	// A free destination still relocates, or the guard would block
	// everything and teach operators to ignore it.
	free := entryAt("/home/fixture/b/solo", withGit(&core.GitState{
		RepoRoot: "/home/fixture/b/solo", UpstreamKnown: true, PublicationKnown: true,
	}))
	solo := actionFor(t, buildPlan(t, []core.Entry{free}, policy, nil), "/home/fixture/b/solo")
	if solo.Kind != core.ActionRelocate || solo.Destination != "/home/fixture/repos/solo" {
		t.Errorf("an uncontested relocation was blocked: %+v", solo)
	}
}

// A downgraded relocation is a conflict resolution, not an unopposed rule,
// so its confidence must say so.
func TestCollisionDowngradeLowersConfidence(t *testing.T) {
	policy := fixturePolicy()
	occupied := entryAt("/home/fixture/repos/dup")
	candidate := entryAt("/home/fixture/a/dup", withGit(&core.GitState{
		RepoRoot: "/home/fixture/a/dup", UpstreamKnown: true, PublicationKnown: true,
	}))
	free := entryAt("/home/fixture/b/solo", withGit(&core.GitState{
		RepoRoot: "/home/fixture/b/solo", UpstreamKnown: true, PublicationKnown: true,
	}))

	result := buildPlan(t, []core.Entry{occupied, candidate, free}, policy, nil)
	downgraded := actionFor(t, result, "/home/fixture/a/dup")
	if downgraded.Confidence != conflictConfidence {
		t.Errorf("confidence = %v, want %v for a collision-downgraded action",
			downgraded.Confidence, conflictConfidence)
	}
	if uncontested := actionFor(t, result, "/home/fixture/b/solo"); uncontested.Confidence != settledConfidence {
		t.Errorf("confidence = %v, want %v for an unopposed relocation",
			uncontested.Confidence, settledConfidence)
	}
}
