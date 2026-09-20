package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// planFixture is a fixture home with a workspace that exercises the
// documented classes: a canonical project, a clone outside it, a generated
// artifact, a cache, a backup, and something unclassifiable.
type planFixture struct {
	*fixture
	root  string
	repos string
}

func newPlanFixture(t *testing.T) *planFixture {
	t.Helper()
	f := newFixture(t)
	root := filepath.Join(f.home, "workspace")
	repos := filepath.Join(root, "repos")
	for _, dir := range []string{
		filepath.Join(repos, "app"),
		filepath.Join(root, "scratch-clone"),
		filepath.Join(root, "node_modules"),
		filepath.Join(root, ".cache"),
		filepath.Join(root, "backups"),
		filepath.Join(root, "mystery"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	f.writePolicy(t, strings.Join([]string{
		"roots:",
		"  - path: " + root,
		"    max_depth: 1",
		"collectors:",
		"  git: false",
		"  processes: false",
		"  services: false",
		"canonical_roots:",
		"  - class: primary_project",
		"    path: " + repos,
		"",
	}, "\n"))
	return &planFixture{fixture: f, root: root, repos: repos}
}

// planDocument mirrors the published plan envelope.
type planDocument struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	Data          struct {
		Plan      core.Plan        `json:"plan"`
		Summary   core.PlanSummary `json:"summary"`
		Persisted bool             `json:"persisted"`
		Reused    bool             `json:"reused"`
		Approvals []core.Approval  `json:"approvals"`
		Conflicts []struct {
			Path     string                `json:"path"`
			Chosen   core.ActionKind       `json:"chosen"`
			Rejected []core.RejectedAction `json:"rejected"`
		} `json:"conflicts"`
	} `json:"data"`
}

func (f *planFixture) scan(t *testing.T) {
	t.Helper()
	if _, stderr, code := f.run(t, "scan"); code != ExitOK {
		t.Fatalf("scan exit = %d, stderr = %s", code, stderr)
	}
}

func (f *planFixture) planJSON(t *testing.T, args ...string) planDocument {
	t.Helper()
	stdout, stderr, code := f.run(t, append([]string{"--format", "json", "plan"}, args...)...)
	if code != ExitOK {
		t.Fatalf("plan exit = %d, stderr = %s", code, stderr)
	}
	var doc planDocument
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("plan JSON is not valid: %v\n%s", err, stdout)
	}
	return doc
}

func (f *planFixture) action(t *testing.T, doc planDocument, path string) core.Action {
	t.Helper()
	for _, action := range doc.Data.Plan.Actions {
		if action.Path == path {
			return action
		}
	}
	t.Fatalf("plan has no action for %s", path)
	return core.Action{}
}

func TestPlanProducesTypedActionsBoundToTheScan(t *testing.T) {
	f := newPlanFixture(t)
	f.scan(t)
	doc := f.planJSON(t)

	if doc.SchemaVersion != core.ContractVersion || doc.Kind != "plan" {
		t.Errorf("envelope = %+v", doc)
	}
	if doc.Data.Plan.ScanID == "" || doc.Data.Plan.EvidenceDigest == "" || doc.Data.Plan.PolicyDigest == "" {
		t.Errorf("plan is not bound to its inputs: %+v", doc.Data.Plan)
	}
	if !strings.Contains(doc.Data.Plan.ID, doc.Data.Plan.ScanID) {
		t.Errorf("plan id %q does not name its scan %q", doc.Data.Plan.ID, doc.Data.Plan.ScanID)
	}
	if !doc.Data.Persisted {
		t.Error("the plan was not stored")
	}

	for path, want := range map[string]core.ActionKind{
		filepath.Join(f.root, "node_modules"): core.ActionQuarantine,
		filepath.Join(f.root, ".cache"):       core.ActionQuarantine,
		filepath.Join(f.root, "backups"):      core.ActionKeep,
		filepath.Join(f.root, "mystery"):      core.ActionInvestigate,
	} {
		action := f.action(t, doc, path)
		if action.Kind != want {
			t.Errorf("%s: action = %q, want %q (reasons %v)", path, action.Kind, want, action.Reasons)
		}
		if len(action.Rules) == 0 {
			t.Errorf("%s: no contributing rules recorded", path)
		}
		if action.Fingerprint == "" {
			t.Errorf("%s: action is not bound to an evidence fingerprint", path)
		}
	}

	// Nothing in the default policy may propose a direct deletion.
	for _, action := range doc.Data.Plan.Actions {
		if action.Kind == core.ActionDeleteCandidate {
			t.Errorf("%s was proposed for direct deletion: %+v", action.Path, action)
		}
	}
}

// Approving selects actions without touching the plan, and the plan itself
// is immutable across a restart.
func TestPlanApprovalSelectsWithoutEditingThePlan(t *testing.T) {
	f := newPlanFixture(t)
	f.scan(t)
	first := f.planJSON(t)
	target := filepath.Join(f.root, ".cache")
	action := f.action(t, first, target)

	approved := f.planJSON(t, "--approve", action.ID, "--approver", "reviewer", "--note", "checked")
	if len(approved.Data.Approvals) != 1 {
		t.Fatalf("approvals = %+v, want one", approved.Data.Approvals)
	}
	if approved.Data.Approvals[0].ActionID != action.ID || approved.Data.Approvals[0].Approver != "reviewer" {
		t.Errorf("approval = %+v", approved.Data.Approvals[0])
	}
	if !approved.Data.Reused {
		t.Error("re-planning identical inputs must reuse the stored plan, not rewrite it")
	}

	// The plan document itself is unchanged by approving.
	before, err := core.MarshalJSON(first.Data.Plan)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	after, err := core.MarshalJSON(approved.Data.Plan)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("approving changed the plan:\n%s\n---\n%s", before, after)
	}

	// Approving by path is equivalent, and approving twice is idempotent.
	again := f.planJSON(t, "--approve", target)
	if len(again.Data.Approvals) != 1 {
		t.Errorf("approvals = %+v, want the first approval kept", again.Data.Approvals)
	}

	// A non-mutating action needs no approval and saying so is a usage
	// error, not a silent no-op.
	_, stderr, code := f.run(t, "plan", "--approve", filepath.Join(f.root, "backups"))
	if code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "needs no approval") {
		t.Errorf("stderr = %q", stderr)
	}
}

// A plan must survive a restart unchanged, including its approvals.
func TestPlanSurvivesRestartAndStaysImmutable(t *testing.T) {
	f := newPlanFixture(t)
	f.scan(t)
	created := f.planJSON(t)
	action := f.action(t, created, filepath.Join(f.root, ".cache"))
	f.planJSON(t, "--approve", action.ID)

	// A new process, reading only what is on disk.
	reloaded := f.planJSON(t, "--plan", created.Data.Plan.ID)
	before, _ := core.MarshalJSON(created.Data.Plan)
	after, _ := core.MarshalJSON(reloaded.Data.Plan)
	if string(before) != string(after) {
		t.Errorf("the stored plan changed:\n%s\n---\n%s", before, after)
	}
	if len(reloaded.Data.Approvals) != 1 {
		t.Errorf("approvals = %+v, want the approval to survive", reloaded.Data.Approvals)
	}
}

// A stored plan may not be used once the evidence it was built from has
// changed.
func TestStoredPlanRefusesChangedEvidence(t *testing.T) {
	f := newPlanFixture(t)
	f.scan(t)
	created := f.planJSON(t)

	// Change the workspace, then re-scan so the stored inventory differs
	// from what the plan was built against.
	if err := os.MkdirAll(filepath.Join(f.root, "new-thing"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f.scan(t)

	_, stderr, code := f.run(t, "plan", "--plan", created.Data.Plan.ID)
	if code != ExitError {
		t.Fatalf("exit = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr, "binding mismatch") {
		t.Errorf("stderr = %q, want a binding mismatch", stderr)
	}
}

// Rule conflicts are reported, and resolved toward caution.
func TestPlanReportsRuleConflictsResolvedToTheSaferAction(t *testing.T) {
	f := newPlanFixture(t)
	f.writePolicy(t, strings.Join([]string{
		"roots:",
		"  - path: " + f.root,
		"    max_depth: 1",
		"collectors:",
		"  git: false",
		"  processes: false",
		"  services: false",
		"caches:",
		"  - name: aggressive",
		"    path: " + filepath.Join(f.root, ".cache"),
		"    action: delete_candidate",
		"    retention: none",
		"  - name: cautious",
		"    path: " + filepath.Join(f.root, ".cache"),
		"    action: investigate",
		"    retention: none",
		"",
	}, "\n"))
	f.scan(t)
	doc := f.planJSON(t)

	action := f.action(t, doc, filepath.Join(f.root, ".cache"))
	if action.Kind != core.ActionInvestigate {
		t.Fatalf("action = %q, want the safer investigate", action.Kind)
	}
	if len(doc.Data.Conflicts) == 0 {
		t.Fatal("the conflict was not reported")
	}
	found := false
	for _, conflict := range doc.Data.Conflicts {
		if conflict.Path != action.Path {
			continue
		}
		for _, rejected := range conflict.Rejected {
			if rejected.Kind == core.ActionDeleteCandidate {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("conflicts = %+v, want the rejected delete recorded", doc.Data.Conflicts)
	}
}

func TestPlanTextOutputListsActionsAndConflicts(t *testing.T) {
	f := newPlanFixture(t)
	f.scan(t)
	stdout, stderr, code := f.run(t, "plan")
	if code != ExitOK {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{"plan:", "scan:", "evidence:", "ACTION", "CLASS", "APPROVAL", "janitor explain"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("plan output does not contain %q:\n%s", want, stdout)
		}
	}
}

func TestPlanWithoutAScanFailsClearly(t *testing.T) {
	f := newPlanFixture(t)
	_, stderr, code := f.run(t, "plan")
	if code != ExitError {
		t.Fatalf("exit = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr, "janitor scan") {
		t.Errorf("stderr = %q, want it to say what to run first", stderr)
	}
}

// explain must trace the winning action and the alternatives rejected.
func TestExplainTracesTheDecision(t *testing.T) {
	f := newPlanFixture(t)
	f.scan(t)
	doc := f.planJSON(t)
	target := filepath.Join(f.root, ".cache")
	action := f.action(t, doc, target)

	stdout, stderr, code := f.run(t, "explain", target)
	if code != ExitOK {
		t.Fatalf("explain exit = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{
		"action:", string(action.Kind), "class:", "Winning rules", "Rejected alternatives", "Evidence", "Safety:",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("explain output does not contain %q:\n%s", want, stdout)
		}
	}
	if !strings.Contains(stdout, "janitor plan --approve") {
		t.Errorf("explain must say how to approve a mutating action:\n%s", stdout)
	}

	jsonOut, _, code := f.run(t, "--format", "json", "explain", target)
	if code != ExitOK {
		t.Fatalf("explain json exit = %d", code)
	}
	var explained struct {
		Kind string `json:"kind"`
		Data struct {
			Path    string        `json:"path"`
			PlanID  string        `json:"plan_id"`
			Action  core.Action   `json:"action"`
			Entry   *core.Entry   `json:"entry"`
			Verdict *core.Verdict `json:"safety_verdict"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &explained); err != nil {
		t.Fatalf("explain JSON is not valid: %v\n%s", err, jsonOut)
	}
	if explained.Kind != "explain" || explained.Data.Path != target {
		t.Errorf("explain document = %+v", explained.Data)
	}
	if explained.Data.PlanID != doc.Data.Plan.ID {
		t.Errorf("plan id = %q, want %q", explained.Data.PlanID, doc.Data.Plan.ID)
	}
	if explained.Data.Entry == nil || explained.Data.Verdict == nil {
		t.Error("explain must carry the evidence and the safety verdict")
	}
	if len(explained.Data.Action.Rules) == 0 {
		t.Error("explain must name the contributing rules")
	}
}

// An explanation for a conflicted decision must name what lost.
func TestExplainShowsRejectedAlternatives(t *testing.T) {
	f := newPlanFixture(t)
	f.writePolicy(t, strings.Join([]string{
		"roots:",
		"  - path: " + f.root,
		"    max_depth: 1",
		"collectors:",
		"  git: false",
		"  processes: false",
		"  services: false",
		"caches:",
		"  - name: aggressive",
		"    path: " + filepath.Join(f.root, ".cache"),
		"    action: quarantine",
		"    retention: 30d",
		"  - name: cautious",
		"    path: " + filepath.Join(f.root, ".cache"),
		"    action: keep",
		"    retention: none",
		"",
	}, "\n"))
	f.scan(t)
	f.planJSON(t)

	stdout, _, code := f.run(t, "explain", filepath.Join(f.root, ".cache"))
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stdout, "quarantine") || !strings.Contains(stdout, "cautious") {
		t.Errorf("explain does not trace the rejected alternative:\n%s", stdout)
	}
}

func TestExplainUsageErrors(t *testing.T) {
	f := newPlanFixture(t)
	f.scan(t)
	f.planJSON(t)

	for _, args := range [][]string{
		{"explain"},
		{"explain", "relative/path"},
		{"explain", "/a", "/b"},
	} {
		stdout, stderr, code := f.run(t, args...)
		if code != ExitUsage {
			t.Errorf("%v exit = %d, want %d", args, code, ExitUsage)
		}
		if stdout != "" {
			t.Errorf("%v wrote to stdout: %q", args, stdout)
		}
		if stderr == "" {
			t.Errorf("%v produced no diagnostic", args)
		}
	}

	_, stderr, code := f.run(t, "explain", filepath.Join(f.root, "not-in-the-plan"))
	if code != ExitError {
		t.Errorf("exit = %d, want %d", code, ExitError)
	}
	if !strings.Contains(stderr, "no action for") {
		t.Errorf("stderr = %q", stderr)
	}
}

// Planning against a scan that does not exist must fail clearly rather
// than produce an empty plan bound to nothing.
func TestPlanWithUnknownScanFailsClearly(t *testing.T) {
	f := newPlanFixture(t)
	f.scan(t)

	stdout, stderr, code := f.run(t, "plan", "--scan", "scan-does-not-exist")
	if code != ExitError {
		t.Fatalf("exit = %d, want %d", code, ExitError)
	}
	if stdout != "" {
		t.Errorf("wrote a plan for an unknown scan: %q", stdout)
	}
	if !strings.Contains(stderr, "scan-does-not-exist") {
		t.Errorf("stderr = %q, want it to name the missing scan", stderr)
	}
}

// explain pairs each rule with its own reason.
func TestExplainPairsRulesWithTheirOwnReasons(t *testing.T) {
	f := newPlanFixture(t)
	target := filepath.Join(f.root, ".cache")
	f.writePolicy(t, strings.Join([]string{
		"roots:",
		"  - path: " + f.root,
		"    max_depth: 1",
		"collectors:",
		"  git: false",
		"  processes: false",
		"  services: false",
		"caches:",
		"  - name: aaa-first",
		"    path: " + target,
		"    action: quarantine",
		"    retention: 30d",
		"  - name: zzz-second",
		"    path: " + target,
		"    action: quarantine",
		"    retention: 30d",
		"",
	}, "\n"))
	f.scan(t)
	doc := f.planJSON(t)
	action := f.action(t, doc, target)

	if len(action.Rules) != len(action.Reasons) {
		t.Fatalf("%d rules but %d reasons: an explanation would misattribute them\n rules: %v\n reasons: %v",
			len(action.Rules), len(action.Reasons), action.Rules, action.Reasons)
	}
	for i, rule := range action.Rules {
		if strings.HasPrefix(rule, "policy.cache:") {
			name := strings.TrimPrefix(rule, "policy.cache:")
			if !strings.Contains(action.Reasons[i], name) {
				t.Errorf("rule %q is paired with %q, which describes a different rule", rule, action.Reasons[i])
			}
		}
	}
}
