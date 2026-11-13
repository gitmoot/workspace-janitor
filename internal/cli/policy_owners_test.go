package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/plan"
)

// The inventory owner keeps its exact-rule precedence: a cache rule's
// recovery.owner, then an evidence export's owner, then the longest policy
// owners entry, then unassigned.
func TestDecisionOwnerOrder(t *testing.T) {
	policy := config.Policy{
		Caches:          []config.CacheRule{{Name: "build", Path: "/srv/work/app/cache", Recovery: config.CacheRecovery{Owner: "cache-owner"}}},
		EvidenceExports: []config.EvidenceExportRule{{Name: "sessions", Path: "/srv/work/app/export.jsonl", Owner: "export-owner"}},
		Owners: []config.OwnerRule{
			{Path: "/srv/work", Owner: "platform"},
			{Path: "/srv/work/app", Owner: "app-team"},
			{Path: "/srv/work/app/cache", Owner: "policy-cache-owner"},
		},
	}
	for _, tc := range []struct{ path, owner, source string }{
		{"/srv/work/app/cache", "cache-owner", "caches[0].recovery.owner"},
		{"/srv/work/app/export.jsonl", "export-owner", "evidence_exports[0].owner"},
		{"/srv/work/app/cache/sub", "policy-cache-owner", "owners[2] /srv/work/app/cache"},
		{"/srv/work/app/src", "app-team", "owners[1] /srv/work/app"},
		{"/srv/work/application", "platform", "owners[0] /srv/work"},
		{"/srv/elsewhere", unassignedOwner, "no cache recovery.owner"},
	} {
		got := resolveDecisionOwner(tc.path, policy)
		if got.Owner != tc.owner || !strings.HasPrefix(got.Source, tc.source) {
			t.Errorf("resolveDecisionOwner(%s) = %+v, want %s from %s", tc.path, got, tc.owner, tc.source)
		}
		if inventoryOwner(tc.path, policy) != tc.owner {
			t.Errorf("inventoryOwner(%s) = %s, want %s", tc.path, inventoryOwner(tc.path, policy), tc.owner)
		}
	}
	// A cache rule without recovery.owner does not hide a policy owner.
	policy.Caches[0].Recovery.Owner = ""
	if got := inventoryOwner("/srv/work/app/cache", policy); got != "policy-cache-owner" {
		t.Errorf("cache rule without recovery.owner: owner = %s, want the policy owner", got)
	}
}

// ownersPolicy is the plan fixture's policy with an owners section that
// covers every planned path, nested.
func ownersPolicy(t *testing.T, f *planFixture) (without, with string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.home, ".config", config.AppName, "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	without = string(data)
	with = without + "owners:\n" +
		"  - path: " + f.root + "\n    owner: platform\n" +
		"  - path: " + f.repos + "\n    owner: app-team\n    note: canonical projects\n" +
		"  - path: " + filepath.Join(f.root, "node_modules") + "\n    owner: frontend\n" +
		"  - path: " + filepath.Join(f.root, "mystery") + "\n    owner: research\n"
	return without, with
}

// explain states the decision owner and where it came from.
func TestExplainShowsPolicyOwnerAndSource(t *testing.T) {
	f := newPlanFixture(t)
	_, with := ownersPolicy(t, f)
	f.writePolicy(t, with)
	f.scan(t)
	f.planJSON(t)
	target := filepath.Join(f.root, "mystery")

	stdout, stderr, code := f.run(t, "explain", target)
	if code != ExitOK {
		t.Fatalf("explain exit = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "owner:") || !strings.Contains(stdout, "research (source: owners[3] "+target) {
		t.Errorf("explain does not show the policy owner and its source:\n%s", stdout)
	}
	jsonOut, _, code := f.run(t, "--format", "json", "explain", filepath.Join(f.root, "backups"))
	if code != ExitOK {
		t.Fatalf("explain json exit = %d", code)
	}
	var doc struct {
		Data struct {
			Owner decisionOwner `json:"owner"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Data.Owner.Owner != "platform" || doc.Data.Owner.Source != "owners[0] "+f.root {
		t.Errorf("explain JSON owner = %+v, want platform from owners[0]", doc.Data.Owner)
	}
}

// An owner is information, never authority: the same scan planned with and
// without an owners section yields the same plan, actions, traces, safety
// verdicts and approvals, and an approval made before the section was added
// stays bound to the plan.
func TestPolicyOwnersAreInert(t *testing.T) {
	f := newPlanFixture(t)
	without, with := ownersPolicy(t, f)
	f.scan(t)

	type observation struct {
		plan      core.Plan
		traces    []plan.Trace
		approvals []core.Approval
		verdicts  map[string]string
	}
	observe := func(args ...string) observation {
		t.Helper()
		stdout, stderr, code := f.run(t, append([]string{"--format", "json", "plan"}, args...)...)
		if code != ExitOK {
			t.Fatalf("plan %v: exit = %d, stderr = %s", args, code, stderr)
		}
		var doc struct {
			Data struct {
				Plan      core.Plan       `json:"plan"`
				Traces    []plan.Trace    `json:"traces"`
				Approvals []core.Approval `json:"approvals"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
			t.Fatal(err)
		}
		obs := observation{plan: doc.Data.Plan, traces: doc.Data.Traces, approvals: doc.Data.Approvals, verdicts: map[string]string{}}
		for _, action := range doc.Data.Plan.Actions {
			out, stderr, code := f.run(t, "--format", "json", "explain", action.Path)
			if code != ExitOK {
				t.Fatalf("explain %s: exit = %d, stderr = %s", action.Path, code, stderr)
			}
			var explained struct {
				Data struct {
					Verdict  *core.Verdict   `json:"safety_verdict"`
					Approval json.RawMessage `json:"approval"`
				} `json:"data"`
			}
			if err := json.Unmarshal([]byte(out), &explained); err != nil {
				t.Fatal(err)
			}
			if explained.Data.Verdict == nil {
				t.Fatalf("explain %s has no safety verdict", action.Path)
			}
			// Each evaluation stamps its own time; the verdict must match.
			explained.Data.Verdict.EvaluatedAt = time.Time{}
			verdict, err := json.Marshal(explained.Data.Verdict)
			if err != nil {
				t.Fatal(err)
			}
			obs.verdicts[action.Path] = string(verdict) + "|" + string(explained.Data.Approval)
		}
		return obs
	}
	same := func(label string, a, b observation) {
		t.Helper()
		if a.plan.ID != b.plan.ID || a.plan.PolicyDigest != b.plan.PolicyDigest {
			t.Errorf("%s: plan identity changed: %s/%s vs %s/%s", label, a.plan.ID, a.plan.PolicyDigest, b.plan.ID, b.plan.PolicyDigest)
		}
		// A fresh build stamps the time it ran; everything else must match.
		untimed := func(actions []core.Action) []core.Action {
			out := append([]core.Action(nil), actions...)
			for i := range out {
				out[i].CreatedAt = time.Time{}
			}
			return out
		}
		if len(a.plan.Actions) == 0 || !reflect.DeepEqual(untimed(a.plan.Actions), untimed(b.plan.Actions)) {
			t.Errorf("%s: actions changed:\n%+v\n%+v", label, a.plan.Actions, b.plan.Actions)
		}
		if !reflect.DeepEqual(a.traces, b.traces) {
			t.Errorf("%s: traces changed:\n%+v\n%+v", label, a.traces, b.traces)
		}
		if !reflect.DeepEqual(a.verdicts, b.verdicts) {
			t.Errorf("%s: safety verdicts or approvals changed:\n%v\n%v", label, a.verdicts, b.verdicts)
		}
		if len(a.approvals) != len(b.approvals) {
			t.Errorf("%s: approvals changed: %+v vs %+v", label, a.approvals, b.approvals)
		}
	}

	// explain reads the stored plan but evaluates safety against the policy
	// in force, so store the plan once and then compare fresh builds.
	f.planJSON(t)
	baseline := observe("--no-store")
	f.writePolicy(t, with)
	owned := observe("--no-store")
	same("fresh plan", baseline, owned)
	stored := observe()
	if len(stored.approvals) != 0 || len(owned.approvals) != 0 {
		t.Fatalf("an owner approved something: %+v %+v", stored.approvals, owned.approvals)
	}
	target := filepath.Join(f.root, "node_modules")
	mutating := false
	for _, action := range owned.plan.Actions {
		mutating = mutating || action.Path == target && action.Kind.Mutating()
	}
	if !mutating {
		t.Fatalf("fixture plan does not mutate %s, so inertness proves nothing: %+v", target, owned.plan.Actions)
	}

	// An approval recorded without owners stays bound once owners exist.
	f.writePolicy(t, without)
	approved := observe("--approve", target)
	if len(approved.approvals) != 1 {
		t.Fatalf("approvals = %+v, want one for %s", approved.approvals, target)
	}
	f.writePolicy(t, with)
	same("stored plan", approved, observe())
	if _, stderr, code := f.run(t, "apply", "--quarantine"); code != ExitOK {
		t.Fatalf("dry-run apply of the approved plan failed once owners were added: exit = %d, stderr = %s", code, stderr)
	}
}
