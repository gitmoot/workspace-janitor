package plan

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/safety"
)

func TestProviderRootsAndAdjacentLookalikes(t *testing.T) {
	policy := fixturePolicy()
	for _, tc := range []struct {
		path, provider string
		class          core.ArtifactClass
	}{
		{"/home/fixture/.cache/uv", "uv", core.ClassCache},
		{"/home/fixture/.npm", "npm", core.ClassCache},
		{"/home/fixture/.local/share/pnpm/store", "pnpm", core.ClassCache},
		{"/home/fixture/.bun/install/cache", "bun", core.ClassCache},
		{"/home/fixture/.gradle/caches", "gradle", core.ClassCache},
		{"/home/fixture/.cache/go-build", "go-build", core.ClassCache},
		{"/home/fixture/go/pkg/mod", "go-module", core.ClassCache},
		{"/home/fixture/.cache/ms-playwright", "playwright", core.ClassCache},
		{"/home/fixture/.cache/puppeteer", "puppeteer", core.ClassCache},
		{"/home/fixture/repos/app/.uv-cache", "uv", core.ClassCache},
		{"/home/fixture/repos/app/.gradle/caches", "gradle", core.ClassCache},
		{"/home/fixture/repos/app/.pnpm-store", "pnpm", core.ClassCache},
		{"/home/fixture/repos/app/.venv", "python-venv", core.ClassGeneratedArtifact},
		{"/home/fixture/repos/app/node_modules", "node-modules", core.ClassGeneratedArtifact},
		{"/home/fixture/repos/app/dist", "dist", core.ClassGeneratedArtifact},
		{"/home/fixture/repos/app/build", "build", core.ClassGeneratedArtifact},
		{"/home/fixture/repos/app/coverage", "coverage", core.ClassGeneratedArtifact},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			entry := entryAt(tc.path)
			adapter, ok := DescribeAdapter(entry, policy)
			if !ok || adapter.Provider != tc.provider || adapter.Class != tc.class || adapter.Rebuild == "" {
				t.Fatalf("adapter = %+v, found %v", adapter, ok)
			}
			classification := Classify(entry, policy)
			if classification.Class != tc.class || classification.Rule != "classify.adapter:"+tc.provider ||
				!strings.Contains(classification.Reason, adapter.Rebuild) {
				t.Fatalf("classification = %+v", classification)
			}
			if len(adapter.OfficialCommand) > 0 && !strings.Contains(classification.Reason, adapter.OfficialCommand[len(adapter.OfficialCommand)-1]) {
				t.Fatalf("official argv absent from trace: %s", classification.Reason)
			}
			// Recognition cannot override a live owner, even for regenerable content.
			pinned := safety.Evaluate(safety.Input{
				Entry: entry, Now: plannedAt,
				Jobs: []safety.JobRef{{ID: "fixture-job", State: safety.JobRunning, Path: entry.Path}},
			})
			if !pinned.Refused() {
				t.Fatal("live owner was not protected")
			}
			if got := Evaluate(entry, policy, pinned); got.Kind != core.ActionKeep {
				t.Fatalf("provider root bypassed live owner: %+v", got)
			}
		})
		t.Run(tc.provider+":selected_scan_root", func(t *testing.T) {
			entry := entryAt(tc.path)
			entry.Root = entry.Path
			if adapter, ok := DescribeAdapter(entry, policy); !ok || adapter.Provider != tc.provider {
				t.Fatalf("selected scan root adapter = %+v, found %v", adapter, ok)
			}
		})
	}
	for _, path := range []string{
		"/home/fixture/.cache/uv-old", "/home/fixture/.npm-copy",
		"/home/fixture/.local/share/pnpm/store-old", "/home/fixture/.bun/install/cache-old",
		"/home/fixture/.gradle/caches-old", "/home/fixture/.cache/go-build-old",
		"/home/fixture/go/pkg/mod-old", "/home/fixture/.cache/ms-playwright-old",
		"/home/fixture/.cache/puppeteer-old", "/home/fixture/repos/app/venv-old",
		"/home/fixture/repos/app/node_modules-old", "/home/fixture/repos/app/dist-old",
		"/home/fixture/repos/app/build-old", "/home/fixture/repos/app/coverage-old",
		"/home/fixture/.cache/uv/packages", "/home/fixture/repos/app/node_modules/other/build",
		"/home/fixture/archive/old/app/dist",
	} {
		t.Run("not_root:"+path, func(t *testing.T) {
			entry := entryAt(path)
			if adapter, ok := DescribeAdapter(entry, policy); ok {
				t.Errorf("unselected path recognized as %s", adapter.Provider)
			}
			if got := Classify(entry, policy); strings.HasPrefix(got.Rule, "classify.adapter:") {
				t.Errorf("lookalike classified as provider: %+v", got)
			}
		})
	}
	file := entryAt("/home/fixture/.cache/uv")
	file.Kind = core.EntryKindFile
	if _, ok := DescribeAdapter(file, policy); ok {
		t.Fatal("a cache-looking file is not a directory root")
	}
	for _, path := range []string{"/home/fixture/.cache/uv-copy", "/home/fixture/repos/app/dist-copy"} {
		entry := entryAt(path)
		entry.Root = entry.Path
		if adapter, ok := DescribeAdapter(entry, policy); ok {
			t.Errorf("selected lookalike %s recognized as %s", path, adapter.Provider)
		}
	}
}

func TestBoundedCacheRuleEvidenceAndBoundaries(t *testing.T) {
	policy := fixturePolicy()
	policy.Caches = []config.CacheRule{{Name: "uv", Path: "/home/fixture/.cache/uv",
		Action: core.ActionQuarantine, Retention: core.Retention30Days,
		MaxBytes: 100, TTL: config.Duration(24 * time.Hour)}}
	base := entryAt("/home/fixture/.cache/uv")
	base.SizeIsDeep = true
	base.SizeBytes = 101
	base.LatestModifiedAt = plannedAt.Add(-24 * time.Hour)
	for _, tc := range []struct {
		name string
		edit func(*core.Entry)
		want core.ActionKind
	}{
		{"over_limit", nil, core.ActionQuarantine},
		{"at_limit", func(e *core.Entry) { e.SizeBytes = 100 }, core.ActionKeep},
		{"youngest_child", func(e *core.Entry) { e.LatestModifiedAt = plannedAt.Add(-23 * time.Hour) }, core.ActionKeep},
		{"missing_deep_walk", func(e *core.Entry) { e.SizeIsDeep = false }, core.ActionInvestigate},
		{"missing_child_timestamp", func(e *core.Entry) { e.LatestModifiedAt = time.Time{} }, core.ActionInvestigate},
		{"future_child_timestamp", func(e *core.Entry) { e.LatestModifiedAt = plannedAt.Add(time.Hour) }, core.ActionInvestigate},
		{"missing_scan_clock", func(e *core.Entry) { e.ObservedAt = time.Time{} }, core.ActionInvestigate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := base
			if tc.edit != nil {
				tc.edit(&entry)
			}
			decision := Evaluate(entry, policy, core.Verdict{})
			if decision.Kind != tc.want || !strings.Contains(strings.Join(decision.Reasons, " "), "cache rule") {
				t.Fatalf("decision = %+v, want %s", decision, tc.want)
			}
		})
	}
	file := base
	file.Kind = core.EntryKindFile
	file.SizeIsDeep = false
	file.ModifiedAt = plannedAt.Add(-24 * time.Hour)
	if got := Evaluate(file, policy, core.Verdict{}); got.Kind != core.ActionQuarantine {
		t.Fatalf("bounded file at threshold: %+v", got)
	}
	policy.Caches[0].TTL = 0
	base.LatestModifiedAt = time.Time{}
	if got := Evaluate(base, policy, core.Verdict{}); got.Kind != core.ActionQuarantine {
		t.Fatalf("size-only rule required an irrelevant timestamp: %+v", got)
	}
	policy.Caches[0].MaxBytes, policy.Caches[0].TTL = 0, config.Duration(24*time.Hour)
	base.LatestModifiedAt = plannedAt.Add(-24 * time.Hour)
	if got := Evaluate(base, policy, core.Verdict{}); got.Kind != core.ActionQuarantine {
		t.Fatalf("ttl-only rule at boundary: %+v", got)
	}
	policy.Caches[0].MaxBytes, policy.Caches[0].TTL = 0, 0
	base.SizeIsDeep = false
	base.LatestModifiedAt = time.Time{}
	if got := Evaluate(base, policy, core.Verdict{}); got.Kind != core.ActionQuarantine {
		t.Fatalf("legacy unbounded rule changed: %+v", got)
	}
}

func TestGitmootManagementAndProtectedPrecedence(t *testing.T) {
	policy := fixturePolicy()
	policy.Caches = []config.CacheRule{{Name: "everything", Path: "/home/fixture",
		Action: core.ActionDeleteCandidate}}
	for _, signal := range []string{"gitmoot:final_reclaimable", "gitmoot:pinned", "unknown:gitmoot"} {
		entry := entryAt("/home/fixture/workspaces/build")
		entry.Evidence = append(entry.Evidence, core.Evidence{Source: core.SourceFilesystem, Signal: signal, ObservedAt: plannedAt})
		classification := Classify(entry, policy)
		if classification.Class != core.ClassOperationalTool || classification.Rule != "classify.gitmoot_managed" {
			t.Errorf("%s: %+v", signal, classification)
		}
		if got := Evaluate(entry, policy, core.Verdict{}); got.Kind != core.ActionKeep {
			t.Errorf("%s: managed evidence allowed generic cleanup: %+v", signal, got)
		}
		entry.Git = &core.GitState{RepoRoot: entry.Path}
		if got := Evaluate(entry, policy, core.Verdict{}); got.Kind != core.ActionKeep {
			t.Errorf("%s: managed linked repository allowed generic cleanup: %+v", signal, got)
		}
	}
	entry := entryAt("/home/fixture/.gitmoot/build")
	policy.Protect.Paths = nil // Home is independently a mandatory policy boundary.
	if got := Evaluate(entry, policy, core.Verdict{}); got.Kind != core.ActionKeep ||
		!strings.Contains(strings.Join(got.Rules, " "), "policy.gitmoot_home") {
		t.Fatalf("managed home was not protected: %+v", got)
	}
}

func TestAdapterRulesOnlyPlanIsDeterministic(t *testing.T) {
	policy := fixturePolicy()
	entries := []core.Entry{entryAt("/home/fixture/.cache/uv"), entryAt("/home/fixture/repos/app/dist")}
	first := buildPlan(t, entries, policy, nil)
	second := buildPlan(t, entries, policy, nil)
	if !reflect.DeepEqual(first.Plan, second.Plan) {
		t.Fatal("rules-only plan changed between identical inputs")
	}
	for _, entry := range entries {
		action := actionFor(t, first, entry.Path)
		adapter, _ := DescribeAdapter(entry, policy)
		want := core.ActionQuarantine
		if adapter.Class == core.ClassCache {
			want = core.ActionInvestigate
		}
		if action.Kind != want ||
			!strings.Contains(strings.Join(action.Reasons, " "), adapter.Rebuild) {
			t.Errorf("rules-only action or rebuild implication: %+v", action)
		}
	}
}
