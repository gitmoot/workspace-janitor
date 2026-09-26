package core

import (
	"strings"
	"testing"
	"time"
)

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed
}

func TestRetentionWindowAndExpiry(t *testing.T) {
	base := mustTime(t, "2026-01-01T00:00:00Z")
	cases := []struct {
		retention Retention
		window    time.Duration
		bounded   bool
		expired   time.Time
		isExpired bool
	}{
		{RetentionNone, 0, true, base, true},
		{Retention7Days, 7 * 24 * time.Hour, true, base.Add(7*24*time.Hour - time.Second), false},
		{Retention30Days, 30 * 24 * time.Hour, true, base.Add(30 * 24 * time.Hour), true},
		{RetentionPermanent, 0, false, base.Add(100000 * time.Hour), false},
	}
	for _, tc := range cases {
		window, bounded := tc.retention.Window()
		if bounded != tc.bounded || window != tc.window {
			t.Errorf("%s.Window() = (%s, %t), want (%s, %t)", tc.retention, window, bounded, tc.window, tc.bounded)
		}
		if got := tc.retention.Expired(base, tc.expired); got != tc.isExpired {
			t.Errorf("%s.Expired(at %s) = %t, want %t", tc.retention, tc.expired, got, tc.isExpired)
		}
		if _, ok := tc.retention.ExpiresAt(base); ok != tc.bounded {
			t.Errorf("%s.ExpiresAt bounded = %t, want %t", tc.retention, ok, tc.bounded)
		}
	}
}

func TestParseEnumRejectsUnknownValue(t *testing.T) {
	if _, err := ParseActionKind("delete"); err == nil {
		t.Fatal("expected \"delete\" to be rejected: the contract kind is delete_candidate")
	} else if !strings.Contains(err.Error(), "delete_candidate") {
		t.Errorf("error = %v, want the allowed values listed", err)
	}
	if kind, err := ParseActionKind("quarantine"); err != nil || kind != ActionQuarantine {
		t.Errorf("ParseActionKind(quarantine) = (%q, %v)", kind, err)
	}
}

func TestEntryValidateReportsEveryBadField(t *testing.T) {
	entry := Entry{
		Path:  "relative/path",
		Root:  "/repos/../repos",
		Kind:  "socket",
		Class: "junk",
		Evidence: []Evidence{
			{Source: "tea-leaves", Signal: ""},
		},
		Protections: []Protection{
			{Kind: "vibes", Source: SourceGit, Reason: ""},
		},
		SizeBytes: -1,
	}
	err := entry.Validate()
	if err == nil {
		t.Fatal("expected validation to fail")
	}
	fields, ok := err.(FieldErrors)
	if !ok {
		t.Fatalf("error type = %T, want FieldErrors", err)
	}
	got := map[string]bool{}
	for _, fe := range fields {
		got[fe.Field] = true
	}
	for _, want := range []string{
		"contract_version", "path", "root", "kind", "class", "size_bytes", "observed_at",
		"evidence[0].source", "evidence[0].signal", "evidence[0].observed_at",
		"protections[0].kind", "protections[0].reason",
	} {
		if !got[want] {
			t.Errorf("missing field error for %q; got %v", want, fields)
		}
	}
}

func TestEntryNormalizeAndProtected(t *testing.T) {
	local := time.FixedZone("UTC+5", 5*60*60)
	entry := Entry{
		Path:       "/repos/app",
		Root:       "/repos",
		Kind:       EntryKindDirectory,
		ObservedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, local),
		Protections: []Protection{
			{Kind: ProtectDirtyRepository, Reason: "12 modified files", Source: SourceGit, Blocking: true},
		},
	}
	entry.Normalize()
	if entry.ContractVersion != ContractVersion {
		t.Errorf("contract version = %d, want %d", entry.ContractVersion, ContractVersion)
	}
	if loc := entry.ObservedAt.Location(); loc != time.UTC {
		t.Errorf("observed_at location = %v, want UTC", loc)
	}
	if err := entry.Validate(); err != nil {
		t.Fatalf("normalized entry must validate: %v", err)
	}
	if !entry.Protected() {
		t.Error("an entry with a blocking protection must report as protected")
	}
	entry.Protections[0].Blocking = false
	if entry.Protected() {
		t.Error("a non-blocking protection must not mark the entry protected")
	}
}

func TestGitStateCleanRequiresCompleteCollection(t *testing.T) {
	var missing *GitState
	if missing.Clean() {
		t.Error("a missing Git state must never report clean")
	}
	degraded := &GitState{Degraded: true, DegradedReason: "git timed out"}
	if degraded.Clean() {
		t.Error("a degraded collection must never report clean")
	}
	dirty := &GitState{UnpublishedCommits: 1}
	if dirty.Clean() {
		t.Error("unpublished commits must not report clean")
	}
	clean := &GitState{RepoRoot: "/repos/app", UpstreamKnown: true, PublicationKnown: true}
	if !clean.Clean() {
		t.Error("a fully collected, unmodified tree must report clean")
	}
}

func TestPlanNormalizeSortsAndStampsActions(t *testing.T) {
	created := mustTime(t, "2026-02-03T04:05:06Z")
	plan := Plan{
		ID:        "plan-1",
		ScanID:    "scan-1",
		CreatedAt: created,
		Actions: []Action{
			{ID: "b", Path: "/repos/zeta", Kind: ActionQuarantine, CreatedAt: created},
			{ID: "a", Path: "/repos/alpha", Kind: ActionKeep, CreatedAt: created},
		},
	}
	plan.Normalize()
	if err := plan.Validate(); err != nil {
		t.Fatalf("normalized plan must validate: %v", err)
	}
	if plan.Actions[0].Path != "/repos/alpha" {
		t.Errorf("actions are not sorted by path: %+v", plan.Actions)
	}
	for _, action := range plan.Actions {
		if action.PlanID != plan.ID {
			t.Errorf("action %s plan id = %q, want %q", action.ID, action.PlanID, plan.ID)
		}
		if action.Status != ActionPending {
			t.Errorf("action %s status = %q, want pending", action.ID, action.Status)
		}
		if action.Retention != RetentionNone {
			t.Errorf("action %s retention = %q, want none", action.ID, action.Retention)
		}
	}
}

func TestPlanValidateRejectsDuplicateActionAndMissingDestination(t *testing.T) {
	created := mustTime(t, "2026-02-03T04:05:06Z")
	plan := Plan{
		ID:        "plan-1",
		ScanID:    "scan-1",
		CreatedAt: created,
		Actions: []Action{
			{ID: "dup", Path: "/repos/a", Kind: ActionRelocate, CreatedAt: created},
			{ID: "dup", Path: "/repos/b", Kind: ActionKeep, CreatedAt: created},
		},
	}
	plan.Normalize()
	err := plan.Validate()
	if err == nil {
		t.Fatal("expected validation to fail")
	}
	message := err.Error()
	if !strings.Contains(message, "duplicate action id") {
		t.Errorf("error = %q, want a duplicate id complaint", message)
	}
	if !strings.Contains(message, "destination") {
		t.Errorf("error = %q, want a missing relocate destination complaint", message)
	}
}

func TestPlanSummaryCoversEveryKindDeterministically(t *testing.T) {
	created := mustTime(t, "2026-02-03T04:05:06Z")
	plan := Plan{
		ID:        "plan-1",
		ScanID:    "scan-1",
		CreatedAt: created,
		Actions: []Action{
			{ID: "1", Path: "/repos/a", Kind: ActionQuarantine, CreatedAt: created},
			{ID: "2", Path: "/repos/b", Kind: ActionQuarantine, CreatedAt: created},
			{ID: "3", Path: "/repos/c", Kind: ActionKeep, CreatedAt: created},
		},
	}
	plan.Normalize()
	summary := plan.Summary()
	if summary.Total != 3 || summary.Mutates != 2 {
		t.Errorf("summary totals = (%d, %d), want (3, 2)", summary.Total, summary.Mutates)
	}
	if len(summary.ByKind) != len(ActionKinds()) {
		t.Fatalf("by_kind has %d rows, want one per action kind", len(summary.ByKind))
	}
	for i, kind := range ActionKinds() {
		if summary.ByKind[i].Kind != kind {
			t.Fatalf("by_kind[%d].kind = %q, want %q", i, summary.ByKind[i].Kind, kind)
		}
	}
	counts := map[ActionKind]int{}
	for _, row := range summary.ByKind {
		counts[row.Kind] = row.Count
	}
	if counts[ActionQuarantine] != 2 || counts[ActionKeep] != 1 || counts[ActionInvestigate] != 0 {
		t.Errorf("counts = %v", counts)
	}
}

func TestMarshalJSONIsStableAndUnescaped(t *testing.T) {
	value := map[string]any{"b": 2, "a": "x&y<z", "c": []int{3, 1}}
	first, err := MarshalJSON(value)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	second, err := MarshalJSON(value)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("encoding is not stable:\n%s\n%s", first, second)
	}
	want := `{"a":"x&y<z","b":2,"c":[3,1]}`
	if string(first) != want {
		t.Errorf("MarshalJSON = %s, want %s", first, want)
	}
}

func TestFieldErrorsSortAndErrorOrNil(t *testing.T) {
	var errs FieldErrors
	if err := errs.ErrorOrNil(); err != nil {
		t.Fatalf("empty FieldErrors must yield a nil error, got %v", err)
	}
	errs.Add("b", "second")
	errs.Add("a", "first")
	if got := errs.Error(); got != "a: first; b: second" {
		t.Errorf("Error() = %q", got)
	}
	if errs.ErrorOrNil() == nil {
		t.Error("non-empty FieldErrors must yield an error")
	}
}

func TestVerdictDecisionFollowsBlockingProtections(t *testing.T) {
	verdict := Verdict{
		Path:        "/repos/app",
		EvaluatedAt: mustTime(t, "2026-06-07T08:09:10Z"),
		Guards:      []string{"git_state"},
	}
	verdict.Normalize()
	if verdict.Decision != DecisionAllow || verdict.Refused() {
		t.Fatalf("verdict = %+v, want allow with no protections", verdict)
	}
	if err := verdict.Validate(); err != nil {
		t.Fatalf("clean verdict must validate: %v", err)
	}

	verdict.Protections = []Protection{
		{Kind: ProtectDirtyRepository, Reason: "2 changes", Source: SourceGit, Remediation: "commit", Blocking: true},
		{Kind: ProtectActiveProcess, Reason: "pid 1", Source: SourceProcess, Remediation: "stop it", Blocking: true},
		{Kind: ProtectActiveProcess, Reason: "pid 0", Source: SourceProcess, Remediation: "stop it", Blocking: true},
	}
	verdict.Normalize()
	if verdict.Decision != DecisionRefuse {
		t.Errorf("decision = %q, want refuse", verdict.Decision)
	}
	// Protections order by kind then reason, so identical evidence always
	// renders identically.
	if verdict.Protections[0].Kind != ProtectActiveProcess || verdict.Protections[0].Reason != "pid 0" {
		t.Errorf("protections are not ordered: %+v", verdict.Protections)
	}
	if kinds := verdict.Kinds(); len(kinds) != 2 {
		t.Errorf("kinds = %v, want the distinct kinds", kinds)
	}
	if verdict.Summary() != "refuse: active_process,dirty_repository" {
		t.Errorf("summary = %q", verdict.Summary())
	}
}

// A mutating action needs a clean verdict; a non-mutating one never does.
func TestVerdictAllowsOnlyNonMutatingActionsWhenRefused(t *testing.T) {
	refused := Verdict{
		Path:        "/repos/app",
		EvaluatedAt: mustTime(t, "2026-06-07T08:09:10Z"),
		Guards:      []string{"git_state"},
		Protections: []Protection{{
			Kind: ProtectDirtyRepository, Reason: "2 changes", Source: SourceGit,
			Remediation: "commit", Blocking: true,
		}},
	}
	refused.Normalize()
	for _, kind := range ActionKinds() {
		allowed := refused.Allows(kind)
		if kind.Mutating() && allowed {
			t.Errorf("%s was allowed on a refused path", kind)
		}
		if !kind.Mutating() && !allowed {
			t.Errorf("%s must stay allowed: it mutates nothing", kind)
		}
	}
}

// A refusal without a remedy is a dead end, so validation rejects it.
func TestVerdictValidateRequiresRemediationForRefusals(t *testing.T) {
	verdict := Verdict{
		Path:        "/repos/app",
		EvaluatedAt: mustTime(t, "2026-06-07T08:09:10Z"),
		Guards:      []string{"git_state"},
		Protections: []Protection{{
			Kind: ProtectDirtyRepository, Reason: "2 changes", Source: SourceGit, Blocking: true,
		}},
	}
	verdict.Normalize()
	err := verdict.Validate()
	if err == nil {
		t.Fatal("expected a refusal without remediation to be rejected")
	}
	if !strings.Contains(err.Error(), "remediation") {
		t.Errorf("error = %v, want it to name the missing remediation", err)
	}
}

func TestVerdictValidateRejectsAContradictoryDecision(t *testing.T) {
	verdict := Verdict{
		ContractVersion: ContractVersion,
		Path:            "/repos/app",
		Decision:        DecisionAllow,
		EvaluatedAt:     mustTime(t, "2026-06-07T08:09:10Z"),
		Guards:          []string{"git_state"},
		Protections: []Protection{{
			Kind: ProtectDirtyRepository, Reason: "2 changes", Source: SourceGit,
			Remediation: "commit", Blocking: true,
		}},
	}
	// Deliberately not normalized: a hand-built document must not be able
	// to claim "allow" while carrying a blocking protection.
	if err := verdict.Validate(); err == nil {
		t.Fatal("expected a contradictory verdict to be rejected")
	}
}

// A protection covering "/" must cover everything under it: prefix matching
// that appends a separator builds "//" and matches nothing, turning a valid
// protection into no protection at all.
func TestPathWithinHandlesTheRootDirectory(t *testing.T) {
	cases := []struct {
		path, target string
		want         bool
	}{
		{"/repos/app", "/", true},
		{"/", "/", true},
		{"/repos/app/src", "/repos/app", true},
		{"/repos/app", "/repos/app/", true},
		{"/repos/application", "/repos/app", false},
		{"/repos", "/repos/app", false},
		{"relative/path", "/", false},
		{"/repos/app", "", false},
		{"", "/", false},
	}
	for _, tc := range cases {
		if got := PathWithin(tc.path, tc.target); got != tc.want {
			t.Errorf("PathWithin(%q, %q) = %t, want %t", tc.path, tc.target, got, tc.want)
		}
	}
	if !PathsOverlap("/repos", "/repos/app") || !PathsOverlap("/repos/app", "/repos") {
		t.Error("overlap must hold in both directions")
	}
	if PathsOverlap("/repos", "/other") {
		t.Error("unrelated paths must not overlap")
	}
}
