package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/jev"
)

// These tests run the real plan command against a loopback httptest
// server. Nothing reaches the real API, and every entry lives in a
// throwaway fixture home.

const fakeKey = "sk-fixture-key-0000"

// fakeJev answers every typed question for every entry in a request.
type fakeJev struct {
	t      *testing.T
	mu     sync.Mutex
	bodies []string
	auth   []string
	status int
	action string
	class  string
	server *httptest.Server
}

func newFakeJev(t *testing.T, action, class string) *fakeJev {
	t.Helper()
	f := &fakeJev{t: t, status: http.StatusOK, action: action, class: class}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.bodies = append(f.bodies, string(raw))
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		status := f.status
		f.mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"error":"unavailable"}`)
			return
		}
		var request jev.Request
		if err := json.Unmarshal(raw, &request); err != nil {
			t.Errorf("undecodable request: %v", err)
		}
		confidence, unsafe := 0.95, 0.01
		answers := map[string]jev.Answer{}
		for _, entry := range request.State.Entries {
			answers[entry.Ref+"_class"] = jev.Answer{Type: "choice", Choice: f.class, Confidence: &confidence}
			answers[entry.Ref+"_action"] = jev.Answer{Type: "choice", Choice: f.action, Confidence: &confidence}
			answers[entry.Ref+"_retention"] = jev.Answer{Type: "choice", Choice: "30d", Confidence: &confidence}
			answers[entry.Ref+"_unsafe"] = jev.Answer{Type: "noul", Noul: &unsafe}
		}
		_ = json.NewEncoder(w).Encode(jev.Response{
			Model: "jev-1.13.0", Answers: answers,
			Usage: jev.Usage{InputTokens: 1000, OutputTokens: 40},
		})
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeJev) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

// enableJev rewrites the plan fixture's policy with the model enabled and
// pointed at the fake server.
func (f *planFixture) enableJev(t *testing.T, endpoint string, extra ...string) {
	t.Helper()
	f.writePolicy(t, strings.Join(append([]string{
		"roots:",
		"  - path: " + f.root,
		"    max_depth: 1",
		"collectors:",
		"  git: false",
		"  processes: false",
		"  services: false",
		"canonical_roots:",
		"  - class: primary_project",
		"    path: " + f.repos,
		"jev:",
		"  enabled: true",
		"  endpoint: " + endpoint,
		"  max_retries: 0",
		"  min_interval: 0s",
	}, extra...), "\n")+"\n")
}

type advisedPlan struct {
	Data struct {
		Plan      core.Plan  `json:"plan"`
		Persisted bool       `json:"persisted"`
		Reused    bool       `json:"reused"`
		Advisor   jev.Report `json:"advisor"`
	} `json:"data"`
}

func (f *planFixture) advisedPlan(t *testing.T, args ...string) (advisedPlan, string) {
	t.Helper()
	stdout, stderr, code := f.run(t, append([]string{"--format", "json", "plan"}, args...)...)
	if code != ExitOK {
		t.Fatalf("plan exit = %d, stderr = %s", code, stderr)
	}
	var doc advisedPlan
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("plan JSON: %v\n%s", err, stdout)
	}
	return doc, stdout
}

func actionAt(t *testing.T, plan core.Plan, path string) core.Action {
	t.Helper()
	for _, action := range plan.Actions {
		if action.Path == path {
			return action
		}
	}
	t.Fatalf("no action for %s", path)
	return core.Action{}
}

// With a key, only the ambiguous entries are sent, sanitized; the safer
// advice is applied and credited; usage is recorded and shown; and
// re-planning the same inputs reuses the stored plan without a request.
func TestPlanConsultsJevForAmbiguousEntriesOnly(t *testing.T) {
	server := newFakeJev(t, "keep", "operational_tool")
	f := newPlanFixture(t)
	f.enableJev(t, server.server.URL)
	f.env["TYPESAFE_API_KEY"] = fakeKey
	f.scan(t)

	doc, _ := f.advisedPlan(t)
	if server.calls() != 1 {
		t.Fatalf("server saw %d requests, want 1", server.calls())
	}
	if server.auth[0] != "Bearer "+fakeKey {
		t.Errorf("Authorization = %q", server.auth[0])
	}
	body := server.bodies[0]
	if !strings.Contains(body, `"<root>/mystery"`) {
		t.Errorf("the ambiguous entry was not sent:\n%s", body)
	}
	for _, forbidden := range []string{f.home, "node_modules", ".cache", "backups", fakeKey} {
		if strings.Contains(body, forbidden) {
			t.Errorf("request body contains %q:\n%s", forbidden, body)
		}
	}

	report := doc.Data.Advisor
	if report.Mode != jev.ModeLive || report.Requests != 1 || report.Usage.InputTokens != 1000 {
		t.Errorf("advisor report = %+v", report)
	}
	if doc.Data.Plan.Advisor != "typesafe:jev-latest" {
		t.Errorf("plan advisor = %q", doc.Data.Plan.Advisor)
	}
	mystery := actionAt(t, doc.Data.Plan, filepath.Join(f.root, "mystery"))
	if mystery.Kind != core.ActionKeep || !containsRule(mystery.Rules, "advisor:typesafe:jev-latest") {
		t.Errorf("mystery = %s via %v, want the safer keep credited to the advisor", mystery.Kind, mystery.Rules)
	}
	if got := actionAt(t, doc.Data.Plan, filepath.Join(f.root, "node_modules")); got.Kind != core.ActionQuarantine {
		t.Errorf("a rules-decided entry changed: node_modules = %s", got.Kind)
	}

	// Re-planning answers from the decision cache: no request, and the
	// same advice yields the same stored plan.
	again, _ := f.advisedPlan(t)
	if server.calls() != 1 || !again.Data.Reused || again.Data.Plan.ID != doc.Data.Plan.ID {
		t.Errorf("re-planning sent %d requests (reused=%t); want the stored plan and no request", server.calls()-1, again.Data.Reused)
	}
	if again.Data.Advisor.CacheHits == 0 {
		t.Errorf("re-planning did not answer from the cache: %+v", again.Data.Advisor)
	}

	stdout, stderr, code := f.run(t, "--format", "json", "status")
	if code != ExitOK {
		t.Fatalf("status: %s", stderr)
	}
	var status struct {
		Data struct {
			Store struct {
				ModelUsage struct {
					Records          int64   `json:"records"`
					PromptTokens     int64   `json:"prompt_tokens"`
					EstimatedCostUSD float64 `json:"estimated_cost_usd"`
				} `json:"model_usage"`
			} `json:"store"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &status); err != nil {
		t.Fatal(err)
	}
	if usage := status.Data.Store.ModelUsage; usage.Records != 1 || usage.PromptTokens != 1000 || usage.EstimatedCostUSD <= 0 {
		t.Errorf("status model usage = %+v", usage)
	}
	text, _, _ := f.run(t, "status")
	if !strings.Contains(text, "model usage:") || !strings.Contains(text, "1 request(s), 1000 input") {
		t.Errorf("status text does not show model usage:\n%s", text)
	}
}

// Rules-only is the default and stays complete: no key, the model
// disabled, or --no-jev all plan without a request.
func TestPlanWithoutTheModelSendsNothing(t *testing.T) {
	server := newFakeJev(t, "keep", "operational_tool")

	noKey := newPlanFixture(t)
	noKey.enableJev(t, server.server.URL)
	noKey.scan(t)
	doc, _ := noKey.advisedPlan(t)
	if doc.Data.Advisor.Mode != jev.ModeNoCredentials || doc.Data.Plan.Advisor != "rules-only" {
		t.Errorf("no key: advisor = %+v, plan advisor %q", doc.Data.Advisor, doc.Data.Plan.Advisor)
	}
	if got := actionAt(t, doc.Data.Plan, filepath.Join(noKey.root, "mystery")); got.Kind != core.ActionInvestigate {
		t.Errorf("no key: mystery = %s, want the rules' investigate", got.Kind)
	}

	optOut := newPlanFixture(t)
	optOut.enableJev(t, server.server.URL)
	optOut.env["TYPESAFE_API_KEY"] = fakeKey
	optOut.scan(t)
	doc, _ = optOut.advisedPlan(t, "--no-jev")
	if doc.Data.Advisor.Mode != jev.ModeRulesOnly || doc.Data.Plan.Advisor != "rules-only" {
		t.Errorf("--no-jev: advisor = %+v", doc.Data.Advisor)
	}

	disabled := newPlanFixture(t)
	disabled.env["TYPESAFE_API_KEY"] = fakeKey
	disabled.scan(t)
	doc, _ = disabled.advisedPlan(t)
	if doc.Data.Advisor.Mode != jev.ModeRulesOnly {
		t.Errorf("disabled: advisor = %+v", doc.Data.Advisor)
	}

	if server.calls() != 0 {
		t.Errorf("rules-only planning sent %d request(s)", server.calls())
	}
}

// A dry run prints the exact sanitized requests, redacts the key, sends
// nothing, and stores nothing.
func TestPlanDryRunShowsRequestsWithoutSending(t *testing.T) {
	server := newFakeJev(t, "keep", "operational_tool")
	f := newPlanFixture(t)
	f.enableJev(t, server.server.URL)
	f.env["TYPESAFE_API_KEY"] = fakeKey
	f.scan(t)

	doc, stdout := f.advisedPlan(t, "--jev-dry-run")
	if server.calls() != 0 {
		t.Fatalf("a dry run sent %d request(s)", server.calls())
	}
	if doc.Data.Persisted || doc.Data.Advisor.Mode != jev.ModeDryRun || len(doc.Data.Advisor.Payloads) != 1 {
		t.Fatalf("dry run: persisted=%t advisor=%+v", doc.Data.Persisted, doc.Data.Advisor)
	}
	payload := doc.Data.Advisor.Payloads[0]
	if payload.Headers["Authorization"] != "Bearer [redacted]" || payload.Endpoint != server.server.URL {
		t.Errorf("payload = %+v", payload)
	}
	if strings.Contains(stdout, fakeKey) || strings.Contains(string(payload.Body), f.home) {
		t.Error("the dry run leaked the key or the home path")
	}
	if got := actionAt(t, doc.Data.Plan, filepath.Join(f.root, "mystery")); got.Kind != core.ActionInvestigate {
		t.Errorf("a dry run applied advice: mystery = %s", got.Kind)
	}

	text, _, code := f.run(t, "plan", "--jev-dry-run")
	if code != ExitOK || !strings.Contains(text, "mode:") || !strings.Contains(text, "request 1 of 1") ||
		!strings.Contains(text, `"<root>/mystery"`) ||
		!strings.Contains(text, "Bearer [redacted]") {
		t.Errorf("dry-run text output does not show the request:\n%s", text)
	}

	if _, _, code := f.run(t, "plan", "--jev-dry-run", "--no-jev"); code != ExitUsage {
		t.Errorf("--jev-dry-run with --no-jev exit = %d, want a usage error", code)
	}
}

// A failing provider leaves the rules' plan intact and says what failed.
func TestPlanSurvivesAFailingProvider(t *testing.T) {
	server := newFakeJev(t, "keep", "operational_tool")
	server.status = http.StatusServiceUnavailable
	f := newPlanFixture(t)
	f.enableJev(t, server.server.URL)
	f.env["TYPESAFE_API_KEY"] = fakeKey
	f.scan(t)

	doc, _ := f.advisedPlan(t)
	if server.calls() == 0 {
		t.Fatal("the provider was never called")
	}
	report := doc.Data.Advisor
	if report.FailedRequests == 0 || len(report.Failures) == 0 || report.Usage.InputTokens != 0 {
		t.Errorf("report = %+v, want the failure reported and no usage", report)
	}
	if got := actionAt(t, doc.Data.Plan, filepath.Join(f.root, "mystery")); got.Kind != core.ActionInvestigate {
		t.Errorf("mystery = %s, want the rules' investigate", got.Kind)
	}

	// Once the provider recovers, re-planning asks again and yields a new
	// plan: the plan a failure shaped is not served in its place.
	server.mu.Lock()
	server.status = http.StatusOK
	server.mu.Unlock()
	calls := server.calls()
	recovered, _ := f.advisedPlan(t)
	if server.calls() == calls {
		t.Fatal("re-planning after a failure did not ask the provider again")
	}
	if recovered.Data.Reused || recovered.Data.Plan.ID == doc.Data.Plan.ID {
		t.Errorf("re-planning reused the failed plan %s", doc.Data.Plan.ID)
	}
	if got := actionAt(t, recovered.Data.Plan, filepath.Join(f.root, "mystery")); got.Kind != core.ActionKeep {
		t.Errorf("after recovery mystery = %s, want the advisor's keep", got.Kind)
	}
}

// A model can never move an entry the safety engine protects, however
// confident it is: its proposal is offered, clamped, and recorded as
// rejected.
func TestModelCannotMoveAProtectedEntry(t *testing.T) {
	server := newFakeJev(t, "quarantine", "generated_artifact")
	f := newPlanFixture(t)
	protected := filepath.Join(f.root, "mystery")
	f.enableJev(t, server.server.URL, "protect:", "  paths:", "    - "+protected)
	f.env["TYPESAFE_API_KEY"] = fakeKey
	f.scan(t)

	doc, _ := f.advisedPlan(t)
	if server.calls() != 1 || !strings.Contains(server.bodies[0], `"<root>/mystery"`) {
		t.Fatalf("the protected ambiguous entry was not offered to the model")
	}
	got := actionAt(t, doc.Data.Plan, protected)
	if got.Kind != core.ActionKeep {
		t.Fatalf("protected entry = %s via %v, want it left in place", got.Kind, got.Rules)
	}
	rejected := false
	for _, alternative := range got.Rejected {
		if alternative.Rule == "advisor:typesafe:jev-latest" {
			rejected = true
		}
	}
	if !rejected {
		t.Errorf("the model's proposal was not recorded as rejected: %+v", got.Rejected)
	}
}

func containsRule(rules []string, want string) bool {
	for _, rule := range rules {
		if rule == want {
			return true
		}
	}
	return false
}
