package jev

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

// Every test here talks to an httptest server on loopback. None reaches the
// real API, and every entry is a fabricated fixture.

var fixedNow = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

const testKey = "sk-test-0123456789abcdef"

func testPolicy(endpoint string) config.JevPolicy {
	return config.JevPolicy{
		Enabled:         true,
		Model:           "typesafe/jev-1.13",
		Endpoint:        endpoint,
		APIKeyEnv:       "OPENROUTER_API_KEY",
		MaxBatch:        20,
		MaxStateTokens:  24000,
		Timeout:         config.Duration(2 * time.Second),
		MaxRetries:      2,
		BreakerFailures: 3,
		MinConfidence:   0.7,
		MaxUnsafe:       0.2,
		PricePerMTokUSD: 0.042,
		CacheTTL:        config.Duration(24 * time.Hour),
	}
}

// sensitiveEntry carries every kind of fact that must never leave the host.
func sensitiveEntry() core.Entry {
	return core.Entry{
		Path:          "/home/alice/work/ghp_AbCdEf1234567890GhIjKlMn/client-acme",
		Root:          "/home/alice",
		Kind:          core.EntryKindDirectory,
		Ownership:     core.Ownership{UID: 4242, GID: 4343, Mode: "0700"},
		SizeBytes:     5 << 20,
		SizeIsDeep:    true,
		ModifiedAt:    fixedNow.Add(-72 * time.Hour),
		SymlinkTarget: "/srv/secret-target",
		CanonicalPath: "/home/alice/canonical/client-acme",
		Fingerprint:   "fp-sensitive",
		Class:         core.ClassUnknown,
		Git: &core.GitState{
			RepoRoot:      "/home/alice/work/ghp_AbCdEf1234567890GhIjKlMn/client-acme",
			Remote:        "https://alice:tok3nvalue@github.com/acme/private.git",
			Branch:        "feature/acme-merger",
			Head:          "deadbeefcafebabe0123456789abcdef01234567",
			UpstreamKnown: true,
			DirtyFiles:    2,
		},
		Evidence: []core.Evidence{
			{Source: core.SourceProcess, Signal: "active_process",
				Detail: "pid 991 env AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIexample"},
			{Source: core.SourceFilesystem, Signal: "Weird Signal /home/alice", Detail: "x"},
		},
		Protections: []core.Protection{{
			Kind: core.ProtectDirtyRepository, Reason: "2 dirty files under /home/alice",
			Source: core.SourceGit, Blocking: true,
		}},
	}
}

func testRedactor() Redactor {
	return Redactor{Segments: []string{"client-*"}, SensitiveNames: []string{".env", "*.pem"}}
}

// The request body is built from an allowlist: nothing identifying reaches
// it, and the facts a classification needs do.
func TestRequestCarriesOnlySanitizedFacts(t *testing.T) {
	projection := Project(sensitiveEntry(), "e1", testRedactor(), fixedNow)
	body, err := json.Marshal(Build("typesafe/jev-1.13", []Projection{projection}))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, forbidden := range []string{
		"alice", "/home", "tok3nvalue", "github.com", "acme", "feature/", "deadbeef",
		"AWS_SECRET", "wJalr", "pid 991", "/srv/secret-target", "canonical", "4242", "4343",
		"0700", "ghp_", "Weird", "dirty files under", "fp-sensitive", "5242880",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("request body leaks %q:\n%s", forbidden, text)
		}
	}

	if projection.Path != "<root>/work/[redacted]/[redacted]" || projection.Name != "[redacted]" {
		t.Errorf("path = %q, name = %q; want the root and secret-looking segments redacted", projection.Path, projection.Name)
	}
	if projection.Git == nil || projection.Git.DirtyFiles != 2 || !projection.Git.HasUpstream {
		t.Errorf("git = %+v, want counts and booleans kept", projection.Git)
	}
	if strings.Join(projection.Signals, ",") != "active_process" {
		t.Errorf("signals = %v, want only well-formed signal names", projection.Signals)
	}
	if strings.Join(projection.Protections, ",") != "dirty_repository" {
		t.Errorf("protections = %v", projection.Protections)
	}
	if projection.Size != "under_100MiB" || projection.AgeDays != 3 || projection.Depth != 3 {
		t.Errorf("size/age/depth = %s/%d/%d", projection.Size, projection.AgeDays, projection.Depth)
	}
}

func TestRedactorRedactsConfiguredAndSecretLookingSegments(t *testing.T) {
	r := testRedactor()
	for segment, redacted := range map[string]bool{
		"node_modules":                 false,
		"my-project-2024":              false,
		"workspace-janitor":            false,
		".env":                         true,
		"server.pem":                   true,
		"client-globex":                true,
		"AKIAIOSFODNN7EXAMPLE12345678": true,
		"ghp_AbCdEf1234567890GhIjKlMn": true,
	} {
		if got := r.Segment(segment) == redactedSegment; got != redacted {
			t.Errorf("Segment(%q) redacted = %t, want %t", segment, got, redacted)
		}
	}
}

// An entry with no usable root sends only its own name, never a path.
func TestProjectionWithoutARootSendsOnlyTheName(t *testing.T) {
	entry := core.Entry{Path: "/opt/private/thing", Kind: core.EntryKindFile}
	projection := Project(entry, "e1", Redactor{}, fixedNow)
	if projection.Path != "<root>/thing" {
		t.Errorf("path = %q", projection.Path)
	}
}

// fakeServer records what it was sent and answers with a scripted reply.
type fakeServer struct {
	t       *testing.T
	mu      sync.Mutex
	bodies  [][]byte
	headers []http.Header
	reply   func(n int, request Request) (int, http.Header, any)
	server  *httptest.Server
}

func newFakeServer(t *testing.T, reply func(n int, request Request) (int, http.Header, any)) *fakeServer {
	t.Helper()
	f := &fakeServer{t: t, reply: reply}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/systemone" {
			t.Errorf("unexpected OpenRouter request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var request Request
		if err := json.Unmarshal(body, &request); err != nil {
			t.Errorf("server received an undecodable body: %v", err)
		}
		f.mu.Lock()
		f.bodies = append(f.bodies, body)
		f.headers = append(f.headers, r.Header.Clone())
		n := len(f.bodies)
		f.mu.Unlock()

		status, header, payload := f.reply(n, request)
		for k, values := range header {
			for _, v := range values {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(status)
		if raw, ok := payload.(string); ok {
			_, _ = io.WriteString(w, raw)
			return
		}
		_ = json.NewEncoder(w).Encode(payload)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeServer) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

func (f *fakeServer) client() *Client {
	return &Client{
		Endpoint:    f.server.URL + "/api/v1/systemone",
		APIKey:      testKey,
		HTTP:        f.server.Client(),
		Timeout:     2 * time.Second,
		MaxRetries:  2,
		BackoffBase: time.Millisecond,
		MaxBackoff:  5 * time.Second,
		Sleep:       func(context.Context, time.Duration) error { return nil },
	}
}

func f64(v float64) *float64 { return &v }

// answersFor scripts a confident answer for every entry in a request.
func answersFor(request Request, action, class, retention string, confidence, unsafe float64) Response {
	answers := map[string]Answer{}
	for _, entry := range request.State.Entries {
		answers[classKey(entry.Ref)] = Answer{Type: "choice", Choice: class, Confidence: f64(confidence)}
		answers[actionKey(entry.Ref)] = Answer{Type: "choice", Choice: action, Confidence: f64(confidence)}
		answers[retentionKey(entry.Ref)] = Answer{Type: "choice", Choice: retention, Confidence: f64(confidence)}
		answers[unsafeKey(entry.Ref)] = Answer{Type: "noul", Noul: f64(unsafe)}
	}
	return Response{Model: "typesafe/jev-1.13", Answers: answers, Usage: Usage{InputTokens: 1000, OutputTokens: 40}}
}

func mystery(path string) core.Entry {
	return core.Entry{
		Path: path, Root: "/home/fixture", Kind: core.EntryKindDirectory,
		Fingerprint: "fp-" + path, Class: core.ClassUnknown, ModifiedAt: fixedNow.Add(-240 * time.Hour),
	}
}

func liveAdvisor(t *testing.T, policy config.JevPolicy, client *Client, cache Cache) *Advisor {
	t.Helper()
	advisor, err := New(Options{
		Policy: policy, PolicyDigest: "policy-1", ScanID: "scan-1",
		Redactor: testRedactor(), Client: client, Cache: cache,
		Now: func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return advisor
}

// The wire contract: one POST with a bearer key, the model, a sanitized
// state, and four typed questions per entry whose action options exclude
// relocate and delete. The typed answers map onto a recommendation.
func TestLiveRequestMatchesTheAPIContractAndMapsTypedAnswers(t *testing.T) {
	server := newFakeServer(t, func(_ int, request Request) (int, http.Header, any) {
		return http.StatusOK, nil, answersFor(request, "quarantine", "generated_artifact", "30d", 0.92, 0.05)
	})
	advisor := liveAdvisor(t, testPolicy(server.server.URL+"/api/v1/systemone"), server.client(), nil)

	advice, err := advisor.Classify(context.Background(), []core.Entry{mystery("/home/fixture/out")})
	if err != nil {
		t.Fatal(err)
	}
	if server.calls() != 1 {
		t.Fatalf("server saw %d requests, want 1", server.calls())
	}
	header := server.headers[0]
	if got := header.Get("Authorization"); got != "Bearer "+testKey {
		t.Errorf("Authorization = %q", got)
	}
	if got := header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}

	var sent struct {
		Model     string `json:"model"`
		State     State  `json:"state"`
		Questions map[string]struct {
			Type         string            `json:"type"`
			Instructions map[string]string `json:"instructions"`
			Criteria     json.RawMessage   `json:"criteria"`
		} `json:"questions"`
	}
	if err := json.Unmarshal(server.bodies[0], &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Model != "typesafe/jev-1.13" || len(sent.State.Entries) != 1 || sent.State.Entries[0].Ref != "e1" {
		t.Fatalf("sent model %q with entries %+v", sent.Model, sent.State.Entries)
	}
	keys := make([]string, 0, len(sent.Questions))
	for key := range sent.Questions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "e1_action,e1_class,e1_retention,e1_unsafe" {
		t.Errorf("question keys = %v", keys)
	}
	if sent.Questions["e1_unsafe"].Type != "noul" || sent.Questions["e1_action"].Type != "choice" {
		t.Errorf("question types = %+v", sent.Questions)
	}
	if sent.Questions["e1_class"].Instructions["entry"] != "e1" {
		t.Errorf("instructions do not reference the entry: %+v", sent.Questions["e1_class"].Instructions)
	}
	var actions map[string]string
	if err := json.Unmarshal(sent.Questions["e1_action"].Criteria, &actions); err != nil {
		t.Fatal(err)
	}
	offered := make([]string, 0, len(actions))
	for option := range actions {
		offered = append(offered, option)
	}
	sort.Strings(offered)
	if strings.Join(offered, ",") != "investigate,keep,quarantine" {
		t.Errorf("action options = %v, want only keep, quarantine, investigate", offered)
	}

	got := advice["/home/fixture/out"]
	if got.Action != core.ActionQuarantine || got.Class != core.ClassGeneratedArtifact ||
		got.Retention != core.Retention30Days || got.Origin != core.OriginModel {
		t.Errorf("recommendation = %+v", got)
	}

	report := advisor.Report()
	if report.Mode != ModeLive || report.Requests != 1 || report.Attempts != 1 || report.Usage.InputTokens != 1000 {
		t.Errorf("report = %+v", report)
	}
	if want := 1000 * 0.042 / 1e6; report.Usage.EstimatedCostUSD < want*0.999 || report.Usage.EstimatedCostUSD > want*1.001 {
		t.Errorf("estimated cost = %v, want %v", report.Usage.EstimatedCostUSD, want)
	}
	usage := advisor.Usage()
	if len(usage) != 1 || usage[0].Model != "typesafe/jev-1.13" || usage[0].PromptTokens != 1000 || usage[0].ScanID != "scan-1" {
		t.Errorf("usage = %+v", usage)
	}
	decisions := advisor.Decisions()
	if len(decisions) != 1 || decisions[0].Key != CacheKey("fp-/home/fixture/out", SchemaVersion, "typesafe/jev-1.13", "policy-1") ||
		!decisions[0].ExpiresAt.Equal(fixedNow.Add(24*time.Hour)) || decisions[0].ResolvedModel != "typesafe/jev-1.13" {
		t.Errorf("decisions = %+v", decisions)
	}
}

// Anything short of a complete, well-formed, confident answer is
// investigate, with the reason stated.
func TestUnusableAnswersBecomeInvestigate(t *testing.T) {
	thresholds := Thresholds{MinConfidence: 0.7, MaxUnsafe: 0.2}
	base := func() Response {
		return answersFor(Request{State: State{Entries: []Projection{{Ref: "e1"}}}}, "quarantine", "cache", "7d", 0.9, 0.05)
	}
	cases := map[string]struct {
		mutate func(*Response)
		reason string
	}{
		"low confidence": {func(r *Response) {
			r.Answers["e1_action"] = Answer{Type: "choice", Choice: "quarantine", Confidence: f64(0.5)}
		}, "below the 0.70 threshold"},
		"unsafe": {func(r *Response) { r.Answers["e1_unsafe"] = Answer{Type: "noul", Noul: f64(0.6)} }, "exceeds the 0.20 threshold"},
		"unoffered option": {func(r *Response) {
			r.Answers["e1_action"] = Answer{Type: "choice", Choice: "delete_candidate", Confidence: f64(0.99)}
		}, "not one of the options offered"},
		"missing answer": {func(r *Response) { delete(r.Answers, "e1_class") }, "class answer unusable: missing"},
		"wrong type":     {func(r *Response) { r.Answers["e1_action"] = Answer{Type: "noul", Noul: f64(0.1)} }, "expected a choice answer"},
		"no confidence": {func(r *Response) {
			r.Answers["e1_action"] = Answer{Type: "choice", Choice: "keep"}
		}, "action answer unusable"},
		"noul out of range": {func(r *Response) { r.Answers["e1_unsafe"] = Answer{Type: "noul", Noul: f64(1.5)} }, "unsafe-probability answer unusable"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			response := base()
			tc.mutate(&response)
			got := MapAnswers("e1", response, thresholds, fixedNow)
			if got.Action != core.ActionInvestigate {
				t.Fatalf("action = %q, want investigate", got.Action)
			}
			if len(got.Reasons) != 1 || !strings.Contains(got.Reasons[0], tc.reason) {
				t.Errorf("reasons = %v, want one containing %q", got.Reasons, tc.reason)
			}
			if errs := got.Validate("recommendation"); len(errs) > 0 {
				t.Errorf("investigate recommendation is invalid: %v", errs)
			}
		})
	}

	confident := MapAnswers("e1", base(), thresholds, fixedNow)
	if confident.Action != core.ActionQuarantine || confident.Retention != core.Retention7Days {
		t.Errorf("confident answer = %+v, want quarantine for 7d", confident)
	}
}

// A class label with inadequate confidence cannot leak into an
// investigate recommendation when another answer is unusable.
func TestUnusableAnswerDoesNotKeepUncertainClass(t *testing.T) {
	response := answersFor(Request{State: State{Entries: []Projection{{Ref: "e1"}}}},
		"quarantine", "cache", "7d", 0.9, 0)
	response.Answers["e1_class"] = Answer{Type: "choice", Choice: "cache", Confidence: f64(0.1)}
	delete(response.Answers, "e1_action")
	recommendation, cacheable := mapAnswers("e1", response, Thresholds{MinConfidence: 0.7}, fixedNow)
	if recommendation.Action != core.ActionInvestigate || recommendation.Class != core.ClassUnknown || cacheable {
		t.Errorf("unusable answer = %+v, cacheable=%t; want investigate with unknown class and no cache", recommendation, cacheable)
	}
}

// A malformed response may be used safely for this run, but must not
// suppress a later valid answer for the full cache lifetime.
func TestMalformedAnswerIsNotCached(t *testing.T) {
	server := newFakeServer(t, func(n int, request Request) (int, http.Header, any) {
		if n == 1 {
			return http.StatusOK, nil, Response{Model: "typesafe/jev-1.13", Answers: map[string]Answer{},
				Usage: Usage{InputTokens: 100}}
		}
		return http.StatusOK, nil, answersFor(request, "keep", "cache", "none", 0.9, 0)
	})
	advisor := liveAdvisor(t, testPolicy(server.server.URL+"/api/v1/systemone"), server.client(), nil)
	entry := mystery("/home/fixture/uncertain")
	first, err := advisor.Classify(context.Background(), []core.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	if first[entry.Path].Action != core.ActionInvestigate || len(advisor.Decisions()) != 0 {
		t.Fatalf("malformed answer = %+v, decisions = %+v", first, advisor.Decisions())
	}
	second, err := advisor.Classify(context.Background(), []core.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	if server.calls() != 2 || second[entry.Path].Action != core.ActionKeep || len(advisor.Decisions()) != 1 {
		t.Errorf("after recovery calls=%d, advice=%+v, decisions=%+v", server.calls(), second, advisor.Decisions())
	}
}

// A malformed usage counter must not create invalid store records or
// trusted model decisions.
func TestNegativeUsageRejectsTheResponse(t *testing.T) {
	server := newFakeServer(t, func(_ int, request Request) (int, http.Header, any) {
		response := answersFor(request, "keep", "cache", "none", 0.9, 0)
		response.Usage.InputTokens = -1
		return http.StatusOK, nil, response
	})
	advisor := liveAdvisor(t, testPolicy(server.server.URL+"/api/v1/systemone"), server.client(), nil)
	entry := mystery("/home/fixture/uncertain")
	advice, err := advisor.Classify(context.Background(), []core.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	if server.calls() != 1 || len(advice) != 0 || len(advisor.Usage()) != 0 || len(advisor.Decisions()) != 0 {
		t.Errorf("negative usage accepted: calls=%d advice=%+v usage=%+v decisions=%+v",
			server.calls(), advice, advisor.Usage(), advisor.Decisions())
	}
	if advisor.Report().FailedRequests != 1 {
		t.Errorf("malformed usage not reported as a failure: %+v", advisor.Report())
	}
}

// 429 and 529 are retried after the server's Retry-After, capped by the
// client's own bound; a success after them counts every attempt.
func TestClientRetriesBackpressureHonouringRetryAfter(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, 529} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := newFakeServer(t, func(n int, request Request) (int, http.Header, any) {
				if n < 3 {
					return status, http.Header{"Retry-After": {"30"}}, `{"error":"slow down"}`
				}
				return http.StatusOK, nil, answersFor(request, "keep", "cache", "none", 0.9, 0.0)
			})
			client := server.client()
			var slept []time.Duration
			client.Sleep = func(_ context.Context, d time.Duration) error {
				slept = append(slept, d)
				return nil
			}
			exchange, err := client.Evaluate(context.Background(), Build("typesafe/jev-1.13", []Projection{{Ref: "e1"}}))
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if exchange.Attempts != 3 || server.calls() != 3 {
				t.Errorf("attempts = %d, calls = %d; want 3", exchange.Attempts, server.calls())
			}
			if len(slept) != 2 || slept[0] != 5*time.Second || slept[1] != 5*time.Second {
				t.Errorf("slept %v, want Retry-After capped at the 5s bound twice", slept)
			}
		})
	}
}

// Retries are bounded: a persistent 429 gives up after MaxRetries.
func TestClientGivesUpAfterBoundedRetries(t *testing.T) {
	server := newFakeServer(t, func(int, Request) (int, http.Header, any) {
		return http.StatusTooManyRequests, nil, `{"error":"rate limited"}`
	})
	exchange, err := server.client().Evaluate(context.Background(), Build("typesafe/jev-1.13", nil))
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusTooManyRequests {
		t.Fatalf("err = %v, want a 429 APIError", err)
	}
	if exchange.Attempts != 3 || server.calls() != 3 {
		t.Errorf("attempts = %d, calls = %d; want 1 + 2 retries", exchange.Attempts, server.calls())
	}
}

// A rejected key or an invalid request fails the same way every time, so
// it is not retried; an echoed key never reaches the error text.
func TestClientDoesNotRetryPermanentFailures(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusUnprocessableEntity} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := newFakeServer(t, func(int, Request) (int, http.Header, any) {
				return status, nil, `{"error":"bad key ` + testKey + `"}`
			})
			exchange, err := server.client().Evaluate(context.Background(), Build("typesafe/jev-1.13", nil))
			if err == nil {
				t.Fatal("want an error")
			}
			if exchange.Attempts != 1 || server.calls() != 1 {
				t.Errorf("attempts = %d, calls = %d; want no retry", exchange.Attempts, server.calls())
			}
			if strings.Contains(err.Error(), testKey) {
				t.Errorf("error text leaks the key: %v", err)
			}
		})
	}
}

// A 307 must not forward even sanitized host metadata or a credential
// to another address, regardless of the supplied HTTP client's policy.
func TestClientRefusesRedirects(t *testing.T) {
	var forwarded atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)

	httpClient := source.Client()
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }
	client := &Client{
		Endpoint: source.URL, APIKey: testKey, HTTP: httpClient,
		Timeout: time.Second, MaxRetries: 0,
	}
	exchange, err := client.Evaluate(context.Background(), Build("typesafe/jev-1.13", []Projection{{Ref: "e1"}}))
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusTemporaryRedirect || exchange.Attempts != 1 {
		t.Errorf("redirect = %+v, %v; want an unforwarded 307 after one request", exchange, err)
	}
	if forwarded.Load() != 0 {
		t.Errorf("redirect target received %d request(s)", forwarded.Load())
	}
}

// A slow server is cut off by the per-attempt timeout instead of stalling
// the plan.
func TestClientTimesOutASlowServer(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(release) })

	client := &Client{
		Endpoint: server.URL, APIKey: testKey, HTTP: server.Client(),
		Timeout: 50 * time.Millisecond, MaxRetries: 1,
		Sleep: func(context.Context, time.Duration) error { return nil },
	}
	started := time.Now()
	exchange, err := client.Evaluate(context.Background(), Build("typesafe/jev-1.13", nil))
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.Retryable {
		t.Fatalf("err = %v, want a retryable timeout", err)
	}
	if exchange.Attempts != 2 {
		t.Errorf("attempts = %d, want the timeout retried once", exchange.Attempts)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("evaluate took %v; the timeout did not bound it", elapsed)
	}
}

func TestClientRetriesOrdinarySendGateTimeoutBeforeMidnight(t *testing.T) {
	server := newFakeServer(t, func(_ int, request Request) (int, http.Header, any) {
		return http.StatusOK, nil, answersFor(request, "keep", "cache", "none", 0.9, 0)
	})
	client := server.client()
	client.MaxRetries = 1
	client.SendDeadline = time.Now().Add(time.Minute)
	client.Sleep = func(context.Context, time.Duration) error { return nil }
	reservations := 0
	client.BeforeAttempt = func(context.Context, Request, []byte) error {
		reservations++
		return nil
	}
	client.BeforeSend = func(context.Context) error {
		if reservations == 1 {
			return context.DeadlineExceeded
		}
		return nil
	}
	exchange, err := client.Evaluate(context.Background(), Build("typesafe/jev-1.13", []Projection{{Ref: "e1"}}))
	if err != nil || exchange.Attempts != 2 || reservations != 2 || server.calls() != 1 {
		t.Fatalf("ordinary timeout consumed the rest of the advisory: err=%v attempts=%d reservations=%d calls=%d",
			err, exchange.Attempts, reservations, server.calls())
	}
}

type waitingBeforeWire struct {
	entered chan struct{}
}

func (t waitingBeforeWire) RoundTrip(req *http.Request) (*http.Response, error) {
	close(t.entered)
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func TestClientSendDeadlineCancelsPausedTransportWithoutRetry(t *testing.T) {
	transport := waitingBeforeWire{entered: make(chan struct{})}
	checks := 0
	var client *Client
	client = &Client{
		Endpoint: "http://127.0.0.1:1/api/v1/systemone", APIKey: testKey,
		HTTP:    &http.Client{Transport: transport},
		Timeout: 3 * time.Second, MaxRetries: 2,
		BeforeAttempt: func(context.Context, Request, []byte) error {
			client.SendDeadline = time.Now().Add(time.Second)
			return nil
		},
		BeforeSend: func(context.Context) error { checks++; return nil },
	}
	exchange, err := client.Evaluate(context.Background(), Build("typesafe/jev-1.13", nil))
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.Fatal || exchange.Attempts != 1 || checks != 1 {
		t.Fatalf("expired send deadline retried: err=%v exchange=%+v gate checks=%d", err, exchange, checks)
	}
	select {
	case <-transport.entered:
	default:
		t.Fatal("transport never entered; deadline was not exercised")
	}
}

// Consecutive failures open the breaker, after which nothing more is sent;
// a rejected key opens it at once.
func TestCircuitBreakerStopsSendingAfterFailures(t *testing.T) {
	entries := []core.Entry{mystery("/home/fixture/a"), mystery("/home/fixture/b"), mystery("/home/fixture/c"), mystery("/home/fixture/d")}

	server := newFakeServer(t, func(int, Request) (int, http.Header, any) {
		return http.StatusInternalServerError, nil, `{"error":"boom"}`
	})
	policy := testPolicy(server.server.URL + "/api/v1/systemone")
	policy.MaxBatch = 1
	policy.BreakerFailures = 2
	client := server.client()
	client.MaxRetries = 0
	advisor := liveAdvisor(t, policy, client, nil)
	advice, err := advisor.Classify(context.Background(), entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(advice) != 0 {
		t.Errorf("advice = %+v, want none when every request failed", advice)
	}
	report := advisor.Report()
	if server.calls() != 2 || !report.CircuitOpen || report.FailedRequests != 2 {
		t.Errorf("calls = %d, report = %+v; want the breaker open after 2", server.calls(), report)
	}
	if len(advisor.Usage()) != 0 || len(advisor.Decisions()) != 0 {
		t.Error("failed requests produced usage or cached decisions")
	}

	rejected := newFakeServer(t, func(int, Request) (int, http.Header, any) {
		return http.StatusUnauthorized, nil, `{"error":"invalid key"}`
	})
	policy = testPolicy(rejected.server.URL + "/api/v1/systemone")
	policy.MaxBatch = 1
	advisor = liveAdvisor(t, policy, rejected.client(), nil)
	if _, err := advisor.Classify(context.Background(), entries); err != nil {
		t.Fatal(err)
	}
	if rejected.calls() != 1 || !advisor.Report().CircuitOpen {
		t.Errorf("calls = %d, want the breaker open after one 401", rejected.calls())
	}
}

// A dry run builds the exact requests and sends none of them.
func TestDryRunShowsExactPayloadsAndSendsNothing(t *testing.T) {
	if _, err := New(Options{Policy: testPolicy("https://openrouter.ai/api/v1/systemone"), DryRun: true, Client: &Client{}}); err == nil {
		t.Fatal("a dry-run advisor accepted a client")
	}
	advisor, err := New(Options{
		Policy: testPolicy("https://openrouter.ai/api/v1/systemone"), PolicyDigest: "policy-1",
		Redactor: testRedactor(), DryRun: true, Now: func() time.Time { return fixedNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	entries := []core.Entry{sensitiveEntry(), mystery("/home/fixture/x")}
	advice, err := advisor.Classify(context.Background(), entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(advice) != 0 || advisor.Name() != "rules-only" {
		t.Errorf("dry run produced advice %+v under name %q", advice, advisor.Name())
	}
	report := advisor.Report()
	if report.Mode != ModeDryRun || report.Requests != 0 || len(report.Payloads) != 1 {
		t.Fatalf("report = %+v, want one displayed payload and no requests", report)
	}
	payload := report.Payloads[0]
	if payload.Headers["Authorization"] != "Bearer [redacted]" ||
		payload.Endpoint != "https://openrouter.ai/api/v1/systemone" {
		t.Errorf("payload = %+v", payload)
	}
	var request Request
	if err := json.Unmarshal(payload.Body, &request); err != nil {
		t.Fatal(err)
	}
	if len(request.State.Entries) != 2 || len(request.Questions) != 8 {
		t.Errorf("displayed request has %d entries and %d questions", len(request.State.Entries), len(request.Questions))
	}
	if strings.Contains(string(payload.Body), "alice") {
		t.Error("the displayed payload is not the sanitized one")
	}
}

// Entries are packed within the batch size and the state budget; an entry
// too large to send alone is reported, not sent.
func TestBatchesRespectLimits(t *testing.T) {
	projections := make([]Projection, 0, 6)
	for i := range 5 {
		projections = append(projections, Project(mystery(fmt.Sprintf("/home/fixture/p%d", i)), fmt.Sprintf("e%d", i+1), Redactor{}, fixedNow))
	}
	huge := Project(mystery("/home/fixture/"+strings.Repeat("deep/", 40000)+"x"), "e6", Redactor{}, fixedNow)
	projections = append(projections, huge)

	batches, oversized := Batches("typesafe/jev-1.13", projections, 2, 24000)
	if len(oversized) != 1 || oversized[0].Ref != "e6" {
		t.Fatalf("oversized = %v, want only e6", oversized)
	}
	sizes := []int{}
	for _, batch := range batches {
		sizes = append(sizes, len(batch))
		if tokens := estimateTokens(Build("typesafe/jev-1.13", batch)); tokens > requestTokenLimit {
			t.Errorf("batch of %d estimates %d tokens, over the limit", len(batch), tokens)
		}
	}
	if fmt.Sprint(sizes) != "[2 2 1]" {
		t.Errorf("batch sizes = %v, want [2 2 1]", sizes)
	}

	// The state budget covers the state plus the longest question, so a
	// budget that fits a few entries splits five of them.
	small, _ := Batches("typesafe/jev-1.13", projections[:5], 20, 500)
	for _, batch := range small {
		state := State{Task: task, Entries: batch}
		if estimateTokens(state) > 500 {
			t.Errorf("a batch's state exceeds the state budget")
		}
	}
	if len(small) < 2 {
		t.Errorf("a tight state budget still packed everything into %d batch(es)", len(small))
	}
}

// The total request bound, not just the state bound, must split a batch
// that would exceed Jev's OpenRouter context after its typed questions
// are added.
func TestBatchesIncludeQuestionsInOpenRouterContextLimit(t *testing.T) {
	projections := make([]Projection, 20)
	for i := range projections {
		projections[i] = Projection{
			Ref: fmt.Sprintf("e%d", i+1), Path: "<root>/" + strings.Repeat("p", 3000),
			Name: "fixture", Kind: "directory",
		}
	}
	state := State{Task: task, Entries: projections}
	if tokens := estimateTokens(state); tokens >= 24000 {
		t.Fatalf("fixture state alone estimates %d tokens, want below the state limit", tokens)
	}
	if tokens := estimateTokens(Build("typesafe/jev-1.13", projections)); tokens <= requestTokenLimit {
		t.Fatalf("fixture request estimates %d tokens, want above the total limit", tokens)
	}
	batches, oversized := Batches("typesafe/jev-1.13", projections, 20, 24000)
	if len(oversized) != 0 || len(batches) < 2 {
		t.Fatalf("total limit gave %d batch(es) and %d oversized entries", len(batches), len(oversized))
	}
	for _, batch := range batches {
		if tokens := estimateTokens(Build("typesafe/jev-1.13", batch)); tokens > requestTokenLimit {
			t.Errorf("batch estimates %d tokens, over the OpenRouter request limit", tokens)
		}
	}
}

// memoryCache is an in-memory Cache for tests.
type memoryCache map[string]core.Recommendation

func (m memoryCache) Lookup(_ context.Context, key string, _ time.Time) (core.Recommendation, bool, error) {
	r, ok := m[key]
	return r, ok, nil
}

// A cached decision is reused without a request, and the key changes with
// everything that could change the answer.
func TestCacheReuseAndKeyBinding(t *testing.T) {
	base := CacheKey("fp", 1, "typesafe/jev-1.13", "policy")
	for name, other := range map[string]string{
		"fingerprint": CacheKey("fp2", 1, "typesafe/jev-1.13", "policy"),
		"schema":      CacheKey("fp", 2, "typesafe/jev-1.13", "policy"),
		"model":       CacheKey("fp", 1, "typesafe/jev-1.14", "policy"),
		"policy":      CacheKey("fp", 1, "typesafe/jev-1.13", "policy2"),
	} {
		if other == base {
			t.Errorf("changing the %s did not change the cache key", name)
		}
	}

	server := newFakeServer(t, func(_ int, request Request) (int, http.Header, any) {
		return http.StatusOK, nil, answersFor(request, "keep", "cache", "none", 0.9, 0.0)
	})
	entry := mystery("/home/fixture/cached")
	cached := core.Recommendation{Action: core.ActionKeep, Class: core.ClassCache, Retention: core.RetentionNone,
		Confidence: 0.9, Origin: core.OriginModel, DecidedAt: fixedNow}
	cache := memoryCache{CacheKey(entry.Fingerprint, SchemaVersion, "typesafe/jev-1.13", "policy-1"): cached}
	advisor := liveAdvisor(t, testPolicy(server.server.URL+"/api/v1/systemone"), server.client(), cache)
	advice, err := advisor.Classify(context.Background(), []core.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	if server.calls() != 0 || advisor.Report().CacheHits != 1 || advice[entry.Path].Action != core.ActionKeep {
		t.Errorf("calls = %d, report = %+v; want a cache hit and no request", server.calls(), advisor.Report())
	}
}
