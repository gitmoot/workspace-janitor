package jev

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

// Provider is the name recorded for usage and plan identity.
const Provider = "openrouter"

// Mode says what the advisor actually did during a run.
type Mode string

const (
	// ModeLive sent requests.
	ModeLive Mode = "live"
	// ModeDryRun built requests and showed them without sending.
	ModeDryRun Mode = "dry_run"
	// ModeRulesOnly means the provider is not enabled, or was disabled for
	// this run.
	ModeRulesOnly Mode = "rules_only"
	// ModeNoCredentials means the provider is enabled but no key is
	// configured. That is normal, not an error: the rules decide alone.
	ModeNoCredentials Mode = "no_credentials"
)

// Cache looks up previously made decisions.
type Cache interface {
	Lookup(ctx context.Context, key string, now time.Time) (core.Recommendation, bool, error)
}

// Decision is one model answer ready to be cached.
type Decision struct {
	Key            string              `json:"key"`
	Fingerprint    string              `json:"fingerprint"`
	SchemaVersion  int                 `json:"schema_version"`
	Model          string              `json:"model"`
	PolicyDigest   string              `json:"policy_digest"`
	ResolvedModel  string              `json:"resolved_model"`
	Recommendation core.Recommendation `json:"recommendation"`
	CreatedAt      time.Time           `json:"created_at"`
	ExpiresAt      time.Time           `json:"expires_at"`
}

// Payload is an outbound request exactly as it would be sent, with the
// credential replaced. It is what dry-run and debug display.
type Payload struct {
	Method   string            `json:"method"`
	Endpoint string            `json:"endpoint"`
	Headers  map[string]string `json:"headers"`
	Body     json.RawMessage   `json:"body"`
}

// UsageTotals sums the usage reported during a run.
type UsageTotals struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	// EstimatedCostUSD is derived from reported input tokens and the
	// configured price. The API reports tokens, not money.
	EstimatedCostUSD float64 `json:"estimated_cost_usd"`
}

// Report is what the advisor did, for JSON and terminal output.
type Report struct {
	Provider       string      `json:"provider"`
	Model          string      `json:"model"`
	Mode           Mode        `json:"mode"`
	Note           string      `json:"note,omitempty"`
	Offered        int         `json:"entries_offered"`
	CacheHits      int         `json:"cache_hits"`
	Requests       int         `json:"requests"`
	Attempts       int         `json:"attempts"`
	FailedRequests int         `json:"failed_requests"`
	CircuitOpen    bool        `json:"circuit_open"`
	Investigate    int         `json:"sent_to_investigate"`
	Oversized      int         `json:"oversized_entries"`
	Usage          UsageTotals `json:"usage"`
	Failures       []string    `json:"failures,omitempty"`
	Payloads       []Payload   `json:"payloads,omitempty"`
}

// Options configures one advisor run.
type Options struct {
	Policy       config.JevPolicy
	PolicyDigest string
	ScanID       string
	// Redactor comes from the policy: configured segments plus the
	// protected-name patterns.
	Redactor Redactor
	// Client is nil in dry-run mode, which sends nothing.
	Client *Client
	Cache  Cache
	DryRun bool
	// Debug records every live payload as well.
	Debug bool
	Now   func() time.Time
}

// Advisor implements the planner's Advisor interface.
type Advisor struct {
	opts      Options
	report    Report
	decisions []Decision
	usage     []core.ModelUsage
	failures  int
}

// New builds an advisor. A live advisor needs a client; a dry-run one must
// not have one, so it cannot send anything even by mistake.
func New(opts Options) (*Advisor, error) {
	switch {
	case opts.DryRun && opts.Client != nil:
		return nil, fmt.Errorf("jev: a dry-run advisor must not have a client")
	case !opts.DryRun && opts.Client == nil:
		return nil, fmt.Errorf("jev: a live advisor needs a client")
	}
	mode := ModeLive
	if opts.DryRun {
		mode = ModeDryRun
	}
	return &Advisor{
		opts: opts,
		report: Report{
			Provider: Provider,
			Model:    opts.Policy.Model,
			Mode:     mode,
		},
	}, nil
}

// Name identifies the advisor in plans. A dry run applies no advice, so it
// shapes a plan exactly as rules-only does.
func (a *Advisor) Name() string {
	if a.opts.DryRun {
		return "rules-only"
	}
	return Provider + ":" + a.opts.Policy.Model
}

// Report returns what the advisor did.
func (a *Advisor) Report() Report { return a.report }

// Decisions returns new model answers to cache.
func (a *Advisor) Decisions() []Decision { return a.decisions }

// Usage returns one usage record per completed request.
func (a *Advisor) Usage() []core.ModelUsage { return a.usage }

// CacheKey binds a decision to everything that could change it.
func CacheKey(fingerprint string, schemaVersion int, model, policyDigest string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%s\x00%s", fingerprint, schemaVersion, model, policyDigest)))
	return hex.EncodeToString(sum[:])
}

// Classify advises on the ambiguous entries the planner offers.
//
// Entries it cannot answer for — cache miss in dry run, failed request,
// open circuit, oversized entry — are simply absent from the result, so
// the rules' decision (investigate) stands. Entries whose answer is
// unsure come back as an explicit investigate with the reason, so the
// trace says why.
func (a *Advisor) Classify(ctx context.Context, entries []core.Entry) (map[string]core.Recommendation, error) {
	now := a.now()
	advice := make(map[string]core.Recommendation, len(entries))
	a.report.Offered += len(entries)

	sorted := append([]core.Entry(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	var misses []core.Entry
	for _, entry := range sorted {
		key := a.key(entry)
		if a.opts.Cache != nil {
			cached, ok, err := a.opts.Cache.Lookup(ctx, key, now)
			if err != nil {
				a.fail(fmt.Sprintf("cache lookup failed: %v", err))
			} else if ok {
				a.report.CacheHits++
				advice[entry.Path] = cached
				continue
			}
		}
		misses = append(misses, entry)
	}
	if len(misses) == 0 {
		return advice, nil
	}

	projections := make([]Projection, 0, len(misses))
	byRef := make(map[string]core.Entry, len(misses))
	for i, entry := range misses {
		ref := fmt.Sprintf("e%d", i+1)
		projections = append(projections, Project(entry, ref, a.opts.Redactor, now))
		byRef[ref] = entry
	}

	batches, oversized := Batches(a.opts.Policy.Model, projections, a.opts.Policy.MaxBatch, a.opts.Policy.MaxStateTokens)
	a.report.Oversized += len(oversized)
	for _, projection := range oversized {
		a.fail(fmt.Sprintf("%s is too large to send within the context limit", projection.Ref))
	}

	thresholds := Thresholds{MinConfidence: a.opts.Policy.MinConfidence, MaxUnsafe: a.opts.Policy.MaxUnsafe}
	for _, batch := range batches {
		request := Build(a.opts.Policy.Model, batch)

		if a.opts.DryRun {
			a.record(request)
			continue
		}
		if a.report.CircuitOpen {
			a.fail(fmt.Sprintf("circuit breaker open: %d entrie(s) not sent", len(batch)))
			continue
		}
		if a.opts.Debug {
			a.record(request)
		}

		a.report.Requests++
		exchange, err := a.opts.Client.Evaluate(ctx, request)
		a.report.Attempts += exchange.Attempts
		if err != nil {
			a.report.FailedRequests++
			a.failures++
			a.fail(err.Error())
			if a.failures >= a.opts.Policy.BreakerFailures || isFatal(err) {
				a.report.CircuitOpen = true
			}
			continue
		}
		a.failures = 0
		a.recordUsage(exchange, now)

		for _, projection := range batch {
			entry := byRef[projection.Ref]
			recommendation, cacheable := mapAnswers(projection.Ref, exchange.Response, thresholds, now)
			if recommendation.Action == core.ActionInvestigate {
				a.report.Investigate++
			}
			advice[entry.Path] = recommendation
			if !cacheable {
				continue
			}
			a.decisions = append(a.decisions, Decision{
				Key:            a.key(entry),
				Fingerprint:    entry.Fingerprint,
				SchemaVersion:  SchemaVersion,
				Model:          a.opts.Policy.Model,
				PolicyDigest:   a.opts.PolicyDigest,
				ResolvedModel:  exchange.Response.Model,
				Recommendation: recommendation,
				CreatedAt:      now,
				ExpiresAt:      now.Add(a.opts.Policy.CacheTTL.Duration()),
			})
		}
	}
	return advice, nil
}

func (a *Advisor) key(entry core.Entry) string {
	return CacheKey(entry.Fingerprint, SchemaVersion, a.opts.Policy.Model, a.opts.PolicyDigest)
}

// record keeps an exact outbound payload with the credential replaced.
func (a *Advisor) record(request Request) {
	body, err := Encode(request)
	if err != nil {
		a.fail("encode request for display: " + err.Error())
		return
	}
	a.report.Payloads = append(a.report.Payloads, Payload{
		Method:   "POST",
		Endpoint: a.opts.Policy.Endpoint,
		Headers: map[string]string{
			"Authorization": "Bearer [redacted]",
			"Content-Type":  "application/json",
			"Accept":        "application/json",
		},
		Body: body,
	})
}

func (a *Advisor) recordUsage(exchange Exchange, now time.Time) {
	usage := exchange.Response.Usage
	cost := float64(usage.InputTokens) * a.opts.Policy.PricePerMTokUSD / 1_000_000
	a.report.Usage.InputTokens += usage.InputTokens
	a.report.Usage.OutputTokens += usage.OutputTokens
	a.report.Usage.EstimatedCostUSD += cost

	sum := sha256.Sum256(exchange.Body)
	model := exchange.Response.Model
	if model == "" {
		model = a.opts.Policy.Model
	}
	a.usage = append(a.usage, core.ModelUsage{
		ID:               fmt.Sprintf("usage-%s-%d-%d", hex.EncodeToString(sum[:])[:16], now.UnixNano(), len(a.usage)),
		ScanID:           a.opts.ScanID,
		Provider:         Provider,
		Model:            model,
		RequestKind:      "classify",
		PromptTokens:     usage.InputTokens,
		CompletionTokens: usage.OutputTokens,
		EstimatedCostUSD: cost,
		CreatedAt:        now,
	})
}

func (a *Advisor) fail(message string) {
	a.report.Failures = append(a.report.Failures, message)
}

func (a *Advisor) now() time.Time {
	if a.opts.Now != nil {
		return a.opts.Now().UTC()
	}
	return time.Now().UTC()
}

// isFatal reports failures every later request would repeat. A rejected
// key or a request the API cannot validate will not improve by retrying
// the next batch, so the breaker opens at once.
func isFatal(err error) bool {
	apiErr, ok := err.(*APIError)
	if !ok {
		return false
	}
	return apiErr.Status == 401 || apiErr.Status == 403 || apiErr.Status == 422
}
