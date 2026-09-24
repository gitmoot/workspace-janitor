package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/jev"
	"github.com/gitmoot/workspace-janitor/internal/plan"
	"github.com/gitmoot/workspace-janitor/internal/safety"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

const hostAdvisoryKeyFile = "/root/.env"

type advisorySuggestion struct {
	Path           string              `json:"path"`
	Recommendation core.Recommendation `json:"recommendation"`
}

// advisoryReport is private state, not a Plan: it has no action IDs, approval,
// or mutation authority. Only `advisory report` prints paths; the scheduled
// run's stdout is a path-free summary suitable for the service journal.
type advisoryReport struct {
	Day            string               `json:"utc_day"`
	ScanID         string               `json:"scan_id"`
	Status         string               `json:"status"`
	Reason         string               `json:"reason,omitempty"`
	Incomplete     bool                 `json:"incomplete"`
	Candidates     int                  `json:"candidate_entries"`
	SkippedUnknown int                  `json:"skipped_unknown"`
	SkippedBudget  int                  `json:"skipped_budget"`
	Suggestions    []advisorySuggestion `json:"suggestions,omitempty"`
	Advisor        jev.Report           `json:"advisor"`
	Budget         store.AdvisoryBudget `json:"reserved_daily_budget"`
	// The API reports tokens, not billed money. Advisor's cost is estimated
	// from the response's token count; Budget uses pre-request estimates.
}

type advisorySummary struct {
	Day            string               `json:"utc_day"`
	ScanID         string               `json:"scan_id"`
	Status         string               `json:"status"`
	Reason         string               `json:"reason,omitempty"`
	Incomplete     bool                 `json:"incomplete"`
	Candidates     int                  `json:"candidate_entries"`
	SkippedUnknown int                  `json:"skipped_unknown"`
	Budget         store.AdvisoryBudget `json:"reserved_daily_budget"`
}

func advisoryCommand() *command {
	return &command{name: "advisory", usage: "janitor advisory <run|report>",
		summary: "Review-only daily Jev advice after a successful cycle", subcommands: []*command{
			{name: "run", usage: "janitor advisory run [--key-file ABSOLUTE_PATH]",
				summary: "Reserve bounded daily budget and write a private, non-executable report",
				register: func(fs *flag.FlagSet) func(context.Context, *env, []string) error {
					keyFile := fs.String("key-file", hostAdvisoryKeyFile, "owner-only dotenv file containing OPENROUTER_API_KEY")
					return func(ctx context.Context, e *env, args []string) error {
						if len(args) != 0 {
							return &usageError{msg: "advisory run takes no arguments"}
						}
						return runDailyAdvisory(ctx, e, *keyFile)
					}
				}},
			{name: "report", usage: "janitor advisory report [--day YYYY-MM-DD]",
				summary: "Read the private review-only daily report",
				register: func(fs *flag.FlagSet) func(context.Context, *env, []string) error {
					day := fs.String("day", "", "UTC day (default today)")
					return func(ctx context.Context, e *env, args []string) error {
						if len(args) != 0 {
							return &usageError{msg: "advisory report takes no arguments"}
						}
						return showDailyAdvisory(ctx, e, *day)
					}
				}},
		}}
}

func runDailyAdvisory(ctx context.Context, e *env, keyFile string) error {
	paths, err := e.resolvePaths()
	if err != nil {
		return err
	}
	policy, err := e.loadPolicy()
	if err != nil {
		return err
	}
	if !policy.Jev.Enabled {
		return errors.New("daily advisory disabled in policy; no outbound call")
	}
	if policy.Jev.APIKeyEnv != "OPENROUTER_API_KEY" {
		return errors.New("daily advisory requires the pinned OpenRouter key name")
	}
	price := policy.Jev.PricePerMTokUSD
	if math.IsNaN(price) || math.IsInf(price, 0) || price < 0.042 {
		return errors.New("daily advisory price is unknown or below the pinned rate; no outbound call")
	}
	endpoint, err := url.Parse(policy.Jev.Endpoint)
	if err != nil {
		return errors.New("invalid advisory endpoint")
	}
	// Production permits only the exact pinned OpenRouter URL. Fake-server
	// runs require an IP-literal loopback endpoint and a separate synthetic
	// key file, never the host's reported credential path.
	if endpoint.Scheme == "http" {
		ip := net.ParseIP(endpoint.Hostname())
		if ip == nil || !ip.IsLoopback() || keyFile == hostAdvisoryKeyFile {
			return errors.New("loopback advisory requires a literal loopback address and synthetic key file")
		}
	} else if policy.Jev.Endpoint != "https://openrouter.ai/api/v1/systemone" {
		return errors.New("daily advisory endpoint must be OpenRouter")
	}
	if !filepath.IsAbs(keyFile) {
		return errors.New("advisory key file must be absolute")
	}

	if err := validatePrivateAdvisoryState(paths.StateDir); err != nil {
		return err
	}
	db, err := store.OpenExisting(ctx, paths.DatabaseFile)
	if err != nil {
		return fmt.Errorf("daily advisory requires a successful stored cycle: %w", err)
	}
	defer db.Close()
	now := time.Now().UTC()
	day := now.Format("2006-01-02")
	var scan core.Scan
	var entries []core.Entry
	err = db.Read(ctx, func(tx *store.Tx) error {
		scanID, err := tx.CompletedCycle(ctx, day)
		if err != nil {
			return err
		}
		scan, err = tx.Scan(ctx, scanID)
		if err != nil {
			return err
		}
		if scan.Status != core.ScanCompleted || scan.FinishedAt == nil || scan.FinishedAt.UTC().Format("2006-01-02") != day {
			return errors.New("cycle inventory is not completed today")
		}
		latest, err := tx.ListScans(ctx, 1)
		if err != nil {
			return err
		}
		if len(latest) != 1 || latest[0].ID != scanID || latest[0].Status != core.ScanCompleted {
			return errors.New("newer or failed inventory superseded the successful cycle; no outbound call")
		}
		entries, err = tx.Entries(ctx, scanID)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return errors.New("no successful inventory cycle today; no outbound call")
	}
	if err != nil {
		return err
	}

	r := advisoryReport{Day: day, ScanID: scan.ID, Status: "running", Reason: "in progress or interrupted",
		Advisor: jev.Report{Provider: jev.Provider, Model: policy.Jev.Model, Mode: jev.ModeRulesOnly}}
	for _, collector := range scan.Collectors {
		if collector.Status == core.CollectorFailed || collector.Status == core.CollectorPartial {
			r.Incomplete = true
		}
	}
	// Build rules only. Never store this plan or expose its action IDs: the
	// scheduled advisory must not create an executable apply path.
	target := safety.ResolveTarget(policy.Retention.QuarantineDir)
	built, err := plan.Build(ctx, plan.Input{ScanID: scan.ID, Entries: entries, Policy: policy,
		Safety: enginePolicy(paths, policy), Target: &target, Now: now})
	if err != nil {
		return err
	}
	byPath := make(map[string]core.Entry, len(entries))
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	// A partial global reference collector cannot prove any entry free of
	// unseen references. Per-entry filesystem/Git unknowns are filtered below;
	// unaffected entries can still receive review-only advice.
	globalUnknown := false
	for _, collector := range scan.Collectors {
		if collector.Status != core.CollectorFailed && collector.Status != core.CollectorPartial {
			continue
		}
		switch collector.Name {
		case collect.CollectorProcesses, collect.CollectorServices, collect.CollectorAgents:
			globalUnknown = true
		}
	}
	candidates := make([]core.Entry, 0)
	for i, trace := range built.Traces {
		if !trace.Ambiguous {
			continue
		}
		entry := byPath[trace.Path]
		unknown := globalUnknown || built.Verdicts[i].Refused() || entry.Protected()
		for _, evidence := range entry.Evidence {
			if strings.HasPrefix(evidence.Signal, "unknown:") {
				unknown = true
				break
			}
		}
		if unknown {
			r.SkippedUnknown++
			r.Incomplete = true
			continue
		}
		if len(candidates) == store.AdvisoryMaxEntries {
			r.SkippedBudget++
			r.Incomplete = true
			continue
		}
		candidates = append(candidates, entry)
	}
	r.Candidates = len(candidates)
	initial, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := db.Write(ctx, func(tx *store.Tx) error {
		return tx.ClaimAdvisory(ctx, day, scan.ID, string(initial), time.Now().UTC())
	}); err != nil {
		if errors.Is(err, store.ErrAdvisoryAlreadyRun) {
			return existingDailyAdvisory(ctx, e, db, day)
		}
		return err
	}
	finish := func(status, reason string) error {
		r.Status = status
		r.Reason = reason
		return db.Write(ctx, func(tx *store.Tx) error {
			var err error
			r.Budget, err = tx.AdvisoryBudget(ctx, day)
			if err != nil {
				return err
			}
			body, err := json.Marshal(r)
			if err != nil {
				return err
			}
			return tx.FinishAdvisory(ctx, day, scan.ID, status, string(body), time.Now().UTC())
		})
	}
	if len(candidates) == 0 {
		status, reason := "complete", "no eligible candidates; no outbound call"
		if r.Incomplete {
			status, reason = "incomplete", "safety evidence incomplete; no eligible candidates or outbound call"
		}
		if err := finish(status, reason); err != nil {
			return err
		}
		return writeAdvisorySummary(e, r)
	}

	key, err := readAdvisoryKey(keyFile)
	if err != nil {
		if finishErr := finish("blocked", "key missing or unsafe; no outbound call"); finishErr != nil {
			return finishErr
		}
		_ = writeAdvisorySummary(e, r)
		return errUnsafeAdvisoryKey
	}
	budgetRejected := false
	client := &jev.Client{Endpoint: policy.Jev.Endpoint, APIKey: key, HTTP: &http.Client{},
		Timeout: policy.Jev.Timeout.Duration(), MaxRetries: policy.Jev.MaxRetries, RequireUsage: true,
		MinInterval: policy.Jev.MinInterval.Duration(), BackoffBase: 500 * time.Millisecond,
		MaxBackoff: 10 * time.Second}
	client.BeforeAttempt = func(ctx context.Context, request jev.Request, body []byte) error {
		tokens := int64((len(body) + 2) / 3)
		cost := int64(math.Ceil(float64(tokens) * price)) // micro-USD, rounded up
		if tokens <= 0 || cost <= 0 || cost > store.AdvisoryMaxCostMicroUSD {
			budgetRejected = true
			return store.ErrAdvisoryBudget
		}
		err := db.Write(ctx, func(tx *store.Tx) error {
			return tx.ReserveAdvisoryAttempt(ctx, day, scan.ID, int64(len(request.State.Entries)), tokens, cost, time.Now().UTC())
		})
		if err != nil {
			budgetRejected = true
		}
		return err
	}
	advisor, err := jev.New(jev.Options{Policy: policy.Jev, PolicyDigest: plan.PolicyDigest(policy),
		ScanID: scan.ID, Redactor: jev.Redactor{Segments: policy.Jev.RedactSegments,
			SensitiveNames: policy.Protect.NamePatterns}, Client: client})
	if err != nil {
		if finishErr := finish("blocked", "advisor unavailable"); finishErr != nil {
			return finishErr
		}
		return err
	}
	answers, classifyErr := advisor.Classify(ctx, candidates)
	r.Advisor = advisor.Report()
	for _, entry := range candidates {
		if recommendation, ok := answers[entry.Path]; ok {
			r.Suggestions = append(r.Suggestions, advisorySuggestion{Path: entry.Path, Recommendation: recommendation})
		}
	}
	usageErr := persistAdvice(ctx, db, advisor)
	if classifyErr != nil || usageErr != nil || budgetRejected || r.Advisor.FailedRequests > 0 ||
		r.Advisor.Oversized > 0 || r.Advisor.CircuitOpen || len(answers) < len(candidates) {
		r.Incomplete = true
	}
	status, reason := "complete", "review-only advice; no mutation was authorized"
	if r.Incomplete {
		status, reason = "incomplete", "some entries or requests lack verified advice; review required"
	}
	if budgetRejected {
		reason = "daily budget exhausted or unavailable; no further outbound call"
	}
	if err := finish(status, reason); err != nil {
		return err
	}
	if err := writeAdvisorySummary(e, r); err != nil {
		return err
	}
	if classifyErr != nil {
		return classifyErr
	}
	if usageErr != nil {
		return usageErr
	}
	if budgetRejected {
		return store.ErrAdvisoryBudget
	}
	return nil
}

func writeAdvisorySummary(e *env, r advisoryReport) error {
	return json.NewEncoder(e.stdout).Encode(advisorySummary{Day: r.Day, ScanID: r.ScanID,
		Status: r.Status, Reason: r.Reason, Incomplete: r.Incomplete,
		Candidates: r.Candidates, SkippedUnknown: r.SkippedUnknown, Budget: r.Budget})
}

func existingDailyAdvisory(ctx context.Context, e *env, db *store.Store, day string) error {
	var record store.AdvisoryRecord
	if err := db.Read(ctx, func(tx *store.Tx) error {
		var err error
		record, err = tx.Advisory(ctx, day)
		return err
	}); err != nil {
		return err
	}
	var r advisoryReport
	if json.Unmarshal([]byte(record.Report), &r) != nil {
		return errors.New("stored advisory report is invalid; no outbound call")
	}
	if record.Status == "running" {
		r.Status, r.Reason, r.Incomplete = "incomplete", "earlier run still active or interrupted; no outbound call", true
	}
	if err := writeAdvisorySummary(e, r); err != nil {
		return err
	}
	if record.Status != "complete" {
		return errors.New("daily advisory already started; no outbound call")
	}
	return nil
}

func showDailyAdvisory(ctx context.Context, e *env, day string) error {
	if day == "" {
		day = time.Now().UTC().Format("2006-01-02")
	}
	parsed, err := time.Parse("2006-01-02", day)
	if err != nil || parsed.Format("2006-01-02") != day {
		return &usageError{msg: "--day must be YYYY-MM-DD"}
	}
	paths, err := e.resolvePaths()
	if err != nil {
		return err
	}
	db, err := store.OpenReadOnly(ctx, paths.DatabaseFile)
	if err != nil {
		return err
	}
	defer db.Close()
	var record store.AdvisoryRecord
	err = db.Read(ctx, func(tx *store.Tx) error {
		var err error
		record, err = tx.Advisory(ctx, day)
		return err
	})
	if err != nil {
		return err
	}
	var report advisoryReport
	if err := json.Unmarshal([]byte(record.Report), &report); err != nil {
		return errors.New("stored advisory report is invalid")
	}
	if record.Status == "running" {
		report.Status, report.Reason, report.Incomplete = "incomplete", "earlier run still active or interrupted", true
	}
	return json.NewEncoder(e.stdout).Encode(report)
}
