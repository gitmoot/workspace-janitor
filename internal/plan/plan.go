package plan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/safety"
)

// Advisor is an optional classifier for entries the deterministic rules
// could not decide.
//
// It is consulted after every rule has run, only for ambiguous entries, and
// its answer is clamped: it may make a decision safer, never riskier, and
// it can never clear a protection. A model is an input to planning, not an
// authority over it.
type Advisor interface {
	Name() string
	Classify(ctx context.Context, entries []core.Entry) (map[string]core.Recommendation, error)
}

// Input is one planning run.
type Input struct {
	ScanID  string
	Entries []core.Entry
	Policy  config.Policy
	Safety  safety.Policy
	Jobs    []safety.JobRef
	Target  *safety.Target
	Now     time.Time
	// Advisor is optional. Nil means rules-only, which must remain fully
	// useful: the tool works with no model and no network.
	Advisor Advisor
}

// Result is a plan plus the per-entry traces behind it.
type Result struct {
	Plan     core.Plan
	Verdicts []core.Verdict
	Traces   []Trace
}

// Trace explains one entry's outcome.
type Trace struct {
	Path        string                `json:"path"`
	Class       core.ArtifactClass    `json:"class"`
	Action      core.ActionKind       `json:"action"`
	Rules       []string              `json:"rules"`
	Reasons     []string              `json:"reasons"`
	Rejected    []core.RejectedAction `json:"rejected,omitempty"`
	Ambiguous   bool                  `json:"ambiguous"`
	AdvisedBy   string                `json:"advised_by,omitempty"`
	Fingerprint string                `json:"fingerprint,omitempty"`
}

// ErrBindingMismatch reports a plan used against evidence it was not built
// from.
var ErrBindingMismatch = errors.New("plan: binding mismatch")

// Build produces a plan from an inventory.
//
// Deterministic rules run over every entry first. Only then, and only for
// the entries they left ambiguous, is an advisor consulted; its answers are
// clamped by the safety verdict and can only lower risk.
func Build(ctx context.Context, in Input) (Result, error) {
	if in.ScanID == "" {
		return Result{}, errors.New("plan: a plan must be bound to a scan")
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	entries := append([]core.Entry(nil), in.Entries...)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	result := Result{
		Verdicts: make([]core.Verdict, 0, len(entries)),
		Traces:   make([]Trace, 0, len(entries)),
	}
	decisions := make([]Decision, len(entries))
	verdicts := make([]core.Verdict, len(entries))
	ambiguous := make([]core.Entry, 0, len(entries))

	// Phase one: deterministic rules, for every entry, with no model in
	// the loop at all.
	for i, entry := range entries {
		verdicts[i] = safety.Evaluate(safety.Input{
			Entry:  entry,
			Policy: in.Safety,
			Jobs:   in.Jobs,
			Target: in.Target,
			Now:    now,
		})
		decisions[i] = Evaluate(entry, in.Policy, verdicts[i])
		if decisions[i].Ambiguous {
			ambiguous = append(ambiguous, entry)
		}
	}

	// Phase two: the advisor, for the ambiguous tail only.
	advice := map[string]core.Recommendation{}
	advisorName := ""
	if in.Advisor != nil && len(ambiguous) > 0 {
		advisorName = in.Advisor.Name()
		answers, err := in.Advisor.Classify(ctx, ambiguous)
		if err != nil {
			// A failed advisor changes nothing: the rules already decided.
			advice = map[string]core.Recommendation{}
		} else {
			advice = answers
		}
	}

	plan := core.Plan{
		ID:             "",
		ScanID:         in.ScanID,
		Status:         core.PlanDraft,
		CreatedAt:      now,
		EvidenceDigest: EvidenceDigest(entries),
		PolicyDigest:   PolicyDigest(in.Policy),
		Actions:        make([]core.Action, 0, len(entries)),
	}
	plan.ID = PlanID(in.ScanID, plan.EvidenceDigest, plan.PolicyDigest)

	for i, entry := range entries {
		decision := decisions[i]
		trace := Trace{
			Path:        entry.Path,
			Class:       decision.Class,
			Rules:       decision.Rules,
			Reasons:     decision.Reasons,
			Rejected:    decision.Rejected,
			Ambiguous:   decision.Ambiguous,
			Fingerprint: entry.Fingerprint,
		}
		if recommendation, ok := advice[entry.Path]; ok && decision.Ambiguous {
			decision, trace = applyAdvice(decision, trace, recommendation, verdicts[i], advisorName)
		}
		trace.Action = decision.Kind

		action := core.Action{
			ID:           ActionID(plan.ID, entry.Path),
			PlanID:       plan.ID,
			Path:         entry.Path,
			Kind:         decision.Kind,
			Class:        decision.Class,
			Retention:    decision.Retention,
			Confidence:   confidenceFor(decision),
			Destination:  decision.Destination,
			FilesystemID: entry.FilesystemID,
			Fingerprint:  entry.Fingerprint,
			Reasons:      decision.Reasons,
			Rules:        decision.Rules,
			Rejected:     decision.Rejected,
			Guards:       verdicts[i].Guards,
			CreatedAt:    now,
		}
		plan.Actions = append(plan.Actions, action)
		result.Verdicts = append(result.Verdicts, verdicts[i])
		result.Traces = append(result.Traces, trace)
	}

	plan.Normalize()
	if err := plan.Validate(); err != nil {
		return Result{}, fmt.Errorf("plan: built an invalid plan: %w", err)
	}
	result.Plan = plan
	return result, nil
}

// applyAdvice folds an advisor answer into a decision, clamped.
//
// The answer is first passed through the safety engine, which downgrades
// anything a protection forbids. It is then accepted only if it is safer
// than what the rules decided: an advisor can move a path toward caution,
// never away from it.
func applyAdvice(
	decision Decision,
	trace Trace,
	recommendation core.Recommendation,
	verdict core.Verdict,
	advisor string,
) (Decision, Trace) {
	clamped := safety.ClampRecommendation(verdict, recommendation)
	trace.AdvisedBy = advisor

	if clamped.Action.RiskRank() >= decision.Kind.RiskRank() {
		trace.Rejected = append(trace.Rejected, core.RejectedAction{
			Kind: clamped.Action,
			Rule: "advisor:" + advisor,
			Reason: fmt.Sprintf("the advisor proposed %s, which is not safer than the rules' %s",
				clamped.Action, decision.Kind),
		})
		decision.Rejected = trace.Rejected
		return decision, trace
	}

	trace.Rejected = append(trace.Rejected, core.RejectedAction{
		Kind:   decision.Kind,
		Rule:   "builtin.unknown",
		Reason: fmt.Sprintf("the advisor proposed the safer %s", clamped.Action),
	})
	decision.Kind = clamped.Action
	decision.Retention = clamped.Retention
	decision.Class = clamped.Class
	decision.Rules = append(decision.Rules, "advisor:"+advisor)
	decision.Reasons = append(decision.Reasons, clamped.Reasons...)
	decision.Rejected = trace.Rejected
	trace.Rules = decision.Rules
	trace.Reasons = decision.Reasons
	return decision, trace
}

// confidenceFor reports how firm a decision is. A conflict or an ambiguous
// classification is less certain than an unopposed rule.
func confidenceFor(decision Decision) float64 {
	switch {
	case decision.Ambiguous:
		return 0.3
	case len(decision.Conflicts) > 0:
		return 0.6
	default:
		return 0.9
	}
}

// EvidenceDigest hashes the fingerprints of an inventory.
//
// It is what binds a plan to the evidence it was built from: if any entry
// changed, appeared, or vanished, the digest changes and the plan no longer
// applies.
func EvidenceDigest(entries []core.Entry) string {
	paths := make([]string, 0, len(entries))
	fingerprints := make(map[string]string, len(entries))
	for _, entry := range entries {
		paths = append(paths, entry.Path)
		fingerprints[entry.Path] = entry.Fingerprint
	}
	sort.Strings(paths)

	h := sha256.New()
	for _, path := range paths {
		fmt.Fprintf(h, "%s\x00%s\x00", path, fingerprints[path])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// PolicyDigest hashes the parts of a policy that change planning outcomes.
func PolicyDigest(policy config.Policy) string {
	// The effective policy is marshalled in full: any field that can move
	// a decision is part of it, and hashing the whole document means a new
	// field cannot be forgotten here.
	encoded, err := core.MarshalJSON(policy)
	if err != nil {
		// Marshalling a validated policy cannot fail; if it somehow did, a
		// digest that never matches is safer than one that always does.
		return "unavailable"
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// PlanID derives a stable identifier from what the plan is bound to. The
// same scan, evidence, and policy always produce the same plan id.
func PlanID(scanID, evidenceDigest, policyDigest string) string {
	sum := sha256.Sum256([]byte(scanID + "\x00" + evidenceDigest + "\x00" + policyDigest))
	return fmt.Sprintf("plan-%s-%s", scanID, hex.EncodeToString(sum[:])[:12])
}

// ActionID derives a stable identifier for one action of a plan.
func ActionID(planID, path string) string {
	sum := sha256.Sum256([]byte(planID + "\x00" + path))
	return "action-" + hex.EncodeToString(sum[:])[:16]
}

// VerifyBinding checks that a plan still describes the evidence it was
// built from.
//
// A plan is a set of statements about specific objects at a specific
// moment. Applying it against a different scan, or against entries that
// have changed since, would act on things nobody reviewed.
func VerifyBinding(plan core.Plan, scanID string, entries []core.Entry, policy config.Policy) error {
	if plan.ScanID != scanID {
		return fmt.Errorf("%w: plan %s was built from scan %s, not %s",
			ErrBindingMismatch, plan.ID, plan.ScanID, scanID)
	}
	if digest := EvidenceDigest(entries); digest != plan.EvidenceDigest {
		return fmt.Errorf("%w: the inventory changed since plan %s was built (evidence %s, now %s)",
			ErrBindingMismatch, plan.ID, short(plan.EvidenceDigest), short(digest))
	}
	if digest := PolicyDigest(policy); digest != plan.PolicyDigest {
		return fmt.Errorf("%w: the policy changed since plan %s was built (policy %s, now %s)",
			ErrBindingMismatch, plan.ID, short(plan.PolicyDigest), short(digest))
	}
	return nil
}

func short(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	if digest == "" {
		return "unknown"
	}
	return digest
}
