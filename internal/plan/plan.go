package plan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
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

// RulesOnly is the advisor identity of a plan no model contributed to.
const RulesOnly = "rules-only"

// AdvisorKey returns the identity of the advisor that will shape a plan.
func (in Input) AdvisorKey() string {
	if in.Advisor == nil {
		return RulesOnly
	}
	return in.Advisor.Name()
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
			// Only finite confidence in [0,1] can become action
			// confidence. Invalid advisor confidence must not abort a
			// rules-only plan; the positive comparisons also reject NaN.
			for _, entry := range ambiguous {
				recommendation, ok := answers[entry.Path]
				if !ok || !(recommendation.Confidence >= 0 && recommendation.Confidence <= 1) {
					continue
				}
				advice[entry.Path] = recommendation
			}
		}
	}

	plan := core.Plan{
		ID:             "",
		ScanID:         in.ScanID,
		Status:         core.PlanDraft,
		CreatedAt:      now,
		EvidenceDigest: EvidenceDigest(entries),
		PolicyDigest:   PolicyDigest(in.Policy),
		Advisor:        in.AdvisorKey(),
		Actions:        make([]core.Action, 0, len(entries)),
	}
	plan.ID = PlanID(in.ScanID, plan.EvidenceDigest, plan.PolicyDigest, plan.Advisor, adviceDigest(entries, decisions, advice))

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
		confidence := confidenceFor(decision)
		if recommendation, ok := advice[entry.Path]; ok && decision.Ambiguous {
			before := decision.Kind
			decision, trace = applyAdvice(decision, trace, recommendation, verdicts[i], advisorName)
			// Only a genuinely accepted model action carries model
			// confidence. A safety-clamped or agreeing answer keeps the
			// rules' conservative confidence.
			if decision.Kind != before && decision.Kind == recommendation.Action {
				confidence = recommendation.Confidence
			}
		}
		trace.Action = decision.Kind

		action := core.Action{
			ID:           ActionID(plan.ID, entry.Path),
			PlanID:       plan.ID,
			Path:         entry.Path,
			Kind:         decision.Kind,
			Class:        decision.Class,
			Retention:    decision.Retention,
			Confidence:   confidence,
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

	occupied := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		occupied[entry.Path] = struct{}{}
	}
	resolveDestinationCollisions(&plan, result.Traces, occupied)

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
	rule := "advisor:" + advisor

	if clamped.Action == decision.Kind {
		// The advisor agrees with the rules. Credit it with its reason —
		// for example "confidence below threshold" — so the trace says why
		// the entry stayed where it was, and take its class label when it
		// has one: a label changes no action.
		decision.Rules = append(decision.Rules, rule)
		decision.Reasons = append(decision.Reasons, joinReasons(clamped.Reasons))
		if clamped.Class.Valid() && clamped.Class != core.ClassUnknown {
			decision.Class = clamped.Class
			trace.Class = clamped.Class
		}
		trace.Rules = decision.Rules
		trace.Reasons = decision.Reasons
		return decision, trace
	}

	if clamped.Action.RiskRank() >= decision.Kind.RiskRank() {
		trace.Rejected = append(trace.Rejected, core.RejectedAction{
			Kind: clamped.Action,
			Rule: rule,
			Reason: fmt.Sprintf("the advisor proposed %s, which is not safer than the rules' %s: %s",
				clamped.Action, decision.Kind, joinReasons(clamped.Reasons)),
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
	trace.Class = decision.Class
	decision.Rules = append(decision.Rules, "advisor:"+advisor)
	// One reason per rule: an explanation pairs them by index, so an
	// advisor with several reasons contributes one joined entry.
	decision.Reasons = append(decision.Reasons, joinReasons(clamped.Reasons))
	decision.Rejected = trace.Rejected
	trace.Rules = decision.Rules
	trace.Reasons = decision.Reasons
	return decision, trace
}

// joinReasons collapses several reasons into the single entry that pairs
// with one rule.
func joinReasons(reasons []string) string {
	switch len(reasons) {
	case 0:
		return "the advisor gave no reason"
	case 1:
		return reasons[0]
	default:
		return strings.Join(reasons, "; ")
	}
}

// Confidence levels. A decision reached over a disagreement, or with no
// classification at all, is less certain than an unopposed rule.
const (
	ambiguousConfidence = 0.3
	conflictConfidence  = 0.6
	settledConfidence   = 0.9
)

// confidenceFor reports how firm a decision is.
func confidenceFor(decision Decision) float64 {
	switch {
	case decision.Ambiguous:
		return ambiguousConfidence
	case len(decision.Conflicts) > 0:
		return conflictConfidence
	default:
		return settledConfidence
	}
}

// resolveDestinationCollisions downgrades relocations whose destination is
// not free.
//
// A destination collides in two ways: two projects with the same base name
// both want canonical/<name>, or the destination is already occupied by
// something the scan observed. Either way the relocation cannot be applied
// as written, so it is downgraded to investigate and the collision is
// reported rather than left for apply to discover.
//
// The occupancy check sees what the inventory saw. A destination outside
// every scanned root is unknown to the planner, and apply revalidates the
// destination before mutating regardless.
func resolveDestinationCollisions(built *core.Plan, traces []Trace, occupied map[string]struct{}) {
	byDestination := map[string][]int{}
	for i, action := range built.Actions {
		if action.Kind != core.ActionRelocate || action.Destination == "" {
			continue
		}
		byDestination[action.Destination] = append(byDestination[action.Destination], i)
	}

	traceIndex := map[string]int{}
	for i, trace := range traces {
		traceIndex[trace.Path] = i
	}

	destinations := make([]string, 0, len(byDestination))
	for destination := range byDestination {
		destinations = append(destinations, destination)
	}
	sort.Strings(destinations)

	for _, destination := range destinations {
		indexes := byDestination[destination]
		_, taken := occupied[destination]
		if len(indexes) < 2 && !taken {
			continue
		}
		others := make([]string, 0, len(indexes))
		for _, i := range indexes {
			others = append(others, built.Actions[i].Path)
		}
		for _, i := range indexes {
			action := &built.Actions[i]
			var reason string
			switch {
			case taken && len(indexes) > 1:
				reason = fmt.Sprintf("%s already exists, and %s is also proposed for it",
					destination, strings.Join(without(others, action.Path), ", "))
			case taken:
				reason = fmt.Sprintf("%s already exists, so relocating there would collide with it", destination)
			default:
				reason = fmt.Sprintf("%s is also proposed for %s, so relocating either would collide",
					strings.Join(without(others, action.Path), ", "), destination)
			}
			action.Rejected = append(action.Rejected, core.RejectedAction{
				Kind:     core.ActionRelocate,
				Rule:     "policy.canonical_root",
				Reason:   reason,
				Conflict: true,
			})
			action.Kind = core.ActionInvestigate
			action.Destination = ""
			action.Retention = core.RetentionNone
			// The decision is now a conflict resolution, not an unopposed
			// rule, and the confidence has to say so.
			action.Confidence = conflictConfidence
			action.Rules = append(action.Rules, "plan.destination_collision")
			action.Reasons = append(action.Reasons, reason)
			if t, ok := traceIndex[action.Path]; ok {
				traces[t].Action = core.ActionInvestigate
				traces[t].Rules = action.Rules
				traces[t].Reasons = action.Reasons
				traces[t].Rejected = action.Rejected
			}
		}
	}
}

func without(values []string, exclude string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != exclude {
			out = append(out, value)
		}
	}
	return out
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
// same scan, evidence, policy, advisor, and applied advice always produce
// the same plan id.
func PlanID(scanID, evidenceDigest, policyDigest, advisor, adviceDigest string) string {
	sum := sha256.Sum256([]byte(scanID + "\x00" + evidenceDigest + "\x00" + policyDigest + "\x00" + advisor + "\x00" + adviceDigest))
	return fmt.Sprintf("plan-%s-%s", scanID, hex.EncodeToString(sum[:])[:12])
}

// adviceDigest identifies the advice a plan applied. It is part of the
// plan id because the same inputs can yield different advice: a request
// that failed once and succeeds later must produce a new plan, not be
// answered with the stored plan the failure shaped. Rules-only plans
// apply no advice and digest to "".
func adviceDigest(entries []core.Entry, decisions []Decision, advice map[string]core.Recommendation) string {
	h := sha256.New()
	applied := false
	for i, entry := range entries {
		recommendation, ok := advice[entry.Path]
		if !ok || !decisions[i].Ambiguous {
			continue
		}
		applied = true
		// The decision time is left out: a cached answer and the fresh one
		// it was cached from are the same advice.
		fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%g\x00%s\x00", entry.Path, recommendation.Action,
			recommendation.Class, recommendation.Retention, recommendation.Confidence,
			strings.Join(recommendation.Reasons, "\x01"))
	}
	if !applied {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
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
