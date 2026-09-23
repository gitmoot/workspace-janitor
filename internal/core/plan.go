package core

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ActionKind is the typed decision the planner produces for an entry.
type ActionKind string

const (
	ActionKeep            ActionKind = "keep"
	ActionRelocate        ActionKind = "relocate"
	ActionQuarantine      ActionKind = "quarantine"
	ActionDeleteCandidate ActionKind = "delete_candidate"
	ActionInvestigate     ActionKind = "investigate"
)

var actionKinds = []ActionKind{ActionKeep, ActionRelocate, ActionQuarantine, ActionDeleteCandidate, ActionInvestigate}

// ActionKinds returns every valid action kind, in planner severity order.
func ActionKinds() []ActionKind { return copyEnum(actionKinds) }

// Valid reports whether k is a known action kind.
func (k ActionKind) Valid() bool { return validEnum(k, actionKinds) }

// ParseActionKind converts s into an ActionKind.
func ParseActionKind(s string) (ActionKind, error) { return parseEnum(s, actionKinds, "action kind") }

// Mutating reports whether applying the action changes the filesystem.
func (k ActionKind) Mutating() bool {
	switch k {
	case ActionRelocate, ActionQuarantine, ActionDeleteCandidate:
		return true
	default:
		return false
	}
}

// RecommendationOrigin records who proposed an action. A model origin is
// advisory only: the safety engine still decides.
type RecommendationOrigin string

const (
	OriginRules    RecommendationOrigin = "rules"
	OriginPolicy   RecommendationOrigin = "policy"
	OriginModel    RecommendationOrigin = "model"
	OriginFallback RecommendationOrigin = "fallback"
	OriginOperator RecommendationOrigin = "operator"
)

var recommendationOrigins = []RecommendationOrigin{OriginRules, OriginPolicy, OriginModel, OriginFallback, OriginOperator}

// Valid reports whether o is a known recommendation origin.
func (o RecommendationOrigin) Valid() bool { return validEnum(o, recommendationOrigins) }

// ParseRecommendationOrigin converts s into a RecommendationOrigin.
func ParseRecommendationOrigin(s string) (RecommendationOrigin, error) {
	return parseEnum(s, recommendationOrigins, "recommendation origin")
}

// Recommendation is a proposed action for an entry, with its reasons.
type Recommendation struct {
	Action     ActionKind           `json:"action"`
	Class      ArtifactClass        `json:"class"`
	Retention  Retention            `json:"retention"`
	Confidence float64              `json:"confidence"`
	Origin     RecommendationOrigin `json:"origin"`
	Reasons    []string             `json:"reasons,omitempty"`
	DecidedAt  time.Time            `json:"decided_at"`
}

// Validate reports every field-level problem with the recommendation.
func (r *Recommendation) Validate(field string) FieldErrors {
	var errs FieldErrors
	if !r.Action.Valid() {
		errs.Add(field+".action", "unknown action kind %q", string(r.Action))
	}
	if !r.Class.Valid() {
		errs.Add(field+".class", "unknown artifact class %q", string(r.Class))
	}
	if !r.Retention.Valid() {
		errs.Add(field+".retention", "unknown retention %q", string(r.Retention))
	}
	if !r.Origin.Valid() {
		errs.Add(field+".origin", "unknown recommendation origin %q", string(r.Origin))
	}
	if r.Confidence < 0 || r.Confidence > 1 {
		errs.Add(field+".confidence", "must be within [0,1], got %v", r.Confidence)
	}
	return errs
}

// ScanStatus is the lifecycle state of a scan run.
type ScanStatus string

const (
	ScanRunning   ScanStatus = "running"
	ScanCompleted ScanStatus = "completed"
	ScanFailed    ScanStatus = "failed"
)

var scanStatuses = []ScanStatus{ScanRunning, ScanCompleted, ScanFailed}

// Valid reports whether s is a known scan status.
func (s ScanStatus) Valid() bool { return validEnum(s, scanStatuses) }

// ParseScanStatus converts s into a ScanStatus.
func ParseScanStatus(s string) (ScanStatus, error) { return parseEnum(s, scanStatuses, "scan status") }

// Scan is one inventory collection run over a set of roots.
type Scan struct {
	ContractVersion int               `json:"contract_version"`
	ID              string            `json:"id"`
	Roots           []string          `json:"roots"`
	Status          ScanStatus        `json:"status"`
	StartedAt       time.Time         `json:"started_at"`
	FinishedAt      *time.Time        `json:"finished_at,omitempty"`
	EntryCount      int               `json:"entry_count"`
	Collectors      []CollectorReport `json:"collectors"`
	Error           string            `json:"error,omitempty"`
}

// CollectorStatus is the outcome of one collector during a scan.
type CollectorStatus string

const (
	// CollectorRan means the collector completed within its bounds.
	CollectorRan CollectorStatus = "ran"
	// CollectorPartial means the collector produced results but hit a bound
	// or could not observe part of its input. Everything it could not see is
	// recorded as unknown evidence, never as a clean result.
	CollectorPartial CollectorStatus = "partial"
	// CollectorFailed means the collector produced no usable result.
	CollectorFailed CollectorStatus = "failed"
	// CollectorSkipped means the collector was disabled or unavailable.
	CollectorSkipped CollectorStatus = "skipped"
)

var collectorStatuses = []CollectorStatus{CollectorRan, CollectorPartial, CollectorFailed, CollectorSkipped}

// Valid reports whether s is a known collector status.
func (s CollectorStatus) Valid() bool { return validEnum(s, collectorStatuses) }

// ParseCollectorStatus converts s into a CollectorStatus.
func ParseCollectorStatus(s string) (CollectorStatus, error) {
	return parseEnum(s, collectorStatuses, "collector status")
}

// CollectorReport records what one collector did during a scan, so a reader
// can tell a clean result from an unobserved one.
type CollectorReport struct {
	Name     string          `json:"name"`
	Status   CollectorStatus `json:"status"`
	Detail   string          `json:"detail,omitempty"`
	Visited  int             `json:"visited"`
	Recorded int             `json:"recorded"`
	Unknowns int             `json:"unknowns"`
}

// Validate reports every field-level problem with the report.
func (r CollectorReport) Validate(field string) FieldErrors {
	var errs FieldErrors
	if strings.TrimSpace(r.Name) == "" {
		errs.Add(field+".name", "must not be empty")
	}
	if !r.Status.Valid() {
		errs.Add(field+".status", "unknown collector status %q", string(r.Status))
	}
	for _, count := range []struct {
		name  string
		value int
	}{{"visited", r.Visited}, {"recorded", r.Recorded}, {"unknowns", r.Unknowns}} {
		if count.value < 0 {
			errs.Add(field+"."+count.name, "must not be negative, got %d", count.value)
		}
	}
	return errs
}

// Normalize fills the contract version and normalizes timestamps to UTC.
func (s *Scan) Normalize() {
	if s.ContractVersion == 0 {
		s.ContractVersion = ContractVersion
	}
	if s.Status == "" {
		s.Status = ScanRunning
	}
	s.StartedAt = s.StartedAt.UTC()
	if s.Collectors == nil {
		s.Collectors = []CollectorReport{}
	}
	// Reports render in a stable order so a scan document is byte-stable for
	// identical collection results.
	sort.SliceStable(s.Collectors, func(i, j int) bool { return s.Collectors[i].Name < s.Collectors[j].Name })
	if s.FinishedAt != nil {
		finished := s.FinishedAt.UTC()
		s.FinishedAt = &finished
	}
}

// Validate reports every field-level problem with the scan.
func (s *Scan) Validate() error {
	var errs FieldErrors
	if s.ContractVersion != ContractVersion {
		errs.Add("contract_version", "must be %d, got %d", ContractVersion, s.ContractVersion)
	}
	if strings.TrimSpace(s.ID) == "" {
		errs.Add("id", "must not be empty")
	}
	if len(s.Roots) == 0 {
		errs.Add("roots", "must contain at least one root")
	}
	for i, root := range s.Roots {
		if !isAbsClean(root) {
			errs.Add(fmt.Sprintf("roots[%d]", i), "must be an absolute, cleaned path, got %q", root)
		}
	}
	if !s.Status.Valid() {
		errs.Add("status", "unknown scan status %q", string(s.Status))
	}
	if s.StartedAt.IsZero() {
		errs.Add("started_at", "must be set")
	}
	if s.EntryCount < 0 {
		errs.Add("entry_count", "must not be negative, got %d", s.EntryCount)
	}
	seen := make(map[string]struct{}, len(s.Collectors))
	for i, report := range s.Collectors {
		field := fmt.Sprintf("collectors[%d]", i)
		errs = append(errs, report.Validate(field)...)
		if _, dup := seen[report.Name]; dup {
			errs.Add(field+".name", "duplicate collector report %q", report.Name)
		}
		seen[report.Name] = struct{}{}
	}
	return errs.ErrorOrNil()
}

// ActionStatus is the lifecycle state of a planned action.
type ActionStatus string

const (
	ActionPending  ActionStatus = "pending"
	ActionApplied  ActionStatus = "applied"
	ActionSkipped  ActionStatus = "skipped"
	ActionFailed   ActionStatus = "failed"
	ActionReverted ActionStatus = "reverted"
)

var actionStatuses = []ActionStatus{ActionPending, ActionApplied, ActionSkipped, ActionFailed, ActionReverted}

// Valid reports whether s is a known action status.
func (s ActionStatus) Valid() bool { return validEnum(s, actionStatuses) }

// ParseActionStatus converts s into an ActionStatus.
func ParseActionStatus(s string) (ActionStatus, error) {
	return parseEnum(s, actionStatuses, "action status")
}

// Action is one planned operation on one path.
type Action struct {
	ID           string        `json:"id"`
	PlanID       string        `json:"plan_id"`
	Path         string        `json:"path"`
	Kind         ActionKind    `json:"kind"`
	Class        ArtifactClass `json:"class"`
	Retention    Retention     `json:"retention"`
	Confidence   float64       `json:"confidence"`
	Status       ActionStatus  `json:"status"`
	Destination  string        `json:"destination,omitempty"`
	FilesystemID FilesystemID  `json:"filesystem_id"`
	// Fingerprint is the entry fingerprint this action was planned
	// against. Apply revalidates it before mutating anything.
	Fingerprint string   `json:"fingerprint,omitempty"`
	Reasons     []string `json:"reasons,omitempty"`
	// Rules names every deterministic rule that contributed, in
	// precedence order, so a recommendation can be traced to its source.
	Rules []string `json:"rules,omitempty"`
	// Rejected records the alternatives that lost, and why. Without it an
	// explanation can only justify the winner, not the choice.
	Rejected  []RejectedAction `json:"rejected,omitempty"`
	Guards    []string         `json:"guards,omitempty"`
	CreatedAt time.Time        `json:"created_at"`
	AppliedAt *time.Time       `json:"applied_at,omitempty"`
}

// RejectedAction is an alternative the planner considered and did not take.
type RejectedAction struct {
	Kind   ActionKind `json:"kind"`
	Rule   string     `json:"rule"`
	Reason string     `json:"reason"`
	// Conflict marks a genuine disagreement between rules of the same
	// precedence, as opposed to an opinion a higher-precedence tier simply
	// pre-empted. Only the former is worth an operator's attention.
	Conflict bool `json:"conflict,omitempty"`
}

// Normalize applies defaults and normalizes timestamps to UTC.
func (a *Action) Normalize() {
	if a.Status == "" {
		a.Status = ActionPending
	}
	if a.Retention == "" {
		a.Retention = RetentionNone
	}
	if a.Class == "" {
		a.Class = ClassUnknown
	}
	a.CreatedAt = a.CreatedAt.UTC()
	if a.AppliedAt != nil {
		applied := a.AppliedAt.UTC()
		a.AppliedAt = &applied
	}
}

// Validate reports every field-level problem with the action.
func (a *Action) Validate(field string) FieldErrors {
	var errs FieldErrors
	if strings.TrimSpace(a.ID) == "" {
		errs.Add(field+".id", "must not be empty")
	}
	if !isAbsClean(a.Path) {
		errs.Add(field+".path", "must be an absolute, cleaned path, got %q", a.Path)
	}
	if !a.Kind.Valid() {
		errs.Add(field+".kind", "unknown action kind %q", string(a.Kind))
	}
	if !a.Retention.Valid() {
		errs.Add(field+".retention", "unknown retention %q", string(a.Retention))
	}
	if !a.Status.Valid() {
		errs.Add(field+".status", "unknown action status %q", string(a.Status))
	}
	if a.Confidence < 0 || a.Confidence > 1 {
		errs.Add(field+".confidence", "must be within [0,1], got %v", a.Confidence)
	}
	if a.Kind == ActionRelocate && !isAbsClean(a.Destination) {
		errs.Add(field+".destination", "relocate requires an absolute destination, got %q", a.Destination)
	}
	if a.CreatedAt.IsZero() {
		errs.Add(field+".created_at", "must be set")
	}
	return errs
}

// PlanStatus is the lifecycle state of a plan.
type PlanStatus string

const (
	PlanDraft         PlanStatus = "draft"
	PlanReady         PlanStatus = "ready"
	PlanApplied       PlanStatus = "applied"
	PlanPartial       PlanStatus = "partially_applied"
	PlanSupersededOld PlanStatus = "superseded"
)

var planStatuses = []PlanStatus{PlanDraft, PlanReady, PlanApplied, PlanPartial, PlanSupersededOld}

// Valid reports whether s is a known plan status.
func (s PlanStatus) Valid() bool { return validEnum(s, planStatuses) }

// ParsePlanStatus converts s into a PlanStatus.
func ParsePlanStatus(s string) (PlanStatus, error) { return parseEnum(s, planStatuses, "plan status") }

// Plan is an ordered, reviewable set of actions derived from one scan.
type Plan struct {
	ContractVersion int        `json:"contract_version"`
	ID              string     `json:"id"`
	ScanID          string     `json:"scan_id"`
	Status          PlanStatus `json:"status"`
	CreatedAt       time.Time  `json:"created_at"`
	// EvidenceDigest binds the plan to the exact inventory it was built
	// from. Applying against a scan whose evidence has changed is refused:
	// the plan describes paths that no longer look the way it assumed.
	EvidenceDigest string `json:"evidence_digest"`
	// PolicyDigest binds the plan to the policy that produced it, so a
	// changed rule set is visible rather than silently applied.
	PolicyDigest string `json:"policy_digest"`
	// Advisor names what, beyond the deterministic rules, contributed:
	// "rules-only", or a provider and model. It is part of the plan's
	// identity, because the same scan and policy planned with and without
	// a model are different plans.
	Advisor string   `json:"advisor"`
	Actions []Action `json:"actions"`
}

// Normalize applies defaults, stamps the plan id on every action, and sorts
// actions by path so a plan document is byte-stable for identical input.
func (p *Plan) Normalize() {
	if p.ContractVersion == 0 {
		p.ContractVersion = ContractVersion
	}
	if p.Status == "" {
		p.Status = PlanDraft
	}
	if p.Advisor == "" {
		p.Advisor = "rules-only"
	}
	p.CreatedAt = p.CreatedAt.UTC()
	for i := range p.Actions {
		p.Actions[i].PlanID = p.ID
		p.Actions[i].Normalize()
	}
	sort.SliceStable(p.Actions, func(i, j int) bool {
		if p.Actions[i].Path != p.Actions[j].Path {
			return p.Actions[i].Path < p.Actions[j].Path
		}
		return p.Actions[i].ID < p.Actions[j].ID
	})
}

// Validate reports every field-level problem with the plan and its actions.
func (p *Plan) Validate() error {
	var errs FieldErrors
	if p.ContractVersion != ContractVersion {
		errs.Add("contract_version", "must be %d, got %d", ContractVersion, p.ContractVersion)
	}
	if strings.TrimSpace(p.ID) == "" {
		errs.Add("id", "must not be empty")
	}
	if strings.TrimSpace(p.ScanID) == "" {
		errs.Add("scan_id", "must not be empty")
	}
	if !p.Status.Valid() {
		errs.Add("status", "unknown plan status %q", string(p.Status))
	}
	if p.CreatedAt.IsZero() {
		errs.Add("created_at", "must be set")
	}
	seen := make(map[string]struct{}, len(p.Actions))
	for i := range p.Actions {
		field := fmt.Sprintf("actions[%d]", i)
		errs = append(errs, p.Actions[i].Validate(field)...)
		if _, dup := seen[p.Actions[i].ID]; dup {
			errs.Add(field+".id", "duplicate action id %q", p.Actions[i].ID)
		}
		seen[p.Actions[i].ID] = struct{}{}
		if p.Actions[i].PlanID != p.ID {
			errs.Add(field+".plan_id", "must be %q, got %q", p.ID, p.Actions[i].PlanID)
		}
	}
	return errs.ErrorOrNil()
}

// KindCount is one row of a plan summary.
type KindCount struct {
	Kind  ActionKind `json:"kind"`
	Count int        `json:"count"`
}

// PlanSummary is the deterministic count of actions by kind. It uses a sorted
// slice rather than a map so JSON output and terminal output agree exactly.
type PlanSummary struct {
	PlanID  string      `json:"plan_id"`
	Total   int         `json:"total"`
	ByKind  []KindCount `json:"by_kind"`
	Mutates int         `json:"mutating"`
}

// Summary computes the plan summary. Every action kind appears exactly once,
// in ActionKinds order, including kinds with a zero count.
func (p *Plan) Summary() PlanSummary {
	counts := make(map[ActionKind]int, len(actionKinds))
	mutating := 0
	for _, a := range p.Actions {
		counts[a.Kind]++
		if a.Kind.Mutating() {
			mutating++
		}
	}
	byKind := make([]KindCount, 0, len(actionKinds))
	for _, kind := range actionKinds {
		byKind = append(byKind, KindCount{Kind: kind, Count: counts[kind]})
	}
	return PlanSummary{PlanID: p.ID, Total: len(p.Actions), ByKind: byKind, Mutates: mutating}
}

// ModelUsage records one billed model interaction. Usage is persisted even
// when the answer is discarded, so cost is always attributable.
type ModelUsage struct {
	ID               string    `json:"id"`
	ScanID           string    `json:"scan_id,omitempty"`
	Provider         string    `json:"provider"`
	Model            string    `json:"model"`
	RequestKind      string    `json:"request_kind"`
	PromptTokens     int64     `json:"prompt_tokens"`
	CompletionTokens int64     `json:"completion_tokens"`
	EstimatedCostUSD float64   `json:"estimated_cost_usd"`
	CreatedAt        time.Time `json:"created_at"`
}

// Normalize normalizes the timestamp to UTC.
func (u *ModelUsage) Normalize() { u.CreatedAt = u.CreatedAt.UTC() }

// Validate reports every field-level problem with the usage record.
func (u *ModelUsage) Validate() error {
	var errs FieldErrors
	if strings.TrimSpace(u.ID) == "" {
		errs.Add("id", "must not be empty")
	}
	if strings.TrimSpace(u.Provider) == "" {
		errs.Add("provider", "must not be empty")
	}
	if strings.TrimSpace(u.Model) == "" {
		errs.Add("model", "must not be empty")
	}
	if u.PromptTokens < 0 {
		errs.Add("prompt_tokens", "must not be negative, got %d", u.PromptTokens)
	}
	if u.CompletionTokens < 0 {
		errs.Add("completion_tokens", "must not be negative, got %d", u.CompletionTokens)
	}
	if u.EstimatedCostUSD < 0 {
		errs.Add("estimated_cost_usd", "must not be negative, got %v", u.EstimatedCostUSD)
	}
	if u.CreatedAt.IsZero() {
		errs.Add("created_at", "must be set")
	}
	return errs.ErrorOrNil()
}

// riskRank orders action kinds from least to most destructive. Conflict
// resolution always takes the lower rank, so a disagreement between rules
// can only ever move a decision toward caution.
var riskRank = map[ActionKind]int{
	ActionKeep:            0,
	ActionInvestigate:     1,
	ActionRelocate:        2,
	ActionQuarantine:      3,
	ActionDeleteCandidate: 4,
}

// RiskRank returns the relative risk of an action kind. A higher rank means
// a less recoverable outcome.
func (k ActionKind) RiskRank() int {
	if rank, ok := riskRank[k]; ok {
		return rank
	}
	// An unrecognised kind is treated as the most dangerous thing it could
	// be, so an unmapped addition cannot win a conflict by default.
	return len(riskRank)
}

// Safer returns whichever kind is less destructive. Ties keep the receiver.
func (k ActionKind) Safer(other ActionKind) ActionKind {
	if other.RiskRank() < k.RiskRank() {
		return other
	}
	return k
}

// Approval records a human decision to allow one action of a plan.
//
// Approvals live beside the plan rather than inside it: a plan is immutable
// once written, and approving must not require editing its internals.
type Approval struct {
	PlanID     string    `json:"plan_id"`
	ActionID   string    `json:"action_id"`
	Approver   string    `json:"approver"`
	ApprovedAt time.Time `json:"approved_at"`
	Note       string    `json:"note,omitempty"`
}

// Normalize applies defaults and normalizes the timestamp to UTC.
func (a *Approval) Normalize() {
	if a.Approver == "" {
		a.Approver = "operator"
	}
	a.ApprovedAt = a.ApprovedAt.UTC()
}

// Validate reports every field-level problem with the approval.
func (a *Approval) Validate() error {
	var errs FieldErrors
	if strings.TrimSpace(a.PlanID) == "" {
		errs.Add("plan_id", "must not be empty")
	}
	if strings.TrimSpace(a.ActionID) == "" {
		errs.Add("action_id", "must not be empty")
	}
	if strings.TrimSpace(a.Approver) == "" {
		errs.Add("approver", "must not be empty")
	}
	if a.ApprovedAt.IsZero() {
		errs.Add("approved_at", "must be set")
	}
	return errs.ErrorOrNil()
}
