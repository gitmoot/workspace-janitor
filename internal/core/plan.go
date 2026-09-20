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
	ContractVersion int        `json:"contract_version"`
	ID              string     `json:"id"`
	Roots           []string   `json:"roots"`
	Status          ScanStatus `json:"status"`
	StartedAt       time.Time  `json:"started_at"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	EntryCount      int        `json:"entry_count"`
	Error           string     `json:"error,omitempty"`
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
	ID           string       `json:"id"`
	PlanID       string       `json:"plan_id"`
	Path         string       `json:"path"`
	Kind         ActionKind   `json:"kind"`
	Retention    Retention    `json:"retention"`
	Confidence   float64      `json:"confidence"`
	Status       ActionStatus `json:"status"`
	Destination  string       `json:"destination,omitempty"`
	FilesystemID FilesystemID `json:"filesystem_id"`
	Reasons      []string     `json:"reasons,omitempty"`
	Guards       []string     `json:"guards,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
	AppliedAt    *time.Time   `json:"applied_at,omitempty"`
}

// Normalize applies defaults and normalizes timestamps to UTC.
func (a *Action) Normalize() {
	if a.Status == "" {
		a.Status = ActionPending
	}
	if a.Retention == "" {
		a.Retention = RetentionNone
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
	Actions         []Action   `json:"actions"`
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
