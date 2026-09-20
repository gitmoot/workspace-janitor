package core

import (
	"sort"
	"strings"
	"time"
)

// SafetyDecision is the typed outcome of a safety evaluation.
type SafetyDecision string

const (
	// DecisionAllow means no protection blocks a mutating action. It is
	// permission to plan one, never permission to skip revalidation.
	DecisionAllow SafetyDecision = "allow"
	// DecisionRefuse means at least one blocking protection applies. No
	// model answer, policy setting, or confidence score overrides it.
	DecisionRefuse SafetyDecision = "refuse"
)

var safetyDecisions = []SafetyDecision{DecisionAllow, DecisionRefuse}

// Valid reports whether d is a known safety decision.
func (d SafetyDecision) Valid() bool { return validEnum(d, safetyDecisions) }

// ParseSafetyDecision converts s into a SafetyDecision.
func ParseSafetyDecision(s string) (SafetyDecision, error) {
	return parseEnum(s, safetyDecisions, "safety decision")
}

// Verdict is the safety engine's typed answer for one path.
//
// It is the only authority on whether a path may be mutated. A verdict is
// derived from evidence alone: identical evidence always produces an
// identical verdict, including the order of its protections.
type Verdict struct {
	ContractVersion int            `json:"contract_version"`
	Path            string         `json:"path"`
	Decision        SafetyDecision `json:"decision"`
	// Protections are every blocking reason, ordered by kind then reason.
	Protections []Protection `json:"protections"`
	// Guards names the checks that ran, so a verdict cannot be mistaken for
	// "nothing was checked".
	Guards      []string  `json:"guards"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

// Normalize applies defaults and orders protections and guards so identical
// evidence yields byte-identical output.
func (v *Verdict) Normalize() {
	if v.ContractVersion == 0 {
		v.ContractVersion = ContractVersion
	}
	if v.Protections == nil {
		v.Protections = []Protection{}
	}
	if v.Guards == nil {
		v.Guards = []string{}
	}
	sort.SliceStable(v.Protections, func(i, j int) bool {
		if v.Protections[i].Kind != v.Protections[j].Kind {
			return v.Protections[i].Kind < v.Protections[j].Kind
		}
		return v.Protections[i].Reason < v.Protections[j].Reason
	})
	sort.Strings(v.Guards)
	v.EvaluatedAt = v.EvaluatedAt.UTC()
	v.Decision = DecisionAllow
	for _, protection := range v.Protections {
		if protection.Blocking {
			v.Decision = DecisionRefuse
			break
		}
	}
}

// Refused reports whether any blocking protection applies.
func (v *Verdict) Refused() bool { return v.Decision == DecisionRefuse }

// Allows reports whether the action kind may be performed on this path.
//
// Non-mutating actions are always allowed; every mutating action requires a
// clean verdict. This is the single gate every caller must pass through, so
// a new mutating action kind cannot accidentally bypass the engine.
func (v *Verdict) Allows(kind ActionKind) bool {
	if !kind.Mutating() {
		return true
	}
	return !v.Refused()
}

// Kinds returns the distinct protection kinds, in order.
func (v *Verdict) Kinds() []ProtectionKind {
	seen := make(map[ProtectionKind]struct{}, len(v.Protections))
	kinds := make([]ProtectionKind, 0, len(v.Protections))
	for _, protection := range v.Protections {
		if _, dup := seen[protection.Kind]; dup {
			continue
		}
		seen[protection.Kind] = struct{}{}
		kinds = append(kinds, protection.Kind)
	}
	return kinds
}

// Summary renders the refusal as one line for terminal output.
func (v *Verdict) Summary() string {
	if !v.Refused() {
		return "allow"
	}
	kinds := v.Kinds()
	parts := make([]string, len(kinds))
	for i, kind := range kinds {
		parts[i] = string(kind)
	}
	return "refuse: " + strings.Join(parts, ",")
}

// Validate reports every field-level problem with the verdict.
func (v *Verdict) Validate() error {
	var errs FieldErrors
	if v.ContractVersion != ContractVersion {
		errs.Add("contract_version", "must be %d, got %d", ContractVersion, v.ContractVersion)
	}
	if !isAbsClean(v.Path) {
		errs.Add("path", "must be an absolute, cleaned path, got %q", v.Path)
	}
	if !v.Decision.Valid() {
		errs.Add("decision", "unknown safety decision %q", string(v.Decision))
	}
	if v.EvaluatedAt.IsZero() {
		errs.Add("evaluated_at", "must be set")
	}
	if len(v.Guards) == 0 {
		errs.Add("guards", "must name the checks that ran")
	}
	blocking := false
	for i, protection := range v.Protections {
		errs = append(errs, protection.Validate("protections["+itoa(i)+"]")...)
		if protection.Blocking {
			blocking = true
			if strings.TrimSpace(protection.Remediation) == "" {
				errs.Add("protections["+itoa(i)+"].remediation", "a refusal must tell the operator how to clear it")
			}
		}
	}
	if blocking && v.Decision != DecisionRefuse {
		errs.Add("decision", "must be %q while a blocking protection applies", DecisionRefuse)
	}
	if !blocking && v.Decision != DecisionAllow {
		errs.Add("decision", "must be %q when no blocking protection applies", DecisionAllow)
	}
	return errs.ErrorOrNil()
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := make([]byte, 0, 8)
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}
