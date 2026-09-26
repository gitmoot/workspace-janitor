package plan

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

// WorktreeIdle is how long a clean linked worktree must go without a
// checkout, commit, staging, or top-level change before it is proposed for
// quarantine.
const WorktreeIdle = 7 * 24 * time.Hour

// Tier is a rule's precedence band. A proposal from a lower tier is
// considered before any from a higher one, and a decision made in a lower
// tier cannot be overridden by a higher tier — only made safer.
type Tier int

const (
	// TierSafety holds refusals from the safety engine. Nothing overrides
	// them.
	TierSafety Tier = iota
	// TierProtected holds policy-protected and canonical locations.
	TierProtected
	// TierExplicit holds rules the operator wrote, such as cache rules.
	TierExplicit
	// TierBuiltin holds the built-in classification defaults.
	TierBuiltin
	// TierFallback is what applies when nothing else did.
	TierFallback
)

// String renders the tier for explanations.
func (t Tier) String() string {
	switch t {
	case TierSafety:
		return "safety"
	case TierProtected:
		return "protected"
	case TierExplicit:
		return "explicit"
	case TierBuiltin:
		return "builtin"
	default:
		return "fallback"
	}
}

// Proposal is one rule's opinion about an entry.
type Proposal struct {
	Rule        string
	Tier        Tier
	Kind        core.ActionKind
	Retention   core.Retention
	Destination string
	Reason      string
	// Specificity breaks ties between rules in the same tier: the more
	// specific rule is considered first. Rule order in the policy file is
	// never used, so reordering a file cannot change the outcome.
	Specificity int
}

// Decision is the outcome of evaluating every rule for one entry.
type Decision struct {
	Class       core.ArtifactClass
	Kind        core.ActionKind
	Retention   core.Retention
	Destination string
	Rules       []string
	Reasons     []string
	Rejected    []core.RejectedAction
	// Ambiguous marks an entry the deterministic rules could not classify,
	// which is the only input a model classifier may later be offered.
	Ambiguous bool
	// Conflicts records rules in the winning tier that wanted something
	// more destructive than the action taken.
	Conflicts []core.RejectedAction
}

// proposals gathers every rule opinion for an entry, in deterministic
// order. The policy file's ordering is deliberately not consulted.
func proposals(entry core.Entry, class Classification, policy config.Policy, verdict core.Verdict) []Proposal {
	var out []Proposal

	if verdict.Refused() {
		out = append(out, Proposal{
			Rule: "safety.refused", Tier: TierSafety, Kind: core.ActionKeep,
			Retention: core.RetentionNone, Specificity: len(entry.Path),
			Reason: "the safety engine refuses any mutation: " + verdict.Summary(),
		})
	}

	for _, protected := range policy.Protect.Paths {
		if !core.PathsOverlap(entry.Path, protected) {
			continue
		}
		out = append(out, Proposal{
			Rule: "policy.protected_path", Tier: TierProtected, Kind: core.ActionKeep,
			Specificity: len(protected),
			Reason:      fmt.Sprintf("%s overlaps the protected path %s", entry.Path, protected),
		})
	}
	if policy.Gitmoot.Home != "" && core.PathsOverlap(entry.Path, policy.Gitmoot.Home) {
		out = append(out, Proposal{
			Rule: "policy.gitmoot_home", Tier: TierProtected, Kind: core.ActionKeep,
			Specificity: len(policy.Gitmoot.Home),
			Reason:      fmt.Sprintf("%s overlaps Gitmoot's managed home %s", entry.Path, policy.Gitmoot.Home),
		})
	}
	if signal := gitmootSignal(entry); signal != "" {
		out = append(out, Proposal{
			Rule: "policy.gitmoot_managed", Tier: TierProtected, Kind: core.ActionKeep,
			Specificity: len(entry.Path),
			Reason:      fmt.Sprintf("Gitmoot lifecycle evidence %s requires managed review, not generic filesystem cleanup", signal),
		})
	}

	canonical, hasCanonical := canonicalRootFor(policy, class.Class)
	switch {
	case hasCanonical && core.PathWithin(entry.Path, canonical):
		out = append(out, Proposal{
			Rule: "policy.canonical_root", Tier: TierProtected, Kind: core.ActionKeep,
			Specificity: len(canonical),
			Reason:      fmt.Sprintf("%s already lives in the canonical root %s for %s", entry.Path, canonical, class.Class),
		})
	case hasCanonical && class.Class == core.ClassPrimaryProject && core.PathWithin(canonical, entry.Path):
		// The canonical root lives inside this entry, so relocating would
		// move the entry into itself. That cannot succeed, and attempting
		// it would be destructive.
		out = append(out, Proposal{
			Rule: "policy.canonical_root", Tier: TierProtected, Kind: core.ActionInvestigate,
			Specificity: len(canonical),
			Reason: fmt.Sprintf("the canonical root %s is inside %s, so relocating would move the entry into itself",
				canonical, entry.Path),
		})
	case hasCanonical && class.Class == core.ClassPrimaryProject:
		out = append(out, Proposal{
			Rule: "policy.canonical_root", Tier: TierProtected, Kind: core.ActionRelocate,
			Destination: filepath.Join(canonical, filepath.Base(entry.Path)),
			Specificity: len(canonical),
			Reason: fmt.Sprintf("a primary project belongs in %s, not %s",
				canonical, filepath.Dir(entry.Path)),
		})
	}

	for _, rule := range policy.Caches {
		if !core.PathWithin(entry.Path, rule.Path) {
			continue
		}
		kind, reason := boundedCacheAction(entry, rule)
		out = append(out, Proposal{
			Rule: "policy.cache:" + rule.Name, Tier: TierExplicit, Kind: kind,
			Retention: rule.Retention, Specificity: len(rule.Path),
			Reason: fmt.Sprintf("cache rule %q covers %s; %s", rule.Name, rule.Path, reason),
		})
	}

	if policy.Ownership.InvestigateForeignOwner && foreignOwner(entry, policy) {
		out = append(out, Proposal{
			Rule: "policy.foreign_owner", Tier: TierExplicit, Kind: core.ActionInvestigate,
			Specificity: len(entry.Path),
			Reason:      fmt.Sprintf("%s is owned by uid %d, not the expected owner", entry.Path, entry.Ownership.UID),
		})
	}

	out = append(out, builtinProposal(entry, class, policy))

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Tier != out[j].Tier {
			return out[i].Tier < out[j].Tier
		}
		if out[i].Specificity != out[j].Specificity {
			return out[i].Specificity > out[j].Specificity
		}
		return out[i].Rule < out[j].Rule
	})
	return out
}

// boundedCacheAction uses only inventory evidence and the scan observation
// time, never the planner's wall clock. Zero bounds preserve legacy rules.
func boundedCacheAction(entry core.Entry, rule config.CacheRule) (core.ActionKind, string) {
	if rule.MaxBytes == 0 && rule.TTL == 0 {
		return rule.Action, "no size or age bound is configured"
	}
	if entry.Kind != core.EntryKindDirectory && entry.Kind != core.EntryKindFile {
		return core.ActionInvestigate, "bounded cache cleanup requires a regular file or a completely sized directory"
	}
	if entry.Kind == core.EntryKindDirectory && !entry.SizeIsDeep {
		return core.ActionInvestigate, "complete deep-size evidence is required for bounded directory cleanup"
	}
	modified := entry.ModifiedAt
	if entry.Kind == core.EntryKindDirectory {
		modified = entry.LatestModifiedAt
	}
	if rule.TTL > 0 && (modified.IsZero() || entry.ObservedAt.IsZero() || modified.After(entry.ObservedAt)) {
		return core.ActionInvestigate, "complete latest modification time and observation time are required for ttl"
	}
	if rule.MaxBytes > 0 && entry.SizeIsLowerBound && entry.SizeBytes <= rule.MaxBytes {
		return core.ActionInvestigate, fmt.Sprintf("size is at least %d bytes, which cannot show whether max_bytes %d is exceeded", entry.SizeBytes, rule.MaxBytes)
	}
	if rule.MaxBytes > 0 && entry.SizeBytes <= rule.MaxBytes {
		return core.ActionKeep, fmt.Sprintf("size %d bytes is at or below max_bytes %d", entry.SizeBytes, rule.MaxBytes)
	}
	if rule.TTL > 0 {
		if age := entry.ObservedAt.Sub(modified); age < rule.TTL.Duration() {
			return core.ActionKeep, fmt.Sprintf("newest content age %s is below ttl %s", age, rule.TTL.Duration())
		}
	}
	return rule.Action, fmt.Sprintf("complete evidence meets max_bytes %d and ttl %s at observation time", rule.MaxBytes, rule.TTL.Duration())
}

// builtinProposal is the default action for a class.
//
// None of these is delete_candidate. Deleting directly is not something the
// built-in policy ever recommends: quarantine is the strongest default, and
// a delete can only come from a rule an operator wrote deliberately.
func builtinProposal(entry core.Entry, class Classification, policy config.Policy) Proposal {
	base := Proposal{Tier: TierBuiltin, Specificity: len(entry.Path), Reason: class.Reason}
	switch class.Class {
	case core.ClassEvidence:
		base.Rule, base.Kind = "builtin.evidence", core.ActionKeep
	case core.ClassOperationalTool:
		base.Rule, base.Kind = "builtin.operational_tool", core.ActionKeep
	case core.ClassPrimaryProject:
		base.Rule, base.Kind = "builtin.primary_project", core.ActionKeep
	case core.ClassBackup:
		// Backups are kept: whether one is still needed is a judgement the
		// tool does not have the evidence to make.
		base.Rule, base.Kind = "builtin.backup", core.ActionKeep
	case core.ClassTaskWorktree:
		base.Rule, base.Kind = "builtin.task_worktree", core.ActionInvestigate
		switch {
		case !entry.Git.Clean():
		case entry.Git.LastActivity.IsZero() || entry.ObservedAt.IsZero():
			base.Reason += "; clean, but when it was last used is unknown"
		case entry.ObservedAt.Sub(entry.Git.LastActivity) < WorktreeIdle:
			// A clean worktree can still be someone's current workspace
			// between commits; only an idle one is left behind.
			base.Reason += fmt.Sprintf("; clean, but used within %s", WorktreeIdle)
		default:
			// Everything an idle clean linked worktree holds is committed
			// and on a remote, and its branches live on in the shared
			// repository.
			base.Kind, base.Retention = core.ActionQuarantine, policy.Retention.Default
			base.Reason += fmt.Sprintf("; clean, every commit on a remote-tracking branch, and idle for over %s", WorktreeIdle)
		}
	case core.ClassGeneratedArtifact:
		base.Rule, base.Kind = "builtin.generated_artifact", core.ActionQuarantine
		base.Retention = policy.Retention.Default
	case core.ClassCache:
		base.Rule, base.Kind = "builtin.cache", core.ActionQuarantine
		base.Retention = policy.Retention.Default
		if filepath.Base(entry.Path) == ".cache" {
			// A home cache directory is many tools' caches, and some hold
			// live installs such as browsers. It is not one disposable cache.
			base.Kind = core.ActionInvestigate
			base.Retention = core.RetentionNone
			base.Reason += "; a home cache directory holds many tools' caches, so select them with per-tool cache rules"
		} else if strings.HasPrefix(class.Rule, "classify.adapter:") {
			// Shared provider stores are not equivalent to an isolated
			// project output. The operator must select and bound one.
			base.Kind = core.ActionInvestigate
			base.Retention = core.RetentionNone
			base.Reason += "; shared provider caches need explicit scoped policy and review"
		}
	default:
		base.Rule, base.Kind, base.Tier = "builtin.unknown", core.ActionInvestigate, TierFallback
		base.Reason = "nothing classified this path, so it is left for a human to look at"
	}
	return base
}

// Evaluate resolves every proposal into one decision.
//
// The winning tier is the lowest one that produced a proposal. Within it,
// the safest action wins: a rule asking for something more destructive than
// another rule in the same tier loses and is recorded as a conflict, so
// disagreement is visible rather than arbitrated silently.
func Evaluate(entry core.Entry, policy config.Policy, verdict core.Verdict) Decision {
	class := Classify(entry, policy)
	candidates := proposals(entry, class, policy, verdict)

	decision := Decision{
		Class:     class.Class,
		Kind:      core.ActionInvestigate,
		Ambiguous: class.Class == core.ClassUnknown,
		Rules:     []string{class.Rule},
		Reasons:   []string{class.Reason},
	}
	if len(candidates) == 0 {
		decision.Rules = append(decision.Rules, "fallback.no_rule")
		decision.Reasons = append(decision.Reasons, "no rule applied, so the path is left for review")
		return decision
	}

	winningTier := candidates[0].Tier
	var winner Proposal
	chosen := false
	for _, candidate := range candidates {
		if candidate.Tier != winningTier {
			// Lower tiers decide. A later tier's opinion is recorded as a
			// rejected alternative so the trace is complete.
			decision.Rejected = append(decision.Rejected, core.RejectedAction{
				Kind:   candidate.Kind,
				Rule:   candidate.Rule,
				Reason: fmt.Sprintf("%s tier decided first: %s", winningTier, candidate.Reason),
			})
			continue
		}
		if !chosen {
			winner, chosen = candidate, true
			continue
		}
		safer := winner.Kind.Safer(candidate.Kind)
		switch {
		case safer == candidate.Kind && candidate.Kind != winner.Kind:
			decision.Conflicts = append(decision.Conflicts, core.RejectedAction{
				Kind:     winner.Kind,
				Rule:     winner.Rule,
				Reason:   fmt.Sprintf("conflicting rule %s asked for the safer %s", candidate.Rule, candidate.Kind),
				Conflict: true,
			})
			winner = candidate
		case candidate.Kind != winner.Kind:
			decision.Conflicts = append(decision.Conflicts, core.RejectedAction{
				Kind:     candidate.Kind,
				Rule:     candidate.Rule,
				Reason:   fmt.Sprintf("conflicting rule %s asked for the safer %s", winner.Rule, winner.Kind),
				Conflict: true,
			})
		default:
			// Same tier, same action: both rules agree, so both are
			// credited. Rules and reasons stay index-aligned, which is
			// what lets an explanation pair them.
			decision.Rules = append(decision.Rules, candidate.Rule)
			decision.Reasons = append(decision.Reasons, candidate.Reason)
		}
	}

	decision.Kind = winner.Kind
	decision.Retention = winner.Retention
	decision.Destination = winner.Destination
	decision.Rules = append(decision.Rules, winner.Rule)
	decision.Reasons = append(decision.Reasons, winner.Reason)
	decision.Rejected = append(decision.Rejected, decision.Conflicts...)

	if decision.Kind == core.ActionRelocate && decision.Destination == "" {
		// A relocation with nowhere to go is not actionable.
		decision.Rejected = append(decision.Rejected, core.RejectedAction{
			Kind: core.ActionRelocate, Rule: winner.Rule,
			Reason: "no canonical destination is configured for this class",
		})
		decision.Kind = core.ActionInvestigate
	}
	if decision.Kind.Mutating() && verdict.Refused() {
		// Belt and braces: the safety tier already forces keep, but no
		// mutating action may survive a refusal by any route.
		decision.Rejected = append(decision.Rejected, core.RejectedAction{
			Kind: decision.Kind, Rule: "safety.refused",
			Reason: "the safety engine refuses any mutation: " + verdict.Summary(),
		})
		decision.Kind = core.ActionKeep
		decision.Retention = core.RetentionNone
		decision.Destination = ""
	}
	if !decision.Kind.Mutating() {
		decision.Retention = core.RetentionNone
		if decision.Kind != core.ActionRelocate {
			decision.Destination = ""
		}
	}
	if decision.Kind == core.ActionQuarantine && decision.Retention == "" {
		decision.Retention = policy.Retention.Default
	}
	return decision
}

func canonicalRootFor(policy config.Policy, class core.ArtifactClass) (string, bool) {
	for _, root := range policy.CanonicalRoots {
		if root.Class == class {
			return root.Path, true
		}
	}
	return "", false
}

func foreignOwner(entry core.Entry, policy config.Policy) bool {
	expected := policy.Ownership.ExpectedUID
	if expected == 0 {
		return false
	}
	return entry.Ownership.UID != expected
}
