package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/output"
	"github.com/gitmoot/workspace-janitor/internal/plan"
	"github.com/gitmoot/workspace-janitor/internal/safety"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

// planOptions are the command-line choices for one planning run.
type planOptions struct {
	scanID     string
	planID     string
	approve    string
	approveAll bool
	approver   string
	note       string
	noPersist  bool
}

// planReport is the `plan` result contract.
type planReport struct {
	Plan      core.Plan        `json:"plan"`
	Summary   core.PlanSummary `json:"summary"`
	Persisted bool             `json:"persisted"`
	// Reused reports that an identical plan already existed and was loaded
	// rather than rewritten.
	Reused    bool            `json:"reused"`
	Traces    []plan.Trace    `json:"traces"`
	Approvals []core.Approval `json:"approvals"`
	// Conflicts lists actions where rules disagreed, resolved to the safer
	// option. Reporting them is the difference between arbitration and a
	// silent choice.
	Conflicts []planConflict `json:"conflicts"`
}

// planConflict is one recorded disagreement between rules.
type planConflict struct {
	Path     string                `json:"path"`
	Chosen   core.ActionKind       `json:"chosen"`
	Rejected []core.RejectedAction `json:"rejected"`
}

func runPlan(ctx context.Context, e *env, args []string, opts planOptions) error {
	if len(args) > 0 {
		return &usageError{msg: "plan takes no arguments"}
	}
	format, err := e.format()
	if err != nil {
		return err
	}
	paths, err := e.resolvePaths()
	if err != nil {
		return err
	}
	policy, err := e.loadPolicy()
	if err != nil {
		return err
	}

	db, err := store.OpenExisting(ctx, paths.DatabaseFile)
	if errors.Is(err, store.ErrNotInitialized) {
		return fmt.Errorf("no inventory has been collected yet: run \"janitor scan\" first")
	}
	if err != nil {
		return err
	}
	defer db.Close()

	built, entries, err := buildOrLoadPlan(ctx, e, db, paths, policy, opts)
	if err != nil {
		return err
	}
	report := planReport{
		Plan:      built.Plan,
		Summary:   built.Plan.Summary(),
		Traces:    built.Traces,
		Conflicts: conflictsOf(built.Plan),
	}

	if !opts.noPersist {
		// The plan id is derived from the scan, the evidence, and the
		// policy, so re-planning unchanged inputs yields the plan that is
		// already stored. Reuse it rather than writing a second copy: the
		// stored one is what reviews and approvals already refer to.
		stored, err := loadStoredPlan(ctx, db, built.Plan.ID)
		switch {
		case err == nil:
			report.Plan = stored
			report.Summary = stored.Summary()
			report.Reused = true
		case errors.Is(err, store.ErrNotFound):
			if err := db.Write(ctx, func(tx *store.Tx) error { return tx.SavePlan(ctx, built.Plan) }); err != nil {
				return err
			}
		default:
			return err
		}
		report.Persisted = true
	}

	approvals, err := applyApprovals(ctx, db, report.Plan, opts)
	if err != nil {
		return err
	}
	report.Approvals = approvals
	_ = entries

	if format == output.FormatJSON {
		return output.WriteJSON(e.stdout, "plan", report)
	}
	return writePlanText(e, report)
}

// buildOrLoadPlan either rebuilds a plan from an inventory or loads an
// existing one, which is what makes approving a stored plan possible
// without recomputing or mutating it.
func buildOrLoadPlan(
	ctx context.Context,
	e *env,
	db *store.Store,
	paths config.Paths,
	policy config.Policy,
	opts planOptions,
) (plan.Result, []core.Entry, error) {
	var (
		result  plan.Result
		entries []core.Entry
	)

	if opts.planID != "" {
		err := db.Read(ctx, func(tx *store.Tx) error {
			stored, err := tx.Plan(ctx, opts.planID)
			if err != nil {
				return err
			}
			result.Plan = stored
			// The binding is checked against the current inventory, not
			// against the plan's own frozen scan: comparing a plan with the
			// evidence it was built from would always succeed and prove
			// nothing.
			current, err := tx.LatestScan(ctx, core.ScanCompleted)
			if err != nil {
				return err
			}
			entries, err = tx.Entries(ctx, current.ID)
			return err
		})
		if err != nil {
			return plan.Result{}, nil, err
		}
		if err := plan.VerifyBinding(result.Plan, result.Plan.ScanID, entries, policy); err != nil {
			return plan.Result{}, nil, err
		}
		return result, entries, nil
	}

	scanID := opts.scanID
	err := db.Read(ctx, func(tx *store.Tx) error {
		if scanID == "" {
			latest, err := tx.LatestScan(ctx, core.ScanCompleted)
			if err != nil {
				return err
			}
			scanID = latest.ID
		} else if _, err := tx.Scan(ctx, scanID); err != nil {
			// Entries of an unknown scan come back as an empty slice, which
			// would silently produce a plan bound to a scan that does not
			// exist.
			return err
		}
		var err error
		entries, err = tx.Entries(ctx, scanID)
		return err
	})
	if errors.Is(err, store.ErrNotFound) && opts.scanID != "" {
		return plan.Result{}, nil, fmt.Errorf("no scan %s is stored", opts.scanID)
	}
	if errors.Is(err, store.ErrNotFound) {
		return plan.Result{}, nil, fmt.Errorf("no completed scan is stored: run \"janitor scan\" first")
	}
	if err != nil {
		return plan.Result{}, nil, err
	}

	target := safety.ResolveTarget(policy.Retention.QuarantineDir)
	result, err = plan.Build(ctx, plan.Input{
		ScanID:  scanID,
		Entries: entries,
		Policy:  policy,
		Safety:  enginePolicy(paths, policy),
		Target:  &target,
		Now:     time.Now().UTC(),
	})
	if err != nil {
		return plan.Result{}, nil, err
	}
	return result, entries, nil
}

// applyApprovals records the operator's selection, if any, and returns the
// approvals now on record for the plan.
func applyApprovals(ctx context.Context, db *store.Store, built core.Plan, opts planOptions) ([]core.Approval, error) {
	selected, err := selectedActions(built, opts)
	if err != nil {
		return nil, err
	}
	if len(selected) > 0 {
		if opts.noPersist {
			return nil, &usageError{msg: "--no-store cannot be combined with an approval: an approval must be recorded"}
		}
		now := time.Now().UTC()
		if err := db.Write(ctx, func(tx *store.Tx) error {
			for _, action := range selected {
				if err := tx.Approve(ctx, core.Approval{
					PlanID:     built.ID,
					ActionID:   action.ID,
					Approver:   opts.approver,
					ApprovedAt: now,
					Note:       opts.note,
				}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	var approvals []core.Approval
	if err := db.Read(ctx, func(tx *store.Tx) error {
		var err error
		approvals, err = tx.Approvals(ctx, built.ID)
		return err
	}); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return approvals, nil
}

// selectedActions resolves the operator's approval selection.
//
// Selection is by action id or path only: approving must never require
// editing the plan, and only mutating actions can be approved, because
// approving a "keep" would mean nothing.
func selectedActions(built core.Plan, opts planOptions) ([]core.Action, error) {
	if !opts.approveAll && strings.TrimSpace(opts.approve) == "" {
		return nil, nil
	}
	byID := make(map[string]core.Action, len(built.Actions))
	byPath := make(map[string]core.Action, len(built.Actions))
	for _, action := range built.Actions {
		byID[action.ID] = action
		byPath[action.Path] = action
	}

	if opts.approveAll {
		out := make([]core.Action, 0, len(built.Actions))
		for _, action := range built.Actions {
			if action.Kind.Mutating() {
				out = append(out, action)
			}
		}
		if len(out) == 0 {
			return nil, &usageError{msg: "this plan proposes no mutating action to approve"}
		}
		return out, nil
	}

	var out []core.Action
	for _, token := range strings.Split(opts.approve, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		action, ok := byID[token]
		if !ok {
			action, ok = byPath[token]
		}
		if !ok {
			return nil, &usageError{msg: fmt.Sprintf("plan %s has no action %q", built.ID, token)}
		}
		if !action.Kind.Mutating() {
			return nil, &usageError{msg: fmt.Sprintf("action %s is %s and needs no approval", action.ID, action.Kind)}
		}
		out = append(out, action)
	}
	return out, nil
}

// loadStoredPlan fetches a plan by id.
func loadStoredPlan(ctx context.Context, db *store.Store, id string) (core.Plan, error) {
	var stored core.Plan
	err := db.Read(ctx, func(tx *store.Tx) error {
		var err error
		stored, err = tx.Plan(ctx, id)
		return err
	})
	return stored, err
}

func conflictsOf(built core.Plan) []planConflict {
	conflicts := []planConflict{}
	for _, action := range built.Actions {
		// Only genuine same-tier disagreements are conflicts. An opinion
		// that a higher-precedence tier pre-empted is part of the trace,
		// not something an operator needs to arbitrate.
		disagreements := []core.RejectedAction{}
		for _, rejected := range action.Rejected {
			if rejected.Conflict {
				disagreements = append(disagreements, rejected)
			}
		}
		if len(disagreements) == 0 {
			continue
		}
		conflicts = append(conflicts, planConflict{
			Path:     action.Path,
			Chosen:   action.Kind,
			Rejected: disagreements,
		})
	}
	sort.SliceStable(conflicts, func(i, j int) bool { return conflicts[i].Path < conflicts[j].Path })
	return conflicts
}

// enginePolicy maps the configured policy onto the safety engine's inputs.
func enginePolicy(paths config.Paths, policy config.Policy) safety.Policy {
	return safety.Policy{
		ProtectedPaths:           policy.Protect.Paths,
		NamePatterns:             policy.Protect.NamePatterns,
		StateDir:                 paths.StateDir,
		QuarantineDir:            policy.Retention.QuarantineDir,
		AllowCrossFilesystemCopy: policy.Safety.AllowCrossFilesystemQuarantine,
		MinFreeBytes:             policy.Safety.MinFreeBytes,
	}
}

func writePlanText(e *env, report planReport) error {
	approved := make(map[string]core.Approval, len(report.Approvals))
	for _, approval := range report.Approvals {
		approved[approval.ActionID] = approval
	}

	fields := []output.Field{
		{Key: "plan:", Value: report.Plan.ID},
		{Key: "scan:", Value: report.Plan.ScanID},
		{Key: "evidence:", Value: report.Plan.EvidenceDigest},
		{Key: "policy:", Value: report.Plan.PolicyDigest},
		{Key: "actions:", Value: strconv.Itoa(report.Summary.Total)},
		{Key: "mutating:", Value: strconv.Itoa(report.Summary.Mutates)},
		{Key: "approved:", Value: strconv.Itoa(len(report.Approvals))},
		{Key: "persisted:", Value: strconv.FormatBool(report.Persisted)},
		{Key: "reused:", Value: strconv.FormatBool(report.Reused)},
	}
	if err := output.WriteFields(e.stdout, fields); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(e.stdout, "\nActions:"); err != nil {
		return err
	}
	rows := make([][]string, 0, len(report.Plan.Actions))
	for _, action := range report.Plan.Actions {
		state := "-"
		if _, ok := approved[action.ID]; ok {
			state = "approved"
		}
		rows = append(rows, []string{
			string(action.Kind),
			string(action.Class),
			state,
			action.ID,
			action.Path,
		})
	}
	if err := output.WriteTable(e.stdout, []string{"ACTION", "CLASS", "APPROVAL", "ID", "PATH"}, rows); err != nil {
		return err
	}

	if len(report.Conflicts) > 0 {
		if _, err := fmt.Fprintf(e.stdout, "\nRule conflicts (%d), resolved to the safer action:\n", len(report.Conflicts)); err != nil {
			return err
		}
		conflictRows := make([][]string, 0, len(report.Conflicts))
		for _, conflict := range report.Conflicts {
			for _, rejected := range conflict.Rejected {
				conflictRows = append(conflictRows, []string{
					"  " + conflict.Path,
					"chose " + string(conflict.Chosen),
					"over " + string(rejected.Kind),
					rejected.Rule,
					rejected.Reason,
				})
			}
		}
		if err := output.WriteTable(e.stdout, nil, conflictRows); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintf(e.stdout,
		"\nRun \"janitor explain <path>\" for the reasoning behind one action.\n")
	return err
}
