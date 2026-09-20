package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/output"
	"github.com/gitmoot/workspace-janitor/internal/safety"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

// explainOptions are the command-line choices for one explanation.
type explainOptions struct {
	planID string
}

// explainReport is the `explain` result contract. It answers three
// questions: what was decided, why, and what was rejected instead.
type explainReport struct {
	Path     string         `json:"path"`
	PlanID   string         `json:"plan_id"`
	ScanID   string         `json:"scan_id"`
	Action   core.Action    `json:"action"`
	Entry    *core.Entry    `json:"entry,omitempty"`
	Verdict  *core.Verdict  `json:"safety_verdict,omitempty"`
	Approved *core.Approval `json:"approval,omitempty"`
}

func runExplain(ctx context.Context, e *env, args []string, opts explainOptions) error {
	if len(args) != 1 {
		return &usageError{msg: "explain takes exactly one path"}
	}
	path := filepath.Clean(args[0])
	if !filepath.IsAbs(path) {
		return &usageError{msg: fmt.Sprintf("path %q must be absolute", args[0])}
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
		return fmt.Errorf("no plan has been created yet: run \"janitor scan\" and \"janitor plan\" first")
	}
	if err != nil {
		return err
	}
	defer db.Close()

	report := explainReport{Path: path}
	err = db.Read(ctx, func(tx *store.Tx) error {
		var stored core.Plan
		var err error
		if opts.planID != "" {
			stored, err = tx.Plan(ctx, opts.planID)
		} else {
			stored, err = tx.LatestPlan(ctx, "")
		}
		if err != nil {
			return err
		}
		report.PlanID = stored.ID
		report.ScanID = stored.ScanID

		found := false
		for _, action := range stored.Actions {
			if action.Path == path {
				report.Action = action
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("plan %s has no action for %s", stored.ID, path)
		}

		entry, err := tx.Entry(ctx, stored.ScanID, path)
		if err == nil {
			report.Entry = &entry
			verdict := safety.Evaluate(safety.Input{
				Entry:  entry,
				Policy: enginePolicy(paths, policy),
				Target: targetFor(policy),
			})
			report.Verdict = &verdict
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}

		approvals, err := tx.Approvals(ctx, stored.ID)
		if err != nil {
			return err
		}
		for _, approval := range approvals {
			if approval.ActionID == report.Action.ID {
				found := approval
				report.Approved = &found
				break
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	if format == output.FormatJSON {
		return output.WriteJSON(e.stdout, "explain", report)
	}
	return writeExplainText(e, report)
}

func targetFor(policy config.Policy) *safety.Target {
	target := safety.ResolveTarget(policy.Retention.QuarantineDir)
	return &target
}

func writeExplainText(e *env, report explainReport) error {
	action := report.Action
	fields := []output.Field{
		{Key: "path:", Value: report.Path},
		{Key: "plan:", Value: report.PlanID},
		{Key: "scan:", Value: report.ScanID},
		{Key: "action:", Value: string(action.Kind)},
		{Key: "class:", Value: string(action.Class)},
		{Key: "retention:", Value: string(action.Retention)},
		{Key: "confidence:", Value: strconv.FormatFloat(action.Confidence, 'f', 2, 64)},
	}
	if action.Destination != "" {
		fields = append(fields, output.Field{Key: "destination:", Value: action.Destination})
	}
	if report.Approved != nil {
		fields = append(fields, output.Field{
			Key:   "approved by:",
			Value: fmt.Sprintf("%s at %s", report.Approved.Approver, report.Approved.ApprovedAt.Format("2006-01-02T15:04:05Z")),
		})
	} else if action.Kind.Mutating() {
		fields = append(fields, output.Field{Key: "approved:", Value: "no (run \"janitor plan --approve " + action.ID + "\")"})
	}
	if err := output.WriteFields(e.stdout, fields); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(e.stdout, "\nWinning rules (%d):\n", len(action.Rules)); err != nil {
		return err
	}
	ruleRows := make([][]string, 0, len(action.Rules))
	for i, rule := range action.Rules {
		reason := ""
		if i < len(action.Reasons) {
			reason = action.Reasons[i]
		}
		ruleRows = append(ruleRows, []string{"  " + rule, reason})
	}
	if err := output.WriteTable(e.stdout, nil, ruleRows); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(e.stdout, "\nRejected alternatives (%d):\n", len(action.Rejected)); err != nil {
		return err
	}
	if len(action.Rejected) == 0 {
		if _, err := fmt.Fprintln(e.stdout, "  none: no other rule proposed a different action"); err != nil {
			return err
		}
	} else {
		rejectedRows := make([][]string, 0, len(action.Rejected))
		for _, rejected := range action.Rejected {
			rejectedRows = append(rejectedRows, []string{"  " + string(rejected.Kind), rejected.Rule, rejected.Reason})
		}
		if err := output.WriteTable(e.stdout, nil, rejectedRows); err != nil {
			return err
		}
	}

	if report.Entry != nil {
		if _, err := fmt.Fprintf(e.stdout, "\nEvidence (%d):\n", len(report.Entry.Evidence)); err != nil {
			return err
		}
		evidenceRows := make([][]string, 0, len(report.Entry.Evidence))
		for _, evidence := range report.Entry.Evidence {
			evidenceRows = append(evidenceRows, []string{"  " + string(evidence.Source), evidence.Signal, evidence.Detail})
		}
		if err := output.WriteTable(e.stdout, nil, evidenceRows); err != nil {
			return err
		}
	}

	if report.Verdict != nil {
		if _, err := fmt.Fprintf(e.stdout, "\nSafety: %s\n", report.Verdict.Summary()); err != nil {
			return err
		}
		rows := make([][]string, 0, len(report.Verdict.Protections))
		for _, protection := range report.Verdict.Protections {
			rows = append(rows, []string{"  " + string(protection.Kind), protection.Reason, "-> " + protection.Remediation})
		}
		if err := output.WriteTable(e.stdout, nil, rows); err != nil {
			return err
		}
	}
	return nil
}
