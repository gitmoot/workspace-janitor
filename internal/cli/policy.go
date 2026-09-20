package cli

import (
	"context"
	"fmt"
	"strconv"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/output"
)

// policyCheckReport is the `policy check` result contract. It carries the
// effective policy, including defaults, so an operator can see exactly what
// the tool will act on rather than only what the file says.
type policyCheckReport struct {
	PolicyFile string        `json:"policy_file"`
	Valid      bool          `json:"valid"`
	Effective  config.Policy `json:"effective"`
}

func runPolicyCheck(ctx context.Context, e *env) error {
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
		// Field-level configuration failures are rendered by report().
		return err
	}
	report := policyCheckReport{PolicyFile: paths.PolicyFile, Valid: true, Effective: policy}
	if format == output.FormatJSON {
		return output.WriteJSON(e.stdout, "policy_check", report)
	}
	return writePolicyText(e, report)
}

func writePolicyText(e *env, report policyCheckReport) error {
	fields := []output.Field{
		{Key: "policy file:", Value: report.PolicyFile},
		{Key: "source:", Value: report.Effective.Source},
		{Key: "version:", Value: strconv.Itoa(report.Effective.Version)},
		{Key: "retention default:", Value: string(report.Effective.Retention.Default)},
		{Key: "quarantine dir:", Value: report.Effective.Retention.QuarantineDir},
		{Key: "jev:", Value: jevSummary(report.Effective)},
		{Key: "limits:", Value: fmt.Sprintf("git=%s command=%s max-entries=%d", report.Effective.Limits.GitTimeout, report.Effective.Limits.CommandTimeout, report.Effective.Limits.MaxEntries)},
	}
	if err := output.WriteFields(e.stdout, fields); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(e.stdout, "\nRoots (%d):\n", len(report.Effective.Roots)); err != nil {
		return err
	}
	rows := make([][]string, 0, len(report.Effective.Roots))
	for _, root := range report.Effective.Roots {
		rows = append(rows, []string{
			"  " + root.Path,
			"max-depth=" + strconv.Itoa(root.MaxDepth),
			fmt.Sprintf("follow-symlinks=%t", root.FollowSymlinks),
			fmt.Sprintf("cross-filesystem=%t", root.CrossFilesystem),
			fmt.Sprintf("report-only=%t", root.ReportOnly),
		})
	}
	if err := output.WriteTable(e.stdout, nil, rows); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(e.stdout, "\nProtected paths (%d), name patterns (%d)\n",
		len(report.Effective.Protect.Paths), len(report.Effective.Protect.NamePatterns)); err != nil {
		return err
	}
	if len(report.Effective.Caches) > 0 {
		if _, err := fmt.Fprintf(e.stdout, "\nCache rules (%d):\n", len(report.Effective.Caches)); err != nil {
			return err
		}
		cacheRows := make([][]string, 0, len(report.Effective.Caches))
		for _, cache := range report.Effective.Caches {
			cacheRows = append(cacheRows, []string{"  " + cache.Name, cache.Path, string(cache.Action), string(cache.Retention)})
		}
		if err := output.WriteTable(e.stdout, nil, cacheRows); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(e.stdout, "\npolicy is valid")
	return err
}

func jevSummary(policy config.Policy) string {
	if !policy.Jev.Enabled {
		return "disabled"
	}
	return fmt.Sprintf("enabled model=%s max-batch=%d", policy.Jev.Model, policy.Jev.MaxBatch)
}
