package cli

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/gitmoot/workspace-janitor/internal/buildinfo"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/output"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

// policyStatus summarizes where the effective policy came from.
type policyStatus struct {
	Source   string `json:"source"`
	FromFile bool   `json:"from_file"`
	Version  int    `json:"version"`
	Roots    int    `json:"roots"`
	Caches   int    `json:"caches"`
	JevOn    bool   `json:"jev_enabled"`
}

// storeStatus summarizes the local database.
type storeStatus struct {
	DatabaseFile    string       `json:"database_file"`
	Initialized     bool         `json:"initialized"`
	ExpectedVersion int          `json:"expected_schema_version"`
	Stats           *store.Stats `json:"stats,omitempty"`
}

// statusReport is the `status` result contract.
type statusReport struct {
	Build           buildinfo.Info `json:"build"`
	ContractVersion int            `json:"contract_version"`
	Paths           config.Paths   `json:"paths"`
	Policy          policyStatus   `json:"policy"`
	Store           storeStatus    `json:"store"`
}

func runStatus(ctx context.Context, e *env) error {
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
	report := statusReport{
		Build:           e.buildRef,
		ContractVersion: core.ContractVersion,
		Paths:           paths,
		Policy: policyStatus{
			Source:   policy.Source,
			FromFile: policy.FromFile,
			Version:  policy.Version,
			Roots:    len(policy.Roots),
			Caches:   len(policy.Caches),
			JevOn:    policy.Jev.Enabled,
		},
		Store: storeStatus{
			DatabaseFile:    paths.DatabaseFile,
			ExpectedVersion: store.SchemaVersion(),
		},
	}

	db, err := store.OpenExisting(ctx, paths.DatabaseFile)
	switch {
	case errors.Is(err, store.ErrNotInitialized):
		// Reporting must never create state as a side effect.
	case err != nil:
		return err
	default:
		defer db.Close()
		stats, err := db.Stats(ctx)
		if err != nil {
			return err
		}
		report.Store.Initialized = true
		report.Store.Stats = &stats
	}

	if format == output.FormatJSON {
		return output.WriteJSON(e.stdout, "status", report)
	}
	return writeStatusText(e, report)
}

func writeStatusText(e *env, report statusReport) error {
	fields := []output.Field{
		{Key: "version:", Value: report.Build.String()},
		{Key: "contract:", Value: strconv.Itoa(report.ContractVersion)},
		{Key: "config dir:", Value: fmt.Sprintf("%s (%s)", report.Paths.ConfigDir, report.Paths.Origins.ConfigDir)},
		{Key: "state dir:", Value: fmt.Sprintf("%s (%s)", report.Paths.StateDir, report.Paths.Origins.StateDir)},
		{Key: "cache dir:", Value: fmt.Sprintf("%s (%s)", report.Paths.CacheDir, report.Paths.Origins.CacheDir)},
		{Key: "policy:", Value: fmt.Sprintf("%s (%d root(s), %d cache rule(s), jev=%t)", report.Policy.Source, report.Policy.Roots, report.Policy.Caches, report.Policy.JevOn)},
	}
	if report.Store.Stats == nil {
		fields = append(fields, output.Field{
			Key:   "store:",
			Value: fmt.Sprintf("%s (not initialized; run \"janitor doctor\")", report.Store.DatabaseFile),
		})
		return output.WriteFields(e.stdout, fields)
	}
	stats := report.Store.Stats
	fields = append(fields,
		output.Field{Key: "store:", Value: fmt.Sprintf("%s (schema %d, %s)", report.Store.DatabaseFile, stats.SchemaVersion, output.HumanBytes(stats.DatabaseBytes))},
		output.Field{Key: "scans:", Value: strconv.FormatInt(stats.Scans, 10)},
		output.Field{Key: "inventory entries:", Value: strconv.FormatInt(stats.InventoryEntries, 10)},
		output.Field{Key: "plans:", Value: strconv.FormatInt(stats.Plans, 10)},
		output.Field{Key: "actions:", Value: strconv.FormatInt(stats.Actions, 10)},
		output.Field{Key: "model usage rows:", Value: strconv.FormatInt(stats.ModelUsageRows, 10)},
	)
	if stats.LatestScanID != "" {
		latest := stats.LatestScanID
		if stats.LatestScanAt != nil {
			latest = fmt.Sprintf("%s at %s", latest, stats.LatestScanAt.Format("2006-01-02T15:04:05Z"))
		}
		fields = append(fields, output.Field{Key: "latest scan:", Value: latest})
	}
	return output.WriteFields(e.stdout, fields)
}
