package cli

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

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
	// ModelUsage totals every recorded model request. Cost is an estimate
	// from reported tokens and the configured price.
	ModelUsage *store.UsageTotals `json:"model_usage,omitempty"`
}

// statusReport is the `status` result contract.
type statusReport struct {
	Build           buildinfo.Info         `json:"build"`
	ContractVersion int                    `json:"contract_version"`
	Paths           config.Paths           `json:"paths"`
	Policy          policyStatus           `json:"policy"`
	Store           storeStatus            `json:"store"`
	Capacity        *core.CapacitySnapshot `json:"capacity,omitempty"`
	Inventory       *inventoryReport       `json:"inventory_report"`
}

// runStatus reports paths, policy, stored state and the capacity decision.
// With capacityOnly it reads nothing but the stored capacity decision: no
// store summaries, model usage or inventory growth, and the policy file
// without the state-derived category archive rules, which the decision does
// not depend on. Admission consumers poll this under load.
func runStatus(ctx context.Context, e *env, capacityOnly bool) error {
	format, err := e.format()
	if err != nil {
		return err
	}
	paths, err := e.resolvePaths()
	if err != nil {
		return err
	}
	var policy config.Policy
	if capacityOnly {
		policy, err = e.loadFilePolicy()
	} else {
		policy, err = e.loadPolicy(ctx)
	}
	if err != nil {
		return err
	}
	report := statusReport{
		Capacity:        unknownCapacity(policy, "no capacity sample exists; run cycle or start watch"),
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

	if capacityOnly {
		if err := readStatusCapacity(ctx, &report, policy); err != nil {
			return err
		}
	} else if err := readStatusStore(ctx, &report, policy); err != nil {
		return err
	}

	if format == output.FormatJSON {
		return output.WriteJSON(e.stdout, "status", report)
	}
	return writeStatusText(e, report)
}

// readStatusStore fills the full status from the database, leaving report
// untouched when none exists: reporting must never create state.
func readStatusStore(ctx context.Context, report *statusReport, policy config.Policy) error {
	db, err := store.OpenExisting(ctx, report.Store.DatabaseFile)
	switch {
	case errors.Is(err, store.ErrNotInitialized):
		return nil
	case err != nil:
		return err
	}
	defer db.Close()
	stats, err := db.Stats(ctx)
	if err != nil {
		return err
	}
	var usage store.UsageTotals
	if err := db.Read(ctx, func(tx *store.Tx) error {
		var err error
		usage, err = tx.UsageTotals(ctx)
		return err
	}); err != nil {
		return err
	}
	report.Store.Initialized = true
	report.Store.Stats = &stats
	report.Store.ModelUsage = &usage
	if stats.SchemaVersion != store.SchemaVersion() {
		return nil
	}
	if err := db.Read(ctx, func(tx *store.Tx) error {
		inventory, err := buildInventoryReport(ctx, tx, policy, time.Now().UTC())
		report.Inventory = &inventory
		return err
	}); err != nil {
		return err
	}
	return readStoredCapacity(ctx, db, report, policy)
}

// readStatusCapacity fills only the capacity decision. It opens the database
// read-only, so it never migrates, takes no write lock and does not
// checkpoint on close; a missing database or a schema this build cannot read
// leaves the unknown-capacity answer in place.
func readStatusCapacity(ctx context.Context, report *statusReport, policy config.Policy) error {
	db, err := store.OpenReadOnly(ctx, report.Store.DatabaseFile)
	switch {
	case errors.Is(err, store.ErrNotInitialized):
		return nil
	case errors.Is(err, store.ErrSchemaMismatch):
		report.Store.Initialized = true
		return nil
	case err != nil:
		return err
	}
	defer db.Close()
	report.Store.Initialized = true
	return readStoredCapacity(ctx, db, report, policy)
}

// readStoredCapacity replaces the unknown capacity with the stored snapshot
// when that snapshot was sampled under the current capacity policy.
func readStoredCapacity(ctx context.Context, db *store.Store, report *statusReport, policy config.Policy) error {
	if len(policy.Prevention.Targets) == 0 {
		return nil
	}
	var snapshot core.CapacitySnapshot
	if err := db.Read(ctx, func(tx *store.Tx) error {
		var err error
		snapshot, err = tx.CapacitySnapshot(ctx)
		return err
	}); err != nil {
		return err
	}
	if snapshot.PolicyHash == capacityPolicyHash(policy) {
		snapshot = snapshot.Expire(time.Now().UTC())
		report.Capacity = &snapshot
	}
	return nil
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
	if report.Capacity != nil {
		for _, volume := range report.Capacity.Volumes {
			fields = append(fields, output.Field{Key: volume.Key + ":", Value: fmt.Sprintf("%s hold=%t target=%d reserve=%d recovery=%d (%s)", volume.State, volume.AdmissionHold, volume.TargetBytes, volume.ReserveBytes, volume.RecoveryBytes, volume.Reason)})
		}
	}
	fields = appendInventoryFields(fields, report.Inventory)
	if report.Store.Stats == nil {
		state := "not initialized; run \"janitor doctor\""
		if report.Store.Initialized {
			state = "summary not read with --capacity"
		}
		fields = append(fields, output.Field{
			Key:   "store:",
			Value: fmt.Sprintf("%s (%s)", report.Store.DatabaseFile, state),
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
	)
	if usage := report.Store.ModelUsage; usage != nil {
		fields = append(fields, output.Field{
			Key: "model usage:",
			Value: fmt.Sprintf("%d request(s), %d input / %d output tokens, est. $%.6f",
				usage.Records, usage.PromptTokens, usage.CompletionTokens, usage.EstimatedCostUSD),
		})
	}
	if stats.LatestScanID != "" {
		latest := stats.LatestScanID
		if stats.LatestScanAt != nil {
			latest = fmt.Sprintf("%s at %s", latest, stats.LatestScanAt.Format("2006-01-02T15:04:05Z"))
		}
		fields = append(fields, output.Field{Key: "latest scan:", Value: latest})
	}
	return output.WriteFields(e.stdout, fields)
}
