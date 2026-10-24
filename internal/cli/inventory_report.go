package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

const inventoryReportLimit = 64

func inventoryScope(roots []collect.RootSpec, limits collect.Limits, deep bool) (string, error) {
	ordered := append([]collect.RootSpec(nil), roots...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	// Collection versions, roots, traversal semantics and bounds define the
	// measurement. Approval/retention changes do not change measured byte units.
	data, err := json.Marshal(struct {
		Version                                           int
		Roots                                             []collect.RootSpec
		Deep                                              bool
		MaxEntries, MaxDirEntries, DeepEntries, DeepDepth int
	}{1, ordered, deep, limits.MaxEntries, limits.MaxDirEntries, limits.DeepSizeMaxEntries, limits.DeepSizeMaxDepth})
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

type inventoryChange struct {
	Path   string `json:"path"`
	Owner  string `json:"decision_owner"`
	Before *int64 `json:"before_apparent_bytes"`
	After  *int64 `json:"after_apparent_bytes"`
	Change *int64 `json:"change_apparent_bytes"`
	Reason string `json:"reason,omitempty"`
}

type inventoryGrowth struct {
	Status             string            `json:"status"`
	ScanID             string            `json:"scan_id,omitempty"`
	PreviousScanID     string            `json:"previous_scan_id,omitempty"`
	StartedAt          time.Time         `json:"started_at,omitempty"`
	FinishedAt         *time.Time        `json:"finished_at,omitempty"`
	PreviousStartedAt  *time.Time        `json:"previous_started_at,omitempty"`
	PreviousFinishedAt *time.Time        `json:"previous_finished_at,omitempty"`
	Deep               bool              `json:"deep"`
	Stale              bool              `json:"stale"`
	ComparableEntries  int               `json:"comparable_entries"`
	UnknownEntries     int               `json:"unknown_entries"`
	OmittedChanges     int               `json:"omitted_changes"`
	Changes            []inventoryChange `json:"changes"`
	Limitations        string            `json:"limitations"`
}

type inventoryBudget struct {
	Path              string         `json:"path"`
	Owner             string         `json:"decision_owner"`
	Approval          string         `json:"approval,omitempty"`
	Kind              string         `json:"kind"`
	ApparentBytes     *int64         `json:"observed_apparent_bytes"`
	LogicalThreshold  *int64         `json:"logical_threshold_bytes"`
	AllocatedPruneCap *int64         `json:"allocated_prune_cap_bytes"`
	ExportFileCap     *int64         `json:"export_file_cap_bytes"`
	Retention         core.Retention `json:"retention"`
	Reasons           []string       `json:"reasons"`
}

type inventoryReport struct {
	Growth               inventoryGrowth         `json:"growth"`
	Budgets              []inventoryBudget       `json:"store_budgets"`
	Unresolved           []string                `json:"unresolved_decisions"`
	Activities           []core.CapacityActivity `json:"activities"`
	ActivityHistoryLimit int                     `json:"activity_history_limit"`
}

func observedSize(entry *core.Entry) *int64 {
	if entry == nil || entry.SizeBytes < 0 || entry.SizeIsLowerBound {
		return nil
	}
	if entry.Kind != core.EntryKindFile && (entry.Kind != core.EntryKindDirectory || !entry.SizeIsDeep) {
		return nil
	}
	return &entry.SizeBytes
}

func completeDiscovery(scan core.Scan) bool {
	for _, report := range scan.Collectors {
		if report.Name == collect.CollectorFilesystem {
			return report.Status == core.CollectorRan && report.Unknowns == 0
		}
	}
	return false
}

func inventoryOwner(path string, policy config.Policy) string {
	for _, rule := range policy.Caches {
		if path == rule.Path && rule.Recovery.Owner != "" {
			return rule.Recovery.Owner
		}
	}
	for _, rule := range policy.EvidenceExports {
		if path == rule.Path {
			return rule.Owner
		}
	}
	return "unassigned"
}

func growthMagnitude(change inventoryChange) int64 {
	if change.Change == nil {
		return 0
	}
	if *change.Change < 0 {
		return -*change.Change
	}
	return *change.Change
}

// Keep a bounded, deterministic list rather than allocating a second inventory.
func retainGrowth(rows []inventoryChange, change inventoryChange) []inventoryChange {
	magnitude := growthMagnitude(change)
	at := sort.Search(len(rows), func(i int) bool {
		other := growthMagnitude(rows[i])
		return other < magnitude || (other == magnitude && rows[i].Path > change.Path)
	})
	if at >= inventoryReportLimit {
		return rows
	}
	if len(rows) < inventoryReportLimit {
		rows = append(rows, inventoryChange{})
	}
	copy(rows[at+1:], rows[at:len(rows)-1])
	rows[at] = change
	return rows
}

func buildInventoryReport(ctx context.Context, tx *store.Tx, policy config.Policy, now time.Time) (inventoryReport, error) {
	report := inventoryReport{
		Growth:  inventoryGrowth{Status: "no_inventory", Changes: []inventoryChange{}, Limitations: "Apparent sizes are not allocated or reclaimed bytes. Path rows can overlap: do not sum them. Observations are not atomic; concurrent writers may contribute. Missing, shallow, incomplete or incompatible observations are unknown, never zero growth."},
		Budgets: []inventoryBudget{}, Unresolved: []string{},
	}
	pair, err := tx.InventoryComparison(ctx)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return report, err
	}
	current := make(map[string]*core.Entry, len(pair.CurrentEntries))
	for i := range pair.CurrentEntries {
		current[pair.CurrentEntries[i].Path] = &pair.CurrentEntries[i]
	}
	growth := &report.Growth
	if err == nil {
		growth.ScanID, growth.StartedAt, growth.FinishedAt, growth.Deep = pair.Current.ID, pair.Current.StartedAt, pair.Current.FinishedAt, pair.Deep
		growth.Stale = pair.Current.FinishedAt == nil || now.Before(pair.Current.StartedAt) || now.Sub(*pair.Current.FinishedAt) > policy.Prevention.DeepInterval.Duration()
		growth.Status = "no_comparable_baseline"
		roots, err := scanRoots(policy, nil, scanOptions{})
		if err != nil {
			return report, err
		}
		expectedScope, err := inventoryScope(roots, collectLimits(policy, scanOptions{}), pair.Deep)
		if err != nil {
			return report, err
		}
		switch {
		case pair.Scope == "":
			growth.Status = "legacy_measurement_scope_unknown"
		case pair.Scope != expectedScope:
			growth.Status = "configured_scope_mismatch"
		case pair.Previous != nil:
			growth.Status = "compared"
			growth.PreviousScanID = pair.Previous.ID
			growth.PreviousStartedAt, growth.PreviousFinishedAt = &pair.Previous.StartedAt, pair.Previous.FinishedAt
		}
		previous := make(map[string]*core.Entry, len(pair.PreviousEntries))
		for i := range pair.PreviousEntries {
			previous[pair.PreviousEntries[i].Path] = &pair.PreviousEntries[i]
		}
		changed := 0
		observe := func(path string, before, after *core.Entry) {
			row := inventoryChange{Path: path, Owner: inventoryOwner(path, policy), Before: observedSize(before), After: observedSize(after)}
			zero := int64(0)
			switch {
			case growth.Status != "compared":
				row.Reason = growth.Status
			case before == nil && !completeDiscovery(*pair.Previous):
				row.Reason = "previous_discovery_incomplete"
			case after == nil && !completeDiscovery(pair.Current):
				row.Reason = "current_discovery_incomplete"
			case before != nil && after != nil && (before.FilesystemID != after.FilesystemID || before.Kind != after.Kind):
				row.Reason = "filesystem_identity_or_kind_changed"
			case before != nil && (before.FilesystemID.Device == 0 || before.FilesystemID.Inode == 0):
				row.Reason = "previous_identity_unknown"
			case after != nil && (after.FilesystemID.Device == 0 || after.FilesystemID.Inode == 0):
				row.Reason = "current_identity_unknown"
			default:
				if before == nil {
					row.Before = &zero
				}
				if after == nil {
					row.After = &zero
				}
				if row.Before == nil || row.After == nil {
					row.Reason = "measurement_incomplete_or_shallow"
				} else {
					delta := *row.After - *row.Before
					row.Change = &delta
				}
			}
			if row.Change == nil {
				growth.UnknownEntries++
			} else {
				growth.ComparableEntries++
				if *row.Change == 0 {
					return
				}
			}
			changed++
			growth.Changes = retainGrowth(growth.Changes, row)
		}
		for i := range pair.CurrentEntries {
			entry := &pair.CurrentEntries[i]
			observe(entry.Path, previous[entry.Path], entry)
		}
		for i := range pair.PreviousEntries {
			entry := &pair.PreviousEntries[i]
			if current[entry.Path] == nil {
				observe(entry.Path, entry, nil)
			}
		}
		growth.OmittedChanges = changed - len(growth.Changes)
	}
	for _, rule := range policy.Caches {
		row := inventoryBudget{Path: rule.Path, Owner: inventoryOwner(rule.Path, policy), Approval: rule.Recovery.Approval, Kind: "cache", ApparentBytes: observedSize(current[rule.Path]), Retention: rule.Retention, Reasons: []string{"fresh producer and safety preflight still required"}}
		if rule.MaxBytes > 0 {
			n := rule.MaxBytes
			row.LogicalThreshold = &n
		}
		if rule.Recovery.MaxPruneBytes > 0 {
			n := rule.Recovery.MaxPruneBytes
			row.AllocatedPruneCap = &n
		} else {
			row.Reasons = append(row.Reasons, "no approved automatic prune cap")
		}
		if row.Owner == "unassigned" || row.Approval == "" {
			report.Unresolved = append(report.Unresolved, rule.Path+": owner and scoped approval required")
		}
		if !policy.Prevention.Recovery.Enabled {
			row.Reasons = append(row.Reasons, "automatic recovery disabled")
		}
		if entry := current[rule.Path]; entry != nil {
			for _, protection := range entry.Protections {
				if protection.Blocking {
					row.Reasons = append(row.Reasons, "inventory protection: "+protection.Reason)
				}
			}
		}
		report.Budgets = append(report.Budgets, row)
	}
	for _, rule := range policy.EvidenceExports {
		cap := rule.MaxBytes
		row := inventoryBudget{Path: rule.Path, Owner: rule.Owner, Approval: rule.Approval, Kind: "evidence_export", ApparentBytes: observedSize(current[rule.Path]), ExportFileCap: &cap, Retention: rule.LocalRetention, Reasons: []string{"archive deletion disabled; verified independent archive and fresh safety checks required"}}
		if !rule.LocalExpiryEnabled {
			row.Reasons = append(row.Reasons, "local expiry disabled")
		}
		report.Budgets = append(report.Budgets, row)
	}
	if growth.UnknownEntries > 0 {
		report.Unresolved = append(report.Unresolved, "unknown growth requires a complete comparable inventory; unassigned paths need a data owner, not a guessed retention rule")
	}
	report.ActivityHistoryLimit = store.ActivityHistoryLimit
	report.Activities, err = tx.CapacityActivities(ctx)
	if err != nil {
		return report, err
	}
	return report, nil
}
