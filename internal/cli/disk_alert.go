package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/action"
	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/plan"
	"github.com/gitmoot/workspace-janitor/internal/safety"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

type diskAlert struct {
	Device           uint64   `json:"device"`
	Roots            []string `json:"roots"`
	FreeBytes        uint64   `json:"free_bytes"`
	TotalBytes       uint64   `json:"total_bytes"`
	FreePercent      float64  `json:"free_percent"`
	ReclaimableBytes *int64   `json:"potential_reclaimable_bytes"`
	ProtectedBytes   *int64   `json:"protected_bytes"`
	UnknownBytes     *int64   `json:"unknown_bytes"`
	UnmeasuredGroups []string `json:"unmeasured_groups,omitempty"`
}

// reportDiskPressure emits conservative physical-byte estimates only when a
// configured threshold is crossed. An incomplete traversal is null, not zero.
// SQLite serializes the cooldown claim across restarts and competing cycles.
func reportDiskPressure(ctx context.Context, policy config.Policy, paths config.Paths, scanID string, now time.Time) ([]diskAlert, error) {
	if policy.Prevention.MinFreeBytes == 0 && policy.Prevention.MinFreePercent == 0 {
		return []diskAlert{}, nil
	}
	db, err := store.OpenExisting(ctx, paths.DatabaseFile)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var entries []core.Entry
	var scan core.Scan
	if err := db.Read(ctx, func(tx *store.Tx) error {
		var err error
		scan, err = tx.Scan(ctx, scanID)
		if err != nil {
			return err
		}
		entries, err = tx.Entries(ctx, scanID)
		return err
	}); err != nil {
		return nil, err
	}
	// Inventory roots may overlap. Account a selected subtree once; when
	// nested selections exist, call the containing tree unknown instead of
	// reporting its descendants as independently reclaimable.
	byPath := make(map[string]uint64, len(entries))
	for _, entry := range entries {
		byPath[entry.Path] = entry.FilesystemID.Device
	}
	covered := make(map[string]bool)
	containsSelection := make(map[string]bool)
	for _, entry := range entries {
		for parent := filepath.Dir(entry.Path); parent != entry.Path; parent = filepath.Dir(parent) {
			if device, ok := byPath[parent]; ok && device == entry.FilesystemID.Device {
				covered[entry.Path] = true
				containsSelection[parent] = true
			}
			if parent == filepath.Dir(parent) {
				break
			}
		}
	}
	incomplete := false
	for _, report := range scan.Collectors {
		switch report.Name {
		case collect.CollectorFilesystem, collect.CollectorGit, collect.CollectorProcesses, collect.CollectorServices:
			incomplete = incomplete || report.Status != core.CollectorRan
		default:
			incomplete = incomplete || report.Status == core.CollectorPartial || report.Status == core.CollectorFailed
		}
	}
	volumes := make(map[uint64]*diskAlert)
	for _, root := range policy.Roots {
		volume, err := measureDisk(root.Path)
		if err != nil {
			return nil, fmt.Errorf("disk pressure unknown for %s: %w", root.Path, err)
		}
		alert := volumes[volume.Device]
		if alert == nil {
			percent := 100 * float64(volume.FreeBytes) / float64(volume.TotalBytes)
			alert = &diskAlert{Device: volume.Device, FreeBytes: volume.FreeBytes,
				TotalBytes: volume.TotalBytes, FreePercent: percent}
			volumes[volume.Device] = alert
		}
		alert.Roots = append(alert.Roots, root.Path)
	}
	ids := make([]uint64, 0, len(volumes))
	for id := range volumes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	var emitted []diskAlert
	for _, id := range ids {
		alert := volumes[id]
		sort.Strings(alert.Roots)
		if !(policy.Prevention.MinFreeBytes > 0 && alert.FreeBytes < uint64(policy.Prevention.MinFreeBytes) ||
			policy.Prevention.MinFreePercent > 0 && alert.FreePercent < float64(policy.Prevention.MinFreePercent)) {
			continue
		}
		var reclaimable, protected, unknown []core.Entry
		target := safety.ResolveTarget(policy.Retention.QuarantineDir)
		for _, entry := range entries {
			if entry.FilesystemID.Device != id || covered[entry.Path] {
				continue
			}
			uncertain := incomplete || containsSelection[entry.Path] || entry.FilesystemID.Inode == 0
			for _, evidence := range entry.Evidence {
				uncertain = uncertain || strings.HasPrefix(evidence.Signal, "unknown:")
			}
			if uncertain {
				unknown = append(unknown, entry)
				continue
			}
			verdict := safety.Evaluate(safety.Input{Entry: entry, Policy: enginePolicy(paths, policy), Target: &target, Now: now})
			if entry.Protected() || verdict.Refused() {
				protected = append(protected, entry)
				continue
			}
			decision := plan.Evaluate(entry, policy, verdict)
			if decision.Kind == core.ActionQuarantine || decision.Kind == core.ActionDeleteCandidate {
				reclaimable = append(reclaimable, entry)
			} else {
				unknown = append(unknown, entry)
			}
		}
		for _, group := range []struct {
			name    string
			entries []core.Entry
			bytes   **int64
		}{
			{"reclaimable", reclaimable, &alert.ReclaimableBytes},
			{"protected", protected, &alert.ProtectedBytes},
			{"unknown", unknown, &alert.UnknownBytes},
		} {
			estimate, err := action.EstimateReclaim(ctx, group.entries, policy.Limits.DeepSizeMaxEntries)
			if err != nil {
				alert.UnmeasuredGroups = append(alert.UnmeasuredGroups, group.name)
				continue
			}
			bytes := estimate.Bytes
			*group.bytes = &bytes
		}
		summary, err := json.Marshal(alert)
		if err != nil {
			return nil, err
		}
		var claimed bool
		if err := db.Write(ctx, func(tx *store.Tx) error {
			var err error
			claimed, err = tx.ClaimDiskAlert(ctx, fmt.Sprintf("%d", id), string(summary), now, policy.Prevention.AlertInterval.Duration())
			return err
		}); err != nil {
			return nil, err
		}
		if claimed {
			emitted = append(emitted, *alert)
		}
	}
	return emitted, nil
}
