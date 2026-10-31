package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

func capacityPolicyHash(policy config.Policy) string {
	data, _ := json.Marshal(struct {
		Targets  []config.CapacityTarget
		Interval config.Duration
	}{policy.Prevention.Targets, policy.Prevention.CapacityInterval})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// sampleCapacity serializes the due check and measurement in the existing
// SQLite writer transaction. Concurrent cycles/watchers share one bounded
// sample, including failures; a restart does not reset hysteresis or cooldown.
func sampleCapacity(ctx context.Context, policy config.Policy, paths config.Paths, now time.Time, force bool) (*core.CapacitySnapshot, error) {
	if len(policy.Prevention.Targets) == 0 {
		return nil, nil
	}
	db, err := store.OpenExisting(ctx, paths.DatabaseFile)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	hash := capacityPolicyHash(policy)
	interval := policy.Prevention.CapacityInterval.Duration()
	var snapshot core.CapacitySnapshot
	err = db.Write(ctx, func(tx *store.Tx) error {
		previous, err := tx.CapacitySnapshot(ctx)
		if err != nil {
			return err
		}
		if now.Before(previous.SampledAt) {
			snapshot = *unknownCapacity(policy, "sampling time precedes the newest stored sample")
			return nil
		}
		if !force && previous.PolicyHash == hash && !now.Before(previous.SampledAt) && now.Before(previous.SampledAt.Add(interval)) {
			snapshot = previous
			return nil
		}
		previous = previous.Expire(now)
		byKey := make(map[string]core.CapacityState, len(previous.Volumes))
		byRoot := make(map[string]string)
		for _, volume := range previous.Volumes {
			byKey[volume.Key] = volume
			for _, root := range volume.Roots {
				byRoot[root] = volume.Key
			}
		}
		volumes := make(map[string]*core.CapacityState, len(policy.Prevention.Targets))
		for _, target := range policy.Prevention.Targets {
			if err := ctx.Err(); err != nil {
				return err
			}
			measured, measureErr := measureDisk(target.Path)
			key := fmt.Sprintf("device:%d", measured.Device)
			if measureErr != nil {
				key = byRoot[target.Path]
				if key == "" {
					key = "root:" + target.Path
				}
				measured.Device = byKey[key].Device
			}
			volume := volumes[key]
			if volume == nil {
				volume = &core.CapacityState{Key: key, Device: measured.Device}
				volumes[key] = volume
			}
			volume.Roots = append(volume.Roots, target.Path)
			reserve := uint64(target.ReserveFreeBytes)
			goal := uint64(target.TargetFreeBytes)
			if reserve > goal {
				goal = reserve
			}
			recovery := goal + uint64(target.RecoveryMarginBytes)
			if target.RecoveryMarginBytes == 0 {
				recovery = reserve
			}
			if goal > volume.TargetBytes {
				volume.TargetBytes = goal
			}
			if reserve > volume.ReserveBytes {
				volume.ReserveBytes = reserve
			}
			if recovery > volume.RecoveryBytes {
				volume.RecoveryBytes = recovery
			}
			if measureErr != nil {
				volume.Reason = fmt.Sprintf("cannot measure %s: %v", target.Path, measureErr)
				volume.AvailableBytes, volume.TotalBytes = nil, nil
				continue
			}
			if volume.Reason != "" {
				continue
			}
			if volume.TotalBytes != nil && *volume.TotalBytes != measured.TotalBytes {
				volume.Reason = "filesystem capacity changed during the sample"
				volume.AvailableBytes, volume.TotalBytes = nil, nil
				continue
			}
			if volume.TotalBytes == nil {
				volume.AvailableBytes, volume.TotalBytes = &measured.FreeBytes, &measured.TotalBytes
			} else if measured.FreeBytes < *volume.AvailableBytes {
				*volume.AvailableBytes = measured.FreeBytes
			}
		}
		snapshot = core.CapacitySnapshot{SampledAt: now.UTC(), ValidUntil: now.Add(2 * interval).UTC(), PolicyHash: hash,
			Volumes: make([]core.CapacityState, 0, len(volumes))}
		for _, volume := range volumes {
			sort.Strings(volume.Roots)
			snapshot.Volumes = append(snapshot.Volumes, core.AdvancePressure(*volume, byKey[volume.Key]))
		}
		sort.Slice(snapshot.Volumes, func(i, j int) bool { return snapshot.Volumes[i].Key < snapshot.Volumes[j].Key })
		return tx.SaveCapacitySnapshot(ctx, snapshot)
	})
	if err != nil {
		return nil, err
	}
	return &snapshot, nil
}

func unknownCapacity(policy config.Policy, reason string) *core.CapacitySnapshot {
	if len(policy.Prevention.Targets) == 0 {
		return nil
	}
	snapshot := &core.CapacitySnapshot{PolicyHash: capacityPolicyHash(policy)}
	for _, target := range policy.Prevention.Targets {
		recovery := uint64(target.TargetFreeBytes + target.RecoveryMarginBytes)
		if target.RecoveryMarginBytes == 0 {
			recovery = uint64(target.ReserveFreeBytes)
		}
		snapshot.Volumes = append(snapshot.Volumes, core.CapacityState{
			Key: "root:" + target.Path, Roots: []string{target.Path}, State: core.PressureUnknown,
			AdmissionHold: true, Reason: reason, TargetBytes: uint64(target.TargetFreeBytes),
			ReserveBytes:  uint64(target.ReserveFreeBytes),
			RecoveryBytes: recovery,
		})
	}
	return snapshot
}
