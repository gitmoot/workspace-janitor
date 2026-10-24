package cli

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/store"
	"github.com/google/uuid"
)

type activityMonitor struct {
	db         *store.Store
	samplePath string
	activity   core.CapacityActivity
}

func activityVolume(path string) (diskVolume, error) {
	for {
		volume, err := measureDisk(path)
		if err == nil || !os.IsNotExist(err) {
			return volume, err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return volume, err
		}
		path = parent
	}
}

func startCapacityActivity(ctx context.Context, db *store.Store, kind, receipt, path, owner, samplePath string) (*activityMonitor, error) {
	monitor := &activityMonitor{db: db, samplePath: samplePath, activity: core.CapacityActivity{
		ID: uuid.NewString(), Kind: kind, State: "starting", ReceiptID: receipt,
		Path: path, Owner: owner, StartedAt: time.Now().UTC(), Errors: []string{},
		Attribution: "Available-byte change is an actual filesystem observation, not attributable recovery: concurrent writers and delayed allocation/freeing may contribute. Store reduction is allocated namespace footprint, not proof of returned filesystem blocks. Null means unknown. Reporting history does not authorize replay or deletion.",
	}}
	before, err := activityVolume(samplePath)
	if err != nil {
		monitor.activity.MeasurementError = err.Error()
	} else {
		monitor.activity.Device = before.Device
		monitor.activity.AvailableBeforeBytes = &before.FreeBytes
	}
	if err := db.Write(ctx, func(tx *store.Tx) error { return tx.RecordCapacityActivity(ctx, monitor.activity) }); err != nil {
		return nil, err
	}
	return monitor, nil
}

func (m *activityMonitor) finish(ctx context.Context, operationErr error) error {
	now := time.Now().UTC()
	m.activity.FinishedAt = &now
	m.activity.State = "completed"
	if operationErr != nil {
		m.activity.State = "failed"
		if m.activity.Completed > 0 {
			m.activity.State = "partial"
		}
		message := operationErr.Error()
		if len(message) > 2048 {
			message = message[:2048]
		}
		m.activity.Errors = append(m.activity.Errors, message)
	}
	// Outcome recording must survive cancellation of the operation, but must
	// not keep a cancelled command alive indefinitely.
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	after, err := activityVolume(m.samplePath)
	if err != nil {
		m.activity.MeasurementError = err.Error()
	} else if m.activity.AvailableBeforeBytes == nil || after.Device != m.activity.Device {
		m.activity.MeasurementError = "before/after filesystem observations are not comparable"
	} else {
		m.activity.AvailableAfterBytes = &after.FreeBytes
		if after.FreeBytes <= math.MaxInt64 && *m.activity.AvailableBeforeBytes <= math.MaxInt64 {
			delta := int64(after.FreeBytes) - int64(*m.activity.AvailableBeforeBytes)
			m.activity.AvailableChangeBytes = &delta
		}
	}
	if m.activity.Kind == "quarantine" || m.activity.Kind == "verified_archive" || m.activity.Kind == "archive_restore" {
		zero := int64(0)
		m.activity.ActualReclaimedBytes = &zero
	}
	if m.activity.StoreBeforeBytes != nil && m.activity.StoreAfterBytes != nil {
		delta := *m.activity.StoreBeforeBytes - *m.activity.StoreAfterBytes
		m.activity.StoreRemovedBytes = &delta
	}
	recordErr := m.db.Write(bounded, func(tx *store.Tx) error { return tx.RecordCapacityActivity(bounded, m.activity) })
	return errors.Join(operationErr, recordErr)
}

func recordRecoveryDecision(ctx context.Context, db *store.Store, report *recoveryReport, started time.Time, operationErr error) error {
	now := time.Now().UTC()
	activity := core.CapacityActivity{
		ID: uuid.NewString(), Kind: "recovery_decision", State: "completed",
		StartedAt: started, FinishedAt: &now, StopReason: report.Stopped,
		Skipped: report.Skipped[:min(len(report.Skipped), 8)], Errors: []string{},
		Attribution: "Decision summary only; individual operation receipts carry measured effects. No new deletion or job-admission authority.",
	}
	activity.SkippedOmitted = len(report.Skipped) - len(activity.Skipped)
	if operationErr != nil {
		activity.State = "failed"
		message := operationErr.Error()
		if len(message) > 2048 {
			message = message[:2048]
		}
		activity.Errors = append(activity.Errors, message)
	}
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	return db.Write(bounded, func(tx *store.Tx) error { return tx.RecordCapacityActivity(bounded, activity) })
}
