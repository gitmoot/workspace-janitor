package core

import "time"

// CapacityActivity is bounded reporting evidence, not cleanup authorization.
// Cleanup receipts and provider journals remain the authoritative audit trail.
type CapacityActivity struct {
	ID                    string         `json:"id"`
	Kind                  string         `json:"kind"`
	State                 string         `json:"state"`
	StartedAt             time.Time      `json:"started_at"`
	FinishedAt            *time.Time     `json:"finished_at"`
	ReceiptID             string         `json:"receipt_id,omitempty"`
	Path                  string         `json:"path,omitempty"`
	Owner                 string         `json:"decision_owner,omitempty"`
	Attempted             int            `json:"attempted"`
	Completed             int            `json:"completed"`
	Replayed              int            `json:"replayed"`
	EstimatedReclaimBytes *int64         `json:"estimated_reclaim_bytes"`
	ActualReclaimedBytes  *int64         `json:"actual_reclaimed_bytes"`
	StoreBeforeBytes      *int64         `json:"store_before_allocated_bytes"`
	StoreAfterBytes       *int64         `json:"store_after_allocated_bytes"`
	StoreRemovedBytes     *int64         `json:"store_removed_allocated_bytes"`
	Device                uint64         `json:"device,omitempty"`
	AvailableBeforeBytes  *uint64        `json:"available_before_bytes"`
	AvailableAfterBytes   *uint64        `json:"available_after_bytes"`
	AvailableChangeBytes  *int64         `json:"available_change_bytes"`
	MeasurementError      string         `json:"measurement_error,omitempty"`
	Errors                []string       `json:"errors"`
	Attribution           string         `json:"attribution"`
	StopReason            string         `json:"stop_reason,omitempty"`
	Skipped               []CapacitySkip `json:"skipped,omitempty"`
	SkippedOmitted        int            `json:"skipped_omitted,omitempty"`
}

type CapacitySkip struct {
	Path   string `json:"path"`
	Owner  string `json:"owner"`
	Reason string `json:"reason"`
}
