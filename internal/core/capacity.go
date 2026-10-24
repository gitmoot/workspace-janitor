package core

import "time"

type PressureState string

const (
	PressureRecovered     PressureState = "target_recovered"
	PressureCleanupNeeded PressureState = "cleanup_needed"
	PressureCritical      PressureState = "critical"
	PressureUnknown       PressureState = "measurement_unknown"
	PressureNoSafeReclaim PressureState = "no_safe_reclaim"
)

// CapacityState describes one filesystem, not one inventory root. Available
// bytes are measured with the unprivileged reserve excluded. A hold survives
// recovery above the critical floor until the recovery threshold is reached.
type CapacityState struct {
	Key            string        `json:"filesystem_key"`
	Device         uint64        `json:"device,omitempty"`
	Roots          []string      `json:"roots"`
	State          PressureState `json:"state"`
	AvailableBytes *uint64       `json:"available_bytes"`
	TotalBytes     *uint64       `json:"total_bytes"`
	TargetBytes    uint64        `json:"target_bytes"`
	ReserveBytes   uint64        `json:"reserve_bytes"`
	RecoveryBytes  uint64        `json:"recovery_bytes"`
	AdmissionHold  bool          `json:"admission_hold"`
	Reason         string        `json:"reason"`
}

type CapacitySnapshot struct {
	SampledAt  time.Time       `json:"sampled_at"`
	ValidUntil time.Time       `json:"valid_until"`
	PolicyHash string          `json:"policy_hash"`
	Volumes    []CapacityState `json:"volumes"`
}

// AdvancePressure applies hysteresis to a fresh observation. Unknown samples
// never release an earlier hold, and are themselves a fail-closed hold. This
// state is advisory until an admission consumer enforces it; it never authorizes
// deletion or changes the existing dispatch floor.
func AdvancePressure(current, previous CapacityState) CapacityState {
	if current.AvailableBytes == nil || current.TotalBytes == nil {
		current.State, current.AdmissionHold = PressureUnknown, true
		return current
	}
	available := *current.AvailableBytes
	switch {
	case available < current.ReserveBytes:
		current.State, current.AdmissionHold = PressureCritical, true
		current.Reason = "available space is below the reserve"
	case available < current.TargetBytes || (previous.State != "" && previous.State != PressureRecovered && available < current.RecoveryBytes):
		current.State, current.AdmissionHold = PressureCleanupNeeded, previous.AdmissionHold
		current.Reason = "safe recovery is needed to reach the recovery threshold"
	default:
		current.State, current.AdmissionHold = PressureRecovered, false
		current.Reason = "fresh measurement satisfies the target and hysteresis"
	}
	if previous.State == PressureNoSafeReclaim && current.State != PressureRecovered {
		current.State, current.Reason = previous.State, previous.Reason
		current.AdmissionHold = true
	}
	return current
}

// Expire marks stale observations unknown without changing their durable
// history or pretending that an old available-byte count is current.
func (s CapacitySnapshot) Expire(now time.Time) CapacitySnapshot {
	if now.Before(s.SampledAt) || !now.Before(s.ValidUntil) {
		for i := range s.Volumes {
			s.Volumes[i].State = PressureUnknown
			s.Volumes[i].AvailableBytes, s.Volumes[i].TotalBytes = nil, nil
			s.Volumes[i].AdmissionHold = true
			s.Volumes[i].Reason = "capacity sample is stale; run a cycle or start the watcher"
		}
	}
	return s
}
