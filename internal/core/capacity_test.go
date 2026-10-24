package core

import (
	"testing"
	"time"
)

func TestPressureHysteresisAndUnknownRecovery(t *testing.T) {
	total := uint64(1000)
	previous := CapacityState{}
	for _, step := range []struct {
		available *uint64
		state     PressureState
		hold      bool
	}{
		{capacityBytes(100), PressureRecovered, false},
		{capacityBytes(99), PressureCleanupNeeded, false},
		{capacityBytes(100), PressureCleanupNeeded, false},
		{capacityBytes(119), PressureCleanupNeeded, false},
		{capacityBytes(120), PressureRecovered, false},
		{capacityBytes(19), PressureCritical, true},
		{capacityBytes(20), PressureCleanupNeeded, true},
		{capacityBytes(100), PressureCleanupNeeded, true},
		{nil, PressureUnknown, true},
		{capacityBytes(119), PressureCleanupNeeded, true},
		{capacityBytes(120), PressureRecovered, false},
	} {
		current := AdvancePressure(CapacityState{AvailableBytes: step.available, TotalBytes: &total, TargetBytes: 100, ReserveBytes: 20, RecoveryBytes: 120}, previous)
		if current.State != step.state || current.AdmissionHold != step.hold {
			t.Fatalf("from %s with %v: state=%s hold=%t; want %s hold=%t", previous.State, step.available, current.State, current.AdmissionHold, step.state, step.hold)
		}
		previous = current
	}
}

func TestCapacityStalenessNeverLooksRecovered(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, at := range []time.Time{now.Add(-time.Nanosecond), now.Add(time.Minute), now.Add(time.Hour)} {
		snapshot := CapacitySnapshot{SampledAt: now, ValidUntil: now.Add(time.Minute), Volumes: []CapacityState{{State: PressureRecovered, AvailableBytes: capacityBytes(200), TotalBytes: capacityBytes(1000)}}}
		expired := snapshot.Expire(at)
		volume := expired.Volumes[0]
		if volume.State != PressureUnknown || !volume.AdmissionHold || volume.AvailableBytes != nil || volume.TotalBytes != nil {
			t.Fatalf("stale or reversed clock exposed health: %+v", volume)
		}
	}
}

func TestNoSafeReclaimRemainsHeldUntilRecovery(t *testing.T) {
	previous := CapacityState{State: "no_safe_reclaim", AdmissionHold: true, Reason: "approved candidates exhausted"}
	for _, available := range []uint64{10, 90, 110, 120} {
		current := AdvancePressure(CapacityState{AvailableBytes: capacityBytes(available), TotalBytes: capacityBytes(1000), TargetBytes: 100, ReserveBytes: 20, RecoveryBytes: 120}, previous)
		if available < 120 {
			if current.State != "no_safe_reclaim" || !current.AdmissionHold || current.Reason != previous.Reason {
				t.Fatalf("shortfall lost its hold or explanation: %+v", current)
			}
		} else if current.State != PressureRecovered || current.AdmissionHold {
			t.Fatalf("verified recovery did not release hold: %+v", current)
		}
		previous = current
	}
}

func capacityBytes(n uint64) *uint64 { return &n }
