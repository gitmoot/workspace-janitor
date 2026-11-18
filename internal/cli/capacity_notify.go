package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

// notifySample is one published capacity sample for the notifier.
type notifySample struct {
	snapshot *core.CapacitySnapshot
	at       time.Time
}

// startCapacityNotifier runs the notifier beside the sampler, so capacity
// publication never waits on notify_command. publish hands it the newest
// sample, replacing one it has not yet taken. failed delivers the error
// that ended it (a report that could not be written). stop ends it and
// waits for it; a command in flight is killed with its process group.
func startCapacityNotifier(ctx context.Context, e *env, paths config.Paths, policy config.Policy) (publish func(*core.CapacitySnapshot, time.Time), failed <-chan error, stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	samples := make(chan notifySample, 1)
	errs := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for {
			var sample notifySample
			select {
			case <-ctx.Done():
				return
			case sample = <-samples:
			}
			notify, err := notifyCapacityWarning(ctx, paths, policy, sample.snapshot, sample.at)
			if notify == nil && err == nil {
				continue
			}
			report := watchReport{Reason: "capacity_notify", Notify: notify}
			if err != nil {
				report.Error = err.Error()
			}
			if err := writeWatchReport(e, report); err != nil {
				errs <- fmt.Errorf("capacity notify report: %w", err)
				return
			}
		}
	}()
	publish = func(snapshot *core.CapacitySnapshot, at time.Time) {
		// Only the sampler publishes, so after dropping a stale pending
		// sample the buffer has room.
		select {
		case <-samples:
		default:
		}
		samples <- notifySample{snapshot, at}
	}
	return publish, errs, func() { cancel(); <-finished }
}

// capacityNotifyReport is one prevention.notify_command run.
type capacityNotifyReport struct {
	Command []string `json:"command"`
	Message string   `json:"message"`
	Output  string   `json:"output,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// capacityNotifyVolume is the notifier's persisted view of one volume.
type capacityNotifyVolume struct {
	// Warning is whether the last measured sample was below the target.
	Warning bool `json:"warning"`
	// Notified is whether the command succeeded for this warning episode.
	Notified    bool      `json:"notified"`
	LastAttempt time.Time `json:"last_attempt,omitzero"`
}

const capacityNotifyStateFile = "capacity-notify.json"

// notifyCapacityWarning runs prevention.notify_command once when a volume
// of snapshot is first measured with fewer than notify_below_bytes available
// after having at least that much: edge-triggered, not on every sample. It
// only reads the sample: the threshold is not a capacity target and changes
// no capacity state or admission hold. Within notify_cooldown of the last
// attempt it waits, so space hovering at the threshold cannot repeat the
// warning; a failed attempt is retried, while space stays below, once the
// cooldown has passed. A volume that could not be measured changes nothing.
// The state persists in the state directory, so a restarted watcher does
// not warn again. It returns nil when nothing ran.
func notifyCapacityWarning(ctx context.Context, paths config.Paths, policy config.Policy, snapshot *core.CapacitySnapshot, now time.Time) (*capacityNotifyReport, error) {
	statePath := filepath.Join(paths.StateDir, capacityNotifyStateFile)
	state := map[string]capacityNotifyVolume{}
	if err := readStateJSON(statePath, &state); err != nil {
		return nil, err
	}
	changed := false
	var due []core.CapacityState
	cooldown := policy.Prevention.NotifyCooldown.Duration()
	for _, volume := range snapshot.Volumes {
		if volume.AvailableBytes == nil {
			continue
		}
		previous := state[volume.Key]
		current := previous
		current.Warning = *volume.AvailableBytes < uint64(policy.Prevention.NotifyBelowBytes)
		if !current.Warning {
			current.Notified = false
		} else if !current.Notified && !now.Before(current.LastAttempt.Add(cooldown)) {
			due = append(due, volume)
		}
		if current != previous {
			state[volume.Key] = current
			changed = true
		}
	}
	var report *capacityNotifyReport
	if len(due) != 0 {
		report = runCapacityNotify(ctx, policy, due)
		for _, volume := range due {
			current := state[volume.Key]
			current.LastAttempt, current.Notified = now, report.Error == ""
			state[volume.Key] = current
		}
		changed = true
	}
	if changed {
		if err := writeStateJSON(statePath, state); err != nil {
			return report, err
		}
	}
	return report, nil
}

// runCapacityNotify runs the notify command, bounded by notify_timeout and
// killed with its whole process group (runNotifyCommand), with the warning
// message as its last argument.
func runCapacityNotify(ctx context.Context, policy config.Policy, volumes []core.CapacityState) *capacityNotifyReport {
	message := capacityWarningMessage(uint64(policy.Prevention.NotifyBelowBytes), volumes)
	command := policy.Prevention.NotifyCommand
	report := &capacityNotifyReport{Command: command, Message: message}
	argv := append(append([]string(nil), command...), message)
	out, err := runNotifyCommand(ctx, argv, policy.Prevention.NotifyTimeout.Duration())
	report.Output = boundedOutput(out)
	if err != nil {
		report.Error = err.Error()
	}
	return report
}

// capacityWarningMessage names each volume below the notify threshold, with
// its capacity warning target and reserve, in decimal GB as the owner's
// thresholds are written.
func capacityWarningMessage(below uint64, volumes []core.CapacityState) string {
	host, _ := os.Hostname()
	gb := func(bytes uint64) string { return fmt.Sprintf("%.1f GB", float64(bytes)/1e9) }
	parts := make([]string, 0, len(volumes))
	for _, volume := range volumes {
		roots := append([]string(nil), volume.Roots...)
		sort.Strings(roots)
		parts = append(parts, fmt.Sprintf("%s has %s free, below %s (warning target %s, blocking below %s)",
			strings.Join(roots, ", "), gb(*volume.AvailableBytes), gb(below), gb(volume.TargetBytes), gb(volume.ReserveBytes)))
	}
	return fmt.Sprintf("workspace-janitor on %s: low disk space: %s", host, strings.Join(parts, "; "))
}
