package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

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
// of snapshot is first measured below its warning target (target_free_bytes)
// after being at or above it: edge-triggered, not on every sample. Within
// notify_cooldown of the last attempt it waits, so space hovering at the
// target cannot repeat the warning; a failed attempt is retried, while the
// warning lasts, once the cooldown has passed. A volume that could not be
// measured changes nothing. The state persists in the state directory, so a
// restarted watcher does not warn again. It returns nil when nothing ran.
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
		current.Warning = *volume.AvailableBytes < volume.TargetBytes
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

// runCapacityNotify runs the notify command, bounded by notify_timeout,
// with the warning message as its last argument.
func runCapacityNotify(ctx context.Context, policy config.Policy, volumes []core.CapacityState) *capacityNotifyReport {
	message := capacityWarningMessage(volumes)
	command := policy.Prevention.NotifyCommand
	report := &capacityNotifyReport{Command: command, Message: message}
	runCtx, cancel := context.WithTimeout(ctx, policy.Prevention.NotifyTimeout.Duration())
	defer cancel()
	cmd := exec.CommandContext(runCtx, command[0], append(append([]string(nil), command[1:]...), message)...)
	cmd.Dir = "/"
	out, err := cmd.CombinedOutput()
	report.Output = boundedOutput(out)
	if err != nil {
		report.Error = err.Error()
	}
	return report
}

// capacityWarningMessage names each volume below its warning target, in
// decimal GB as the owner's thresholds are written.
func capacityWarningMessage(volumes []core.CapacityState) string {
	host, _ := os.Hostname()
	gb := func(bytes uint64) string { return fmt.Sprintf("%.1f GB", float64(bytes)/1e9) }
	parts := make([]string, 0, len(volumes))
	for _, volume := range volumes {
		roots := append([]string(nil), volume.Roots...)
		sort.Strings(roots)
		parts = append(parts, fmt.Sprintf("%s has %s free, below the %s warning (blocking below %s)",
			strings.Join(roots, ", "), gb(*volume.AvailableBytes), gb(volume.TargetBytes), gb(volume.ReserveBytes)))
	}
	return fmt.Sprintf("workspace-janitor on %s: low disk space: %s", host, strings.Join(parts, "; "))
}
