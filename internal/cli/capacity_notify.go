package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
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

// capacityNotifyVolume is the notifier's view of one volume.
type capacityNotifyVolume struct {
	// Below is whether the last measured sample was below the threshold.
	Below bool `json:"below"`
	// Episode counts the transitions below the threshold.
	Episode int `json:"episode"`
	// NotifiedEpisode is the episode the command last succeeded for.
	NotifiedEpisode int       `json:"notified_episode"`
	LastAttempt     time.Time `json:"last_attempt,omitzero"`
}

// capacityNotifyState is the notifier's persisted state.
type capacityNotifyState struct {
	// SampledAt is the time of the newest sample the state reflects.
	SampledAt time.Time                       `json:"sampled_at,omitzero"`
	Volumes   map[string]capacityNotifyVolume `json:"volumes"`
}

const capacityNotifyStateFile = "capacity-notify.json"

// capacityNotifier runs prevention.notify_command once for each transition
// of a volume below notify_below_bytes: edge-triggered, not on every
// sample. It only reads the samples: the threshold is not a capacity target
// and changes no capacity state or admission hold.
//
// Every published sample updates the transition state at once (publish),
// whatever the command is doing, so a recovery and a new fall below the
// threshold during a run start a new episode. Only delivery is coalesced:
// the notifier goroutine runs the command for each volume below the
// threshold whose current episode has not been notified, unless the last
// attempt was within notify_cooldown (measured in sample time). A success
// marks the episode the run was for, so an episode begun during the run is
// still notified once the cooldown has passed; a failure is retried then
// too. A volume that could not be measured changes nothing. The state
// persists in the state directory after every delivery check, so a
// restarted watcher does not warn again.
type capacityNotifier struct {
	e         *env
	policy    config.Policy
	statePath string
	wake      chan struct{}

	mu     sync.Mutex
	state  capacityNotifyState
	latest map[string]core.CapacityState // newest measurement of each volume
}

// startCapacityNotifier runs the notifier beside the sampler, so capacity
// publication never waits on notify_command. publish applies a sample's
// transitions and wakes the notifier; it never blocks. failed delivers the
// error that ended it (a report that could not be written). stop ends it
// and waits for it; a command in flight is killed with its process group.
func startCapacityNotifier(ctx context.Context, e *env, paths config.Paths, policy config.Policy) (publish func(*core.CapacitySnapshot, time.Time), failed <-chan error, stop func()) {
	n := &capacityNotifier{e: e, policy: policy, statePath: filepath.Join(paths.StateDir, capacityNotifyStateFile),
		wake: make(chan struct{}, 1), latest: map[string]core.CapacityState{}}
	loadErr := readStateJSON(n.statePath, &n.state)
	if n.state.Volumes == nil {
		n.state.Volumes = map[string]capacityNotifyVolume{}
	}
	ctx, cancel := context.WithCancel(ctx)
	errs := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		if loadErr != nil {
			if err := writeWatchReport(e, watchReport{Reason: "capacity_notify", Error: loadErr.Error()}); err != nil {
				errs <- fmt.Errorf("capacity notify report: %w", err)
				return
			}
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-n.wake:
			}
			notify, err := n.deliver(ctx)
			if ctx.Err() != nil {
				return
			}
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
	return n.publish, errs, func() { cancel(); <-finished }
}

// publish applies snapshot, sampled at at, to the transition state and
// wakes the notifier.
func (n *capacityNotifier) publish(snapshot *core.CapacitySnapshot, at time.Time) {
	threshold := uint64(n.policy.Prevention.NotifyBelowBytes)
	n.mu.Lock()
	for _, volume := range snapshot.Volumes {
		if volume.AvailableBytes == nil {
			continue
		}
		current := n.state.Volumes[volume.Key]
		below := *volume.AvailableBytes < threshold
		if below && !current.Below {
			current.Episode++
		}
		current.Below = below
		n.state.Volumes[volume.Key] = current
		n.latest[volume.Key] = volume
	}
	if at.After(n.state.SampledAt) {
		n.state.SampledAt = at
	}
	n.mu.Unlock()
	select {
	case n.wake <- struct{}{}:
	default: // a wake is already pending; it will see this sample
	}
}

// deliver runs the command for the volumes due, records the attempt and
// persists the state. It returns nil when nothing ran.
func (n *capacityNotifier) deliver(ctx context.Context) (*capacityNotifyReport, error) {
	cooldown := n.policy.Prevention.NotifyCooldown.Duration()
	n.mu.Lock()
	now := n.state.SampledAt
	var due []core.CapacityState
	episodes := map[string]int{}
	for key, volume := range n.state.Volumes {
		// A volume known only from the persisted state waits for its first
		// measurement in this run.
		measured, ok := n.latest[key]
		if ok && volume.Below && volume.NotifiedEpisode != volume.Episode && !now.Before(volume.LastAttempt.Add(cooldown)) {
			due = append(due, measured)
			episodes[key] = volume.Episode
		}
	}
	n.mu.Unlock()
	sort.Slice(due, func(i, j int) bool { return due[i].Key < due[j].Key })
	var report *capacityNotifyReport
	if len(due) != 0 {
		report = runCapacityNotify(ctx, n.policy, due)
	}
	n.mu.Lock()
	for key, episode := range episodes {
		volume := n.state.Volumes[key]
		volume.LastAttempt = now
		if report.Error == "" {
			volume.NotifiedEpisode = episode
		}
		n.state.Volumes[key] = volume
	}
	persisted := capacityNotifyState{SampledAt: n.state.SampledAt, Volumes: make(map[string]capacityNotifyVolume, len(n.state.Volumes))}
	for key, volume := range n.state.Volumes {
		persisted.Volumes[key] = volume
	}
	n.mu.Unlock()
	if ctx.Err() != nil {
		return report, nil
	}
	if err := writeStateJSON(n.statePath, persisted); err != nil {
		return report, fmt.Errorf("capacity notify state: %w", err)
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
