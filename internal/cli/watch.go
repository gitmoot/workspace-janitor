package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/plan"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

// In-place changes in known protected directories do not change the top-level
// inventory. Reconcile them hourly so reference evidence never stays stale
// indefinitely, without persisting a scan for each operational state write.
const watchChurnInterval = time.Hour

// watchChangeGap is the minimum time between full reconciliation scans that
// ordinary changes trigger. Changes inside the gap are coalesced into one
// scan when it ends. A full scan of every root costs ~25 CPU-seconds on the
// live host; one path rewritten every ~30 s made the watcher use 0.7 of a
// core (live 2026-11-05). The watcher never acts on its scans, so a fresher
// inventory buys nothing a few minutes' delay loses.
var watchChangeGap = 5 * time.Minute

// watchReport describes a persisted inventory reconciliation or a deferred
// incomplete observation. It never authorizes a filesystem action.
type watchReport struct {
	Reason          string                 `json:"reason"`
	ScanID          string                 `json:"scan_id"`
	Paths           []watchGuidance        `json:"paths"`
	Reconciled      bool                   `json:"reconciled"`
	Incomplete      bool                   `json:"incomplete"`
	DeferredEvents  uint64                 `json:"deferred_events,omitempty"`
	NextReconcileAt *time.Time             `json:"next_reconcile_at,omitempty"`
	DiskAlerts      []diskAlert            `json:"disk_alerts,omitempty"`
	Capacity        *core.CapacitySnapshot `json:"capacity,omitempty"`
	CacheTrims      []cacheTrimReport      `json:"cache_trims,omitempty"`
	Error           string                 `json:"error,omitempty"`
}

type watchGuidance struct {
	Path              string             `json:"path"`
	Class             core.ArtifactClass `json:"class,omitempty"`
	ObservedAbsent    bool               `json:"observed_absent,omitempty"`
	New               bool               `json:"new,omitempty"`
	Unknown           bool               `json:"unknown,omitempty"`
	CanonicalLocation string             `json:"canonical_location,omitempty"`
}

func runWatch(ctx context.Context, e *env, args []string) error {
	if len(args) != 0 {
		return &usageError{msg: "watch takes no arguments"}
	}
	paths, err := e.resolvePaths()
	if err != nil {
		return err
	}
	policy, err := e.loadPolicy(ctx)
	if err != nil {
		return err
	}
	if len(policy.Roots) == 0 {
		return errors.New("watch requires at least one configured root")
	}
	roots := make([]string, 0, len(policy.Roots))
	seen := make(map[string]bool, len(policy.Roots))
	for _, root := range policy.Roots {
		if !seen[root.Path] {
			roots = append(roots, root.Path)
			seen[root.Path] = true
		}
	}
	return watchLoop(ctx, e, paths, policy, func() (eventWatcher, error) {
		return openTopWatcher(roots)
	}, watchChurnInterval)
}

type eventWatcher interface {
	next(context.Context) (watchEvent, error)
	close() error
}

func watchLoop(ctx context.Context, e *env, paths config.Paths, policy config.Policy,
	open func() (eventWatcher, error), churnInterval time.Duration) (err error) {
	// A stop request (SIGTERM) cancels whatever reconcile or sample is in
	// flight. That cancellation is a clean shutdown, not a watcher failure;
	// any other error still ends the watcher with that error.
	stopping := ctx
	defer func() {
		if stopping.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			err = nil
		}
	}()
	// Capacity sampling needs only the database, never the scan lock that a
	// daily cycle holds through apply. It runs on its own so a long cycle or a
	// slow reconcile cannot let the published sample go stale (live
	// 2026-11-02: a 12-minute cycle starved sampling and Gitmoot refused all
	// new reviews on a measurement_unknown hold). Reports share one writer.
	quiet := *e
	quiet.stdout = &lockedWriter{w: e.stdout}
	e = &quiet
	sampling := make(chan struct{})
	if len(policy.Prevention.Targets) > 0 {
		// Sampling needs an initialized database. Create or migrate it here,
		// without the scan lock, so a cycle holding that lock on a fresh
		// installation cannot make the first sample fail.
		db, openErr := store.Open(ctx, paths.DatabaseFile)
		if openErr != nil {
			return openErr
		}
		if closeErr := db.Close(); closeErr != nil {
			return closeErr
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		// A sampler failure is recorded here, apart from the parent context,
		// so a normal signal-driven shutdown keeps its successful exit status.
		var samplerErr error
		// The goroutine gets its own copy of ctx: watchLoop reassigns the
		// variable below when it starts the trim loop.
		go func(ctx context.Context) {
			defer close(sampling)
			if samplerErr = sampleCapacityLoop(ctx, e, paths, policy); samplerErr != nil {
				cancel()
			}
		}(ctx)
		defer func() {
			cancel()
			<-sampling
			// The main loop then fails with the resulting cancellation;
			// report the cause instead.
			if samplerErr != nil && (err == nil || errors.Is(err, context.Canceled)) {
				err = samplerErr
			}
		}()
	} else {
		close(sampling)
	}
	if len(policy.Prevention.CacheTrims) > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		trimming := make(chan struct{})
		// Like a sampler failure, a lost trim report ends the watcher with
		// that error instead of a clean exit.
		var trimErr error
		go func(ctx context.Context) {
			defer close(trimming)
			if trimErr = cacheTrimLoop(ctx, e, paths, policy); trimErr != nil {
				cancel()
			}
		}(ctx)
		defer func() {
			cancel()
			<-trimming
			if trimErr != nil && (err == nil || errors.Is(err, context.Canceled)) {
				err = trimErr
			}
		}()
	}
	watcher, err := open()
	if err != nil {
		return err
	}
	defer func() { _ = watcher.close() }()
	// Snapshot protected directory identities before the startup scan. Events
	// queued during reconciliation still expose new, removed or replaced paths.
	protected := newProtectedWatchDirs(policy)
	if err := reconcileWatch(ctx, e, paths, policy, "startup", nil, true, 0); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	pendingSettle := map[string]bool{}
	var settleAt, churnAt time.Time
	var deferred uint64
	// Changes held back by watchChangeGap, and when they are due.
	pendingChanged := map[string]bool{}
	pendingOverflow := false
	var changeAt, lastScan time.Time
	lastScan = time.Now()
	// fullScan runs one full reconciliation. Every full scan also carries
	// the change work held back by watchChangeGap, including a pending
	// overflow, so an intervening settle or churn scan cannot persist new
	// paths without reporting them (review of #160). It then schedules the
	// settle revisit of directories it saw.
	fullScan := func(reason string, extra map[string]bool, overflow bool) error {
		changed := make(map[string]bool, len(extra)+len(pendingChanged))
		for path := range extra {
			changed[path] = true
		}
		for path := range pendingChanged {
			changed[path] = true
		}
		if err := reconcileWatch(ctx, e, paths, policy, reason, changed, overflow || pendingOverflow, deferred); err != nil {
			return err
		}
		lastScan = time.Now()
		churnAt, deferred = time.Time{}, 0
		// A direct clone first creates an empty directory and fills .git
		// below our top-level watch. Revisit newly seen directories after
		// they settle; the watcher itself never acts on them.
		for path := range pendingChanged {
			if info, err := os.Lstat(path); err == nil && info.IsDir() {
				pendingSettle[path] = true
				settleAt = time.Now().Add(2 * time.Second)
			}
		}
		pendingChanged, pendingOverflow, changeAt = map[string]bool{}, false, time.Time{}
		return nil
	}
	scanChanges := func() error { return fullScan("change", nil, false) }
	for {
		deadline := settleAt
		for _, at := range []time.Time{churnAt, changeAt} {
			if !at.IsZero() && (deadline.IsZero() || at.Before(deadline)) {
				deadline = at
			}
		}
		eventCtx := ctx
		cancelWait := func() {}
		if !deadline.IsZero() {
			eventCtx, cancelWait = context.WithDeadline(ctx, deadline)
		}
		first, err := watcher.next(eventCtx)
		cancelWait()
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			now := time.Now()
			if !changeAt.IsZero() && !now.Before(changeAt) {
				if err := scanChanges(); err != nil {
					return err
				}
			} else if !settleAt.IsZero() && !now.Before(settleAt) {
				// Settling is a full scan too; it satisfies any deferred churn
				// and any held-back change work.
				settling := pendingSettle
				pendingSettle, settleAt = map[string]bool{}, time.Time{}
				if err := fullScan("settled", settling, false); err != nil {
					return err
				}
			} else if !churnAt.IsZero() && !now.Before(churnAt) {
				// Full reconciliation recovers even a top-level event lost
				// during protected churn or an inotify overflow.
				if err := fullScan("churn", nil, true); err != nil {
					return err
				}
			}
			continue
		}
		if errors.Is(err, context.Canceled) {
			return nil
		}
		if err != nil {
			return err
		}
		var changed map[string]bool
		add := func(event watchEvent) error {
			if event.Name == "" {
				return nil
			}
			path := filepath.Join(event.Root, event.Name)
			if !event.Overflow && protected.suppress(path) {
				if deferred < ^uint64(0) {
					deferred++
				}
				if churnAt.IsZero() {
					churnAt = time.Now().Add(churnInterval)
					if err := emitDeferredWatch(e, churnAt); err != nil {
						return err
					}
				}
				return nil
			}
			if changed == nil {
				changed = make(map[string]bool)
			}
			changed[path] = true
			return nil
		}
		overflow := first.Overflow
		if err := add(first); err != nil {
			return err
		}
		// One bounded burst produces one complete snapshot, never a partial
		// child-only snapshot that could become the planner's latest scan.
		burst, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
		for !overflow {
			event, err := watcher.next(burst)
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
					break
				}
				cancel()
				return err
			}
			overflow = event.Overflow
			if err := add(event); err != nil {
				cancel()
				return err
			}
		}
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if overflow {
			// Re-arm before reconciliation: changes during the scan stay
			// queued rather than falling into an unobserved gap.
			_ = watcher.close()
			rearmed, openErr := open()
			if openErr != nil {
				return errors.Join(openErr, reconcileWatch(ctx, e, paths, policy, "change", changed, true, deferred))
			}
			watcher = rearmed
			protected = newProtectedWatchDirs(policy)
		}
		if !overflow && len(changed) == 0 {
			continue
		}
		for path := range changed {
			pendingChanged[path] = true
		}
		pendingOverflow = pendingOverflow || overflow
		if due := lastScan.Add(watchChangeGap); time.Now().Before(due) {
			if changeAt.IsZero() {
				changeAt = due
			}
			continue
		}
		if err := scanChanges(); err != nil {
			return err
		}
	}
}

// sampleCapacityLoop publishes a capacity sample every capacity_interval.
// Each attempt runs apart from the loop and is bounded by the interval, so a
// store write or measurement that hangs cannot hold the loop. A failed
// attempt is reported and retried next interval. The loop watches its own
// published sample: once the newest one is past valid_until (live
// 2026-11-04: a host thrashing on swap stalled sampling 16 minutes while
// the watcher looked healthy), it reports reason capacity_stale and returns
// an error, so the watcher exits and its supervisor restarts it.
func sampleCapacityLoop(ctx context.Context, e *env, paths config.Paths, policy config.Policy) error {
	interval := policy.Prevention.CapacityInterval.Duration()
	timer := time.NewTimer(0)
	defer timer.Stop()
	// Until a first sample succeeds, allow one validity window from start.
	validUntil := time.Now().Add(2 * interval)
	type attempt struct {
		capacity *core.CapacitySnapshot
		err      error
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
		now := time.Now().UTC()
		attemptCtx, cancel := context.WithTimeout(ctx, interval)
		done := make(chan attempt, 1)
		go func() {
			capacity, err := sampleCapacity(attemptCtx, policy, paths, now, false)
			done <- attempt{capacity, err}
		}()
		stale := time.NewTimer(time.Until(validUntil))
		var result attempt
		select {
		case result = <-done:
		case <-stale.C:
			result.err = errCapacityStale
		case <-ctx.Done():
		}
		stale.Stop()
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if result.err == nil {
			if err := writeWatchReport(e, watchReport{Reason: "capacity", Capacity: result.capacity}); err != nil {
				return err
			}
			if result.capacity != nil {
				validUntil = result.capacity.ValidUntil
			}
		} else if !time.Now().Before(validUntil) {
			staleErr := fmt.Errorf("capacity sample stale since %s: %w", validUntil.UTC().Format(time.RFC3339), result.err)
			if err := writeWatchReport(e, watchReport{Reason: "capacity_stale", Error: staleErr.Error()}); err != nil {
				return errors.Join(staleErr, err)
			}
			return staleErr
		} else if err := writeWatchReport(e, watchReport{Reason: "capacity", Error: "capacity sample failed: " + result.err.Error()}); err != nil {
			return err
		}
		timer.Reset(time.Until(now.Add(interval)))
	}
}

// errCapacityStale marks an attempt still unfinished when the published
// sample expired.
var errCapacityStale = errors.New("sampling attempt did not finish")

// lockedWriter serializes whole report lines from concurrent writers.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// Only explicitly protected directories immediately below a watched root
// qualify. Missing paths are tracked so their creation cannot be suppressed.
type protectedWatchDirs map[string]os.FileInfo

func newProtectedWatchDirs(policy config.Policy) protectedWatchDirs {
	roots := make(map[string]bool, len(policy.Roots))
	for _, root := range policy.Roots {
		roots[root.Path] = true
	}
	dirs := make(protectedWatchDirs)
	for _, path := range policy.Protect.Paths {
		if !roots[filepath.Dir(path)] {
			continue
		}
		if info, err := os.Lstat(path); err == nil && info.IsDir() {
			dirs[path] = info
		} else {
			dirs[path] = nil
		}
	}
	return dirs
}

func (dirs protectedWatchDirs) suppress(path string) bool {
	prior, tracked := dirs[path]
	if !tracked {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() {
		dirs[path] = nil
		return false
	}
	dirs[path] = info
	return prior != nil && os.SameFile(prior, info) && prior.Mode() == info.Mode()
}

func emitDeferredWatch(e *env, due time.Time) error {
	encoded, err := json.Marshal(watchReport{
		Reason: "deferred", Paths: []watchGuidance{}, Incomplete: true,
		DeferredEvents: 1, NextReconcileAt: &due,
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(e.stdout, string(encoded))
	return err
}

func reconcileWatch(ctx context.Context, e *env, paths config.Paths, policy config.Policy,
	reason string, changed map[string]bool, overflow bool, deferred uint64) error {
	quiet := *e
	quiet.stdout = io.Discard
	// Category archive pins live in Janitor's state and change between
	// cycles; the policy file itself is still read once per watcher.
	if e.filePolicy != nil && e.filePolicy.HasArchiveCategories() {
		refreshed, err := withCategoryArchives(ctx, paths, *e.filePolicy)
		if err != nil {
			return err
		}
		quiet.policy = &refreshed
	}
	// Background inventory is local and rules-only; neither planning nor
	// Jev nor an action engine is invoked by this path.
	var scanID string
	// A scheduled cycle holds this lock from its scan through its quarantine
	// apply; scanning in between would make that apply refuse its plan.
	unlockScan, err := lockScan(ctx, paths.StateDir)
	if err != nil {
		return err
	}
	err = runScan(ctx, &quiet, nil, scanOptions{noDeepSize: true, recordScanID: &scanID})
	unlockScan()
	if err != nil {
		return err
	}
	db, err := store.OpenReadOnly(ctx, paths.DatabaseFile)
	if err != nil {
		return err
	}
	defer db.Close()
	var scan core.Scan
	var entries []core.Entry
	err = db.Read(ctx, func(tx *store.Tx) error {
		var err error
		scan, err = tx.Scan(ctx, scanID)
		if err != nil {
			return err
		}
		entries, err = tx.Entries(ctx, scan.ID)
		return err
	})
	if err != nil {
		return err
	}
	report := watchReport{Reason: reason, ScanID: scan.ID, Reconciled: overflow,
		Paths: []watchGuidance{}, DeferredEvents: deferred}
	report.Capacity, err = sampleCapacity(ctx, policy, paths, time.Now().UTC(), false)
	if err != nil {
		return err
	}
	alerts, err := reportDiskPressure(ctx, policy, paths, scan.ID, time.Now().UTC())
	if err != nil {
		return err
	}
	report.DiskAlerts = alerts
	filesystemComplete := true
	for _, collector := range scan.Collectors {
		switch collector.Name {
		case collect.CollectorFilesystem, collect.CollectorGit, collect.CollectorProcesses, collect.CollectorServices:
			report.Incomplete = report.Incomplete || collector.Status != core.CollectorRan
		default:
			report.Incomplete = report.Incomplete || collector.Status == core.CollectorPartial || collector.Status == core.CollectorFailed
		}
		if collector.Name == collect.CollectorFilesystem && collector.Status != core.CollectorRan {
			filesystemComplete = false
		}
	}
	byPath := make(map[string]core.Entry, len(entries))
	for _, entry := range entries {
		byPath[entry.Path] = entry
	}
	if overflow {
		// Merge the complete-scan delta with delivered events. The lost
		// window can contain entries unrelated to the queued event paths.
		if changed == nil {
			changed = make(map[string]bool)
		}
		for _, entry := range entries {
			for _, evidence := range entry.Evidence {
				if evidence.Signal == "new_since_prior_scan" {
					changed[entry.Path] = true
					break
				}
			}
		}
	}
	keys := make([]string, 0, len(changed))
	for path := range changed {
		keys = append(keys, path)
	}
	sort.Strings(keys)
	for _, path := range keys {
		guidance := watchGuidance{Path: path}
		entry, ok := byPath[path]
		if !ok {
			guidance.ObservedAbsent = filesystemComplete
			guidance.Unknown = !filesystemComplete
		} else {
			class := plan.Classify(entry, policy)
			guidance.Class = class.Class
			guidance.Unknown = len(entry.Protections) != 0 && report.Incomplete
			for _, evidence := range entry.Evidence {
				if evidence.Signal == "new_since_prior_scan" {
					guidance.New = true
					break
				}
			}
			if guidance.New || reason == "settled" {
				for _, root := range policy.CanonicalRoots {
					if root.Class == class.Class && !core.PathWithin(path, root.Path) {
						guidance.CanonicalLocation = filepath.Join(root.Path, filepath.Base(path))
						break
					}
				}
			}
		}
		report.Paths = append(report.Paths, guidance)
	}
	return writeWatchReport(e, report)
}

func writeWatchReport(e *env, report watchReport) error {
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(e.stdout, string(encoded))
	return err
}
