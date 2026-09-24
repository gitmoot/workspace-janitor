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

// watchReport describes a persisted inventory reconciliation or a deferred
// incomplete observation. It never authorizes a filesystem action.
type watchReport struct {
	Reason          string          `json:"reason"`
	ScanID          string          `json:"scan_id"`
	Paths           []watchGuidance `json:"paths"`
	Reconciled      bool            `json:"reconciled"`
	Incomplete      bool            `json:"incomplete"`
	DeferredEvents  uint64          `json:"deferred_events,omitempty"`
	NextReconcileAt *time.Time      `json:"next_reconcile_at,omitempty"`
	DiskAlerts      []diskAlert     `json:"disk_alerts,omitempty"`
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
	policy, err := e.loadPolicy()
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
	open func() (eventWatcher, error), churnInterval time.Duration) error {
	watcher, err := open()
	if err != nil {
		return err
	}
	defer func() { _ = watcher.close() }()
	// Snapshot protected directory identities before the startup scan. Events
	// queued during reconciliation still expose new, removed or replaced paths.
	protected := newProtectedWatchDirs(policy)
	if err := reconcileWatch(ctx, e, paths, policy, "startup", nil, true, 0); err != nil {
		return err
	}
	pendingSettle := map[string]bool{}
	var settleAt, churnAt time.Time
	var deferred uint64
	for {
		deadline := settleAt
		if !churnAt.IsZero() && (deadline.IsZero() || churnAt.Before(deadline)) {
			deadline = churnAt
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
			if !settleAt.IsZero() && !now.Before(settleAt) {
				// Settling is a full scan too; it satisfies any deferred churn.
				if err := reconcileWatch(ctx, e, paths, policy, "settled", pendingSettle, false, deferred); err != nil {
					return err
				}
				pendingSettle = map[string]bool{}
				settleAt, churnAt, deferred = time.Time{}, time.Time{}, 0
			} else if !churnAt.IsZero() && !now.Before(churnAt) {
				// Full reconciliation recovers even a top-level event lost
				// during protected churn or an inotify overflow.
				if err := reconcileWatch(ctx, e, paths, policy, "churn", nil, true, deferred); err != nil {
					return err
				}
				churnAt, deferred = time.Time{}, 0
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
		if err := reconcileWatch(ctx, e, paths, policy, "change", changed, overflow, deferred); err != nil {
			return err
		}
		churnAt, deferred = time.Time{}, 0
		// A direct clone first creates an empty directory and fills .git
		// below our top-level watch. Revisit newly seen directories after
		// they settle; the watcher itself never acts on them.
		for path := range changed {
			if info, err := os.Lstat(path); err == nil && info.IsDir() {
				pendingSettle[path] = true
				settleAt = time.Now().Add(2 * time.Second)
			}
		}
	}
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
	// Background inventory is local and rules-only; neither planning nor
	// Jev nor an action engine is invoked by this path.
	var scanID string
	if err := runScan(ctx, &quiet, nil, scanOptions{noDeepSize: true, recordScanID: &scanID}); err != nil {
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
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(e.stdout, string(encoded))
	return err
}
