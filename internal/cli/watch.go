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

// watchReport describes only observed inventory changes. It never authorizes
// or performs a filesystem action.
type watchReport struct {
	Reason     string          `json:"reason"`
	ScanID     string          `json:"scan_id"`
	Paths      []watchGuidance `json:"paths"`
	Reconciled bool            `json:"reconciled"`
	Incomplete bool            `json:"incomplete"`
	DiskAlerts []diskAlert     `json:"disk_alerts,omitempty"`
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
	})
}

type eventWatcher interface {
	next(context.Context) (watchEvent, error)
	close() error
}

func watchLoop(ctx context.Context, e *env, paths config.Paths, policy config.Policy, open func() (eventWatcher, error)) error {
	watcher, err := open()
	if err != nil {
		return err
	}
	defer func() { _ = watcher.close() }()
	// Register watches before reconciling missed events at startup. Events
	// arriving during the full scan stay queued and cause another scan.
	if err := reconcileWatch(ctx, e, paths, policy, "startup", nil, true); err != nil {
		return err
	}
	pendingSettle := map[string]bool{}
	var settleAt time.Time
	for {
		eventCtx := ctx
		cancelWait := func() {}
		if !settleAt.IsZero() {
			eventCtx, cancelWait = context.WithDeadline(ctx, settleAt)
		}
		first, err := watcher.next(eventCtx)
		cancelWait()
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			if err := reconcileWatch(ctx, e, paths, policy, "settled", pendingSettle, false); err != nil {
				return err
			}
			pendingSettle = map[string]bool{}
			settleAt = time.Time{}
			continue
		}
		if errors.Is(err, context.Canceled) {
			return nil
		}
		if err != nil {
			return err
		}
		changed := map[string]bool{}
		overflow := first.Overflow
		if first.Name != "" {
			changed[filepath.Join(first.Root, first.Name)] = true
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
			if event.Name != "" {
				changed[filepath.Join(event.Root, event.Name)] = true
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
				// A removed root cannot be re-armed yet. Still report the
				// bounded reconciliation; the service can restart once the
				// root returns, without asserting an empty event stream.
				return errors.Join(openErr, reconcileWatch(ctx, e, paths, policy, "change", changed, true))
			}
			watcher = rearmed
		}
		if err := reconcileWatch(ctx, e, paths, policy, "change", changed, overflow); err != nil {
			return err
		}
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

func reconcileWatch(ctx context.Context, e *env, paths config.Paths, policy config.Policy, reason string, changed map[string]bool, overflow bool) error {
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
	report := watchReport{Reason: reason, ScanID: scan.ID, Reconciled: overflow, Paths: []watchGuidance{}}
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
