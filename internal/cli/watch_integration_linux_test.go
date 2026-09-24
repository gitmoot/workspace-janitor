//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

type watchSink struct {
	mu      sync.Mutex
	pending []byte
	reports chan watchReport
}

func (s *watchSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = append(s.pending, p...)
	for {
		end := bytes.IndexByte(s.pending, '\n')
		if end < 0 {
			break
		}
		var report watchReport
		if err := json.Unmarshal(s.pending[:end], &report); err != nil {
			return 0, err
		}
		s.reports <- report
		s.pending = s.pending[end+1:]
	}
	return len(p), nil
}

func watchFixture(t *testing.T) (*fixture, string, string) {
	t.Helper()
	f := newFixture(t)
	root := filepath.Join(f.home, "workspace")
	canonical := filepath.Join(f.home, "canonical")
	for _, path := range []string{root, canonical} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	f.writePolicy(t, "roots:\n  - path: "+root+"\ncanonical_roots:\n  - class: primary_project\n    path: "+canonical+"\ncollectors:\n  git: true\n  processes: false\n  services: false\nprevention:\n  min_free_percent: 0\n  min_free_bytes: 0\n")
	return f, root, canonical
}

func nextWatchReport(t *testing.T, reports <-chan watchReport, path string) watchReport {
	t.Helper()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case report := <-reports:
			if path == "" {
				return report
			}
			for _, guidance := range report.Paths {
				if guidance.Path == path {
					return report
				}
			}
		case <-deadline.C:
			t.Fatalf("watcher did not report %s", path)
		}
	}
}

func guidanceFor(t *testing.T, report watchReport, path string) watchGuidance {
	t.Helper()
	for _, guidance := range report.Paths {
		if guidance.Path == path {
			return guidance
		}
	}
	t.Fatalf("missing guidance for %s: %+v", path, report)
	return watchGuidance{}
}

func TestWatchCreateRenameDeleteGuidesCloneWithoutMoving(t *testing.T) {
	f, root, canonical := watchFixture(t)
	staging := filepath.Join(f.home, "staging-clone")
	if output, err := exec.Command("git", "init", "-q", staging).CombinedOutput(); err != nil {
		t.Fatalf("fixture clone: %v %s", err, output)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sink := &watchSink{reports: make(chan watchReport, 32)}
	done := make(chan ExitCode, 1)
	go func() {
		done <- Run(ctx, Options{Args: []string{"watch"}, Stdout: sink, Stderr: io.Discard,
			Lookup: config.MapLookup(f.env)})
	}()
	if report := nextWatchReport(t, sink.reports, ""); report.Reason != "startup" || !report.Reconciled {
		t.Fatalf("startup did not reconcile: %+v", report)
	}
	clone := filepath.Join(root, "review-clone")
	if err := os.Rename(staging, clone); err != nil {
		t.Fatal(err)
	}
	created := guidanceFor(t, nextWatchReport(t, sink.reports, clone), clone)
	if !created.New || created.Class != "primary_project" || created.CanonicalLocation != filepath.Join(canonical, "review-clone") {
		t.Fatalf("new clone lacked canonical guidance: %+v", created)
	}
	if _, err := os.Stat(clone); err != nil {
		t.Fatalf("watcher moved or removed the clone: %v", err)
	}
	renamed := filepath.Join(root, "review-renamed")
	if err := os.Rename(clone, renamed); err != nil {
		t.Fatal(err)
	}
	renameReport := nextWatchReport(t, sink.reports, renamed)
	if !guidanceFor(t, renameReport, clone).ObservedAbsent || !guidanceFor(t, renameReport, renamed).New {
		t.Fatalf("rename inventory was not reconciled: %+v", renameReport)
	}
	if err := os.RemoveAll(renamed); err != nil {
		t.Fatal(err)
	}
	deleted := guidanceFor(t, nextWatchReport(t, sink.reports, renamed), renamed)
	if !deleted.ObservedAbsent || deleted.Unknown {
		t.Fatalf("deletion was not observed from a complete scan: %+v", deleted)
	}
	cancel()
	select {
	case code := <-done:
		if code != ExitOK {
			t.Fatalf("watch stopped with exit %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("watcher did not stop on cancellation")
	}
}

func TestWatchGuidesCloneBuiltInsideRootAfterSettlement(t *testing.T) {
	f, root, canonical := watchFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink := &watchSink{reports: make(chan watchReport, 16)}
	done := make(chan ExitCode, 1)
	go func() {
		done <- Run(ctx, Options{Args: []string{"watch"}, Stdout: sink, Stderr: io.Discard,
			Lookup: config.MapLookup(f.env)})
	}()
	nextWatchReport(t, sink.reports, "")
	clone := filepath.Join(root, "direct-clone")
	if err := os.Mkdir(clone, 0700); err != nil {
		t.Fatal(err)
	}
	nextWatchReport(t, sink.reports, clone) // initial directory can be incomplete
	if output, err := exec.Command("git", "init", "-q", clone).CombinedOutput(); err != nil {
		t.Fatalf("finish clone: %v %s", err, output)
	}
	for {
		report := nextWatchReport(t, sink.reports, clone)
		if report.Reason != "settled" {
			continue
		}
		guidance := guidanceFor(t, report, clone)
		if guidance.Class != "primary_project" || guidance.CanonicalLocation != filepath.Join(canonical, "direct-clone") {
			t.Fatalf("settled clone lacked guidance: %+v", guidance)
		}
		break
	}
	if _, err := os.Stat(clone); err != nil {
		t.Fatalf("watcher mutated clone: %v", err)
	}
	cancel()
	if code := <-done; code != ExitOK {
		t.Fatalf("watch stopped with exit %d", code)
	}
}

func TestWatchMetadataDoesNotAdvanceWeeklyDeepScan(t *testing.T) {
	f, root, _ := watchFixture(t)
	f.writePolicy(t, "roots:\n  - path: "+root+"\ncollectors:\n  deep_size: true\n  git: false\n  processes: false\n  services: false\nprevention:\n  min_free_percent: 0\n")
	var out bytes.Buffer
	e := &env{opts: &globalOpts{format: "json"}, stdout: &out, stderr: io.Discard, lookup: config.MapLookup(f.env)}
	paths, err := e.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := e.loadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if err := reconcileWatch(context.Background(), e, paths, policy, "startup", nil, true, 0); err != nil {
		t.Fatal(err)
	}
	due, err := deepScanDue(context.Background(), paths.DatabaseFile, 7*24*time.Hour, time.Now().UTC())
	if err != nil || !due {
		t.Fatalf("watcher incorrectly satisfied the deep-scan schedule: due=%v err=%v", due, err)
	}
}

type scriptedWatcher struct {
	events []watchEvent
	before func()
	closed bool
}

func (w *scriptedWatcher) next(ctx context.Context) (watchEvent, error) {
	if len(w.events) == 0 {
		<-ctx.Done()
		return watchEvent{}, ctx.Err()
	}
	if w.before != nil {
		w.before()
		w.before = nil
	}
	event := w.events[0]
	w.events = w.events[1:]
	return event, nil
}
func (w *scriptedWatcher) close() error { w.closed = true; return nil }

func TestWatchOverflowAndRestartReconcileMissedChanges(t *testing.T) {
	f, root, _ := watchFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	sink := &watchSink{reports: make(chan watchReport, 8)}
	e := &env{opts: &globalOpts{format: "json"}, stdout: sink, stderr: io.Discard, lookup: config.MapLookup(f.env)}
	paths, err := e.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := e.loadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	lost := filepath.Join(root, "created-during-loss")
	known := filepath.Join(root, "delivered-event")
	first := &scriptedWatcher{events: []watchEvent{
		{Root: root, Name: "delivered-event"}, {Overflow: true},
	}, before: func() {
		for _, path := range []string{known, lost} {
			if err := os.Mkdir(path, 0700); err != nil {
				t.Error(err)
			}
		}
	}}
	second := &scriptedWatcher{}
	opens := 0
	done := make(chan error, 1)
	go func() {
		done <- watchLoop(ctx, e, paths, policy, func() (eventWatcher, error) {
			opens++
			if opens == 1 {
				return first, nil
			}
			return second, nil
		}, watchChurnInterval)
	}()
	startup := nextWatchReport(t, sink.reports, "")
	var recovery watchReport
	select {
	case recovery = <-sink.reports:
	case err := <-done:
		t.Fatalf("watch loop exited before overflow recovery: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("overflow recovery did not complete")
	}
	if startup.ScanID == recovery.ScanID || !recovery.Reconciled || opens != 2 || !first.closed {
		t.Fatalf("overflow did not re-arm and rescan: startup=%+v recovery=%+v opens=%d", startup, recovery, opens)
	}
	if guidance := guidanceFor(t, recovery, lost); !guidance.New || guidance.ObservedAbsent {
		t.Fatalf("lost-window entry omitted from mixed overflow guidance: %+v", guidance)
	}
	if guidance := guidanceFor(t, recovery, known); !guidance.New || guidance.ObservedAbsent {
		t.Fatalf("delivered entry omitted from mixed overflow guidance: %+v", guidance)
	}
	cancel()
	assertInventoryPath(t, paths.DatabaseFile, recovery.ScanID, lost)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !second.closed {
		t.Fatal("re-armed watcher remained open")
	}
	// A restart performs another full scan even though no inotify event was
	// available for this change while the first watcher was stopped.
	missed := filepath.Join(root, "created-while-stopped")
	if err := os.Mkdir(missed, 0700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	e.stdout = &out
	if err := reconcileWatch(context.Background(), e, paths, policy, "startup", nil, true, 0); err != nil {
		t.Fatal(err)
	}
	var restart watchReport
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &restart); err != nil {
		t.Fatal(err)
	}
	if restart.Reason != "startup" || !restart.Reconciled || restart.ScanID == recovery.ScanID {
		t.Fatalf("restart did not reconcile a fresh snapshot: %+v", restart)
	}
	assertInventoryPath(t, paths.DatabaseFile, restart.ScanID, missed)
	if guidance := guidanceFor(t, restart, missed); !guidance.New || guidance.ObservedAbsent {
		t.Fatalf("missed new entry had no restart guidance: %+v", guidance)
	}
}

func assertInventoryPath(t *testing.T, database, scanID, path string) {
	t.Helper()
	ctx := context.Background()
	db, err := store.OpenReadOnly(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Read(ctx, func(tx *store.Tx) error {
		_, err := tx.Entry(ctx, scanID, path)
		return err
	}); err != nil {
		t.Fatalf("scan %s did not record %s: %v", scanID, path, err)
	}
}

// pulseWatcher lets the integration test drive distinct event bursts without
// waiting for a wall-clock debounce per event. The real watch loop, scan and
// store still run; only the event source's short burst wait is accelerated.
type pulseWatcher struct {
	events chan watchEvent
	ready  chan struct{}
}

func (w *pulseWatcher) next(ctx context.Context) (watchEvent, error) {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < 200*time.Millisecond {
		return watchEvent{}, context.DeadlineExceeded
	}
	select {
	case w.ready <- struct{}{}:
	default:
	}
	select {
	case event := <-w.events:
		return event, nil
	case <-ctx.Done():
		return watchEvent{}, ctx.Err()
	}
}

func (*pulseWatcher) close() error { return nil }

func TestWatchBoundsProtectedChurnWithoutLosingRealDirectories(t *testing.T) {
	f, root, canonical := watchFixture(t)
	operational := filepath.Join(root, ".gitmoot")
	if err := os.Mkdir(operational, 0700); err != nil {
		t.Fatal(err)
	}
	f.writePolicy(t, "roots:\n  - path: "+root+"\n    max_depth: 1\n    report_only: true\n"+
		"protect:\n  paths:\n    - "+operational+"\n"+
		"canonical_roots:\n  - class: primary_project\n    path: "+canonical+"\n"+
		"collectors:\n  git: false\n  processes: false\n  services: false\n"+
		"prevention:\n  min_free_percent: 0\n  auto_expire: false\n"+
		"retention:\n  delete_enabled: false\n")
	sink := &watchSink{reports: make(chan watchReport, 64)}
	e := &env{opts: &globalOpts{format: "json"}, stdout: sink, stderr: io.Discard,
		lookup: config.MapLookup(f.env)}
	paths, err := e.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := e.loadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	watcher := &pulseWatcher{events: make(chan watchEvent), ready: make(chan struct{}, 1)}
	done := make(chan error, 1)
	go func() {
		done <- watchLoop(ctx, e, paths, policy, func() (eventWatcher, error) { return watcher, nil }, 800*time.Millisecond)
	}()
	startup := nextWatchReport(t, sink.reports, "")
	if startup.Reason != "startup" || !startup.Reconciled {
		t.Fatalf("initial inventory was not reconciled: %+v", startup)
	}
	send := func(name string) {
		t.Helper()
		select {
		case <-watcher.ready:
		case err := <-done:
			t.Fatalf("watch stopped before event: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("watch did not become ready")
		}
		select {
		case watcher.events <- watchEvent{Root: root, Name: name}:
		case <-time.After(5 * time.Second):
			t.Fatal("watch did not accept event")
		}
	}
	counts := func() (int, int) {
		t.Helper()
		db, err := store.OpenReadOnly(ctx, paths.DatabaseFile)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		scans, rows := 0, 0
		if err := db.Read(ctx, func(tx *store.Tx) error {
			all, err := tx.ListScans(ctx, 0)
			if err != nil {
				return err
			}
			scans = len(all)
			for _, scan := range all {
				rows += scan.EntryCount
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return scans, rows
	}
	assertProtected := func(scanID string) {
		t.Helper()
		db, err := store.OpenReadOnly(ctx, paths.DatabaseFile)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		protected := false
		if err := db.Read(ctx, func(tx *store.Tx) error {
			entry, err := tx.Entry(ctx, scanID, operational)
			if err == nil {
				protected = entry.Protected()
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if !protected {
			t.Fatalf("operational directory lost its safety protection in scan %s", scanID)
		}
	}
	assertProtected(startup.ScanID)
	start := time.Now()
	for i := range 8 {
		if err := os.WriteFile(filepath.Join(operational, "state"), []byte{byte(i)}, 0600); err != nil {
			t.Fatal(err)
		}
		send(".gitmoot")
	}
	// The next ready signal proves every prior burst was processed.
	select {
	case <-watcher.ready:
	case err := <-done:
		t.Fatalf("watch stopped after churn: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not drain churn")
	}
	// The watcher is already inside next: restore its readiness token so a
	// real event is delivered now, rather than waiting for the churn timer.
	watcher.ready <- struct{}{}
	scans, rows := counts()
	t.Logf("protected churn: 8 bursts in %s, persisted scans=%d inventory rows=%d", time.Since(start), scans, rows)
	if scans > 2 {
		t.Fatalf("protected operational churn amplified persisted scans: %d scans for 8 bursts", scans)
	}
	deferred := nextWatchReport(t, sink.reports, "")
	if deferred.Reason != "deferred" || !deferred.Incomplete || deferred.ScanID != "" ||
		deferred.NextReconcileAt == nil {
		t.Fatalf("suppressed inventory was not marked incomplete: %+v", deferred)
	}
	fresh := filepath.Join(root, "new-workspace")
	if err := os.Mkdir(fresh, 0700); err != nil {
		t.Fatal(err)
	}
	send("new-workspace")
	createdReport := nextWatchReport(t, sink.reports, fresh)
	if createdReport.DeferredEvents != 8 {
		t.Fatalf("real event did not immediately reconcile deferred churn: %+v", createdReport)
	}
	created := guidanceFor(t, createdReport, fresh)
	if !created.New {
		t.Fatalf("new workspace was suppressed behind churn: %+v", created)
	}
	if err := os.Remove(fresh); err != nil {
		t.Fatal(err)
	}
	send("new-workspace")
	removedReport := nextWatchReport(t, sink.reports, fresh)
	removed := guidanceFor(t, removedReport, fresh)
	if !removed.ObservedAbsent || removed.Unknown {
		t.Fatalf("removed workspace was not reconciled: %+v", removed)
	}
	scans, rows = counts()
	if scans != 3 {
		t.Fatalf("new and removed workspace did not each trigger a scan: %d", scans)
	}
	if err := os.WriteFile(filepath.Join(operational, "state"), []byte("again"), 0600); err != nil {
		t.Fatal(err)
	}
	send(".gitmoot")
	nextDeferred := nextWatchReport(t, sink.reports, "")
	if nextDeferred.Reason != "deferred" || !nextDeferred.Incomplete {
		t.Fatalf("second protected churn was not deferred: %+v", nextDeferred)
	}
	periodic := nextWatchReport(t, sink.reports, "")
	if periodic.Reason != "churn" || !periodic.Reconciled || periodic.DeferredEvents != 1 {
		t.Fatalf("deferred evidence was not reconciled at the bound: %+v", periodic)
	}
	assertProtected(periodic.ScanID)
	scans, rows = counts()
	t.Logf("churn plus two real changes: persisted scans=%d inventory rows=%d", scans, rows)
	if scans > 4 || rows > 8 {
		t.Fatalf("real events amplified or were not bounded: %d scans", scans)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("watch stopped with error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("watch did not stop on cancellation")
	}
}
