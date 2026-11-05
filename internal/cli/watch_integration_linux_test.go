//go:build linux

package cli

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	policy, err := e.loadPolicy(context.Background())
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
	policy, err := e.loadPolicy(context.Background())
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
	policy, err := e.loadPolicy(context.Background())
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

// A daily cycle holds the scan lock through apply. The watcher must keep
// publishing fresh capacity samples meanwhile, even before its own startup
// reconcile can run (live 2026-11-02: a 12-minute cycle let the sample go
// stale and Gitmoot refused every new review on a measurement_unknown hold).
func TestWatchKeepsSamplingCapacityWhileTheScanLockIsHeld(t *testing.T) {
	f, root, _ := watchFixture(t)
	f.writePolicy(t, "roots:\n  - path: "+root+"\ncollectors:\n  git: false\n  processes: false\n  services: false\nprevention:\n  min_free_percent: 0\n  min_free_bytes: 0\n  capacity_interval: 1s\n  targets:\n    - path: "+root+"\n      target_free_bytes: 1\n      reserve_free_bytes: 0\n      recovery_margin_bytes: 0\n")
	sink := &watchSink{reports: make(chan watchReport, 32)}
	e := &env{opts: &globalOpts{format: "json"}, stdout: sink, stderr: io.Discard, lookup: config.MapLookup(f.env)}
	paths, err := e.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := e.loadPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out, stderr, code := f.run(t, "scan"); code != ExitOK {
		t.Fatalf("seed database: %d %s %s", code, out, stderr)
	}
	release, err := lockScan(context.Background(), paths.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- watchLoop(ctx, e, paths, policy, func() (eventWatcher, error) { return &scriptedWatcher{}, nil }, watchChurnInterval)
	}()
	var stamps []string
	deadline := time.After(6 * time.Second)
	for len(stamps) < 2 {
		select {
		case report := <-sink.reports:
			if report.Reason != "capacity" || report.Capacity == nil {
				t.Fatalf("report while the scan lock is held: %+v", report)
			}
			stamp := report.Capacity.SampledAt.String()
			if len(stamps) == 0 || stamps[len(stamps)-1] != stamp {
				stamps = append(stamps, stamp)
			}
		case err := <-done:
			t.Fatalf("watch loop exited: %v", err)
		case <-deadline:
			t.Fatalf("capacity sampling starved by the scan lock: %d fresh samples", len(stamps))
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// On a fresh installation the database does not exist yet. A cycle holding
// the scan lock must not make the watcher's first capacity sample fail; the
// watcher keeps running and publishes samples.
func TestWatchSamplesOnAFreshInstallWhileTheScanLockIsHeld(t *testing.T) {
	f, root, _ := watchFixture(t)
	f.writePolicy(t, "roots:\n  - path: "+root+"\ncollectors:\n  git: false\n  processes: false\n  services: false\nprevention:\n  min_free_percent: 0\n  min_free_bytes: 0\n  capacity_interval: 1s\n  targets:\n    - path: "+root+"\n      target_free_bytes: 1\n      reserve_free_bytes: 0\n      recovery_margin_bytes: 0\n")
	sink := &watchSink{reports: make(chan watchReport, 32)}
	e := &env{opts: &globalOpts{format: "json"}, stdout: sink, stderr: io.Discard, lookup: config.MapLookup(f.env)}
	paths, err := e.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(paths.DatabaseFile); !os.IsNotExist(err) {
		t.Fatalf("fixture database already exists: %v", err)
	}
	policy, err := e.loadPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release, err := lockScan(context.Background(), paths.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- watchLoop(ctx, e, paths, policy, func() (eventWatcher, error) { return &scriptedWatcher{}, nil }, watchChurnInterval)
	}()
	select {
	case report := <-sink.reports:
		if report.Reason != "capacity" || report.Capacity == nil {
			t.Fatalf("unexpected report: %+v", report)
		}
	case err := <-done:
		t.Fatalf("watch loop exited on a fresh installation: %v", err)
	case <-time.After(6 * time.Second):
		t.Fatal("no capacity sample on a fresh installation")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// A normal shutdown (SIGTERM through signal.NotifyContext gives the context a
// cause other than context.Canceled) must end the watcher successfully.
func TestWatchShutdownWithACancellationCauseSucceeds(t *testing.T) {
	f, root, _ := watchFixture(t)
	f.writePolicy(t, "roots:\n  - path: "+root+"\ncollectors:\n  git: false\n  processes: false\n  services: false\nprevention:\n  min_free_percent: 0\n  min_free_bytes: 0\n  capacity_interval: 1s\n  targets:\n    - path: "+root+"\n      target_free_bytes: 1\n      reserve_free_bytes: 0\n      recovery_margin_bytes: 0\n")
	sink := &watchSink{reports: make(chan watchReport, 32)}
	e := &env{opts: &globalOpts{format: "json"}, stdout: sink, stderr: io.Discard, lookup: config.MapLookup(f.env)}
	paths, err := e.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := e.loadPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- watchLoop(ctx, e, paths, policy, func() (eventWatcher, error) { return &scriptedWatcher{}, nil }, watchChurnInterval)
	}()
	select {
	case <-sink.reports:
	case err := <-done:
		t.Fatalf("watch loop exited early: %v", err)
	case <-time.After(6 * time.Second):
		t.Fatal("watcher produced no report")
	}
	cancel(errors.New("terminated signal received"))
	if err := <-done; err != nil {
		t.Fatalf("normal shutdown returned %v, want nil", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

// A sampler failure (here: the capacity report cannot be written) must end
// the watcher with that error, even while the startup reconcile waits on a
// scan lock held by a cycle, so systemd records and restarts it.
func TestWatchReturnsTheSamplerFailure(t *testing.T) {
	f, root, _ := watchFixture(t)
	f.writePolicy(t, "roots:\n  - path: "+root+"\ncollectors:\n  git: false\n  processes: false\n  services: false\nprevention:\n  min_free_percent: 0\n  min_free_bytes: 0\n  capacity_interval: 1s\n  targets:\n    - path: "+root+"\n      target_free_bytes: 1\n      reserve_free_bytes: 0\n      recovery_margin_bytes: 0\n")
	e := &env{opts: &globalOpts{format: "json"}, stdout: failingWriter{}, stderr: io.Discard, lookup: config.MapLookup(f.env)}
	paths, err := e.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := e.loadPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release, err := lockScan(context.Background(), paths.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	done := make(chan error, 1)
	go func() {
		done <- watchLoop(context.Background(), e, paths, policy, func() (eventWatcher, error) { return &scriptedWatcher{}, nil }, watchChurnInterval)
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "no space left on device") {
			t.Fatalf("sampler failure was not returned: %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("watcher kept running after its sampler failed")
	}
}

// A stop that arrives while a change reconcile is in flight (here: waiting
// for the scan lock a cycle holds) is a clean shutdown. Live 2026-11-03: a
// restart during a settle scan logged "store: begin transaction: context
// canceled" and systemd recorded the watcher as failed.
func TestWatchStopDuringReconcileSucceeds(t *testing.T) {
	f, root, _ := watchFixture(t)
	sink := &watchSink{reports: make(chan watchReport, 32)}
	e := &env{opts: &globalOpts{format: "json"}, stdout: sink, stderr: io.Discard, lookup: config.MapLookup(f.env)}
	paths, err := e.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := e.loadPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "new-clone"), 0o700); err != nil {
		t.Fatal(err)
	}
	locked := make(chan func(), 1)
	watcher := &scriptedWatcher{
		events: []watchEvent{{Root: root, Name: "new-clone"}},
		before: func() {
			release, err := lockScan(context.Background(), paths.StateDir)
			if err != nil {
				t.Error(err)
				return
			}
			locked <- release
		},
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- watchLoop(ctx, e, paths, policy, func() (eventWatcher, error) { return watcher, nil }, watchChurnInterval)
	}()
	var release func()
	select {
	case release = <-locked:
	case err := <-done:
		t.Fatalf("watch loop exited before the change: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("startup reconcile never finished")
	}
	defer release()
	// The change reconcile is now waiting for the scan lock.
	time.Sleep(500 * time.Millisecond)
	cancel(errors.New("terminated signal received"))
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stop during reconcile returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch loop did not stop")
	}
}

// Live 2026-11-04: sampling stalled 16 minutes while the watcher stayed up,
// then the exit blamed the scan ("context canceled"). With the database
// write-locked by another process, sampling cannot publish; once the newest
// sample expires the watcher must report capacity_stale and exit with that
// cause, so its supervisor restarts it.
func TestWatchExitsWhenItsCapacitySampleGoesStale(t *testing.T) {
	f, root, _ := watchFixture(t)
	f.writePolicy(t, "roots:\n  - path: "+root+"\ncollectors:\n  git: false\n  processes: false\n  services: false\nprevention:\n  min_free_percent: 0\n  min_free_bytes: 0\n  capacity_interval: 1s\n  targets:\n    - path: "+root+"\n      target_free_bytes: 1\n      reserve_free_bytes: 0\n      recovery_margin_bytes: 0\n")
	sink := &watchSink{reports: make(chan watchReport, 64)}
	e := &env{opts: &globalOpts{format: "json"}, stdout: sink, stderr: io.Discard, lookup: config.MapLookup(f.env)}
	paths, err := e.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := e.loadPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out, stderr, code := f.run(t, "scan"); code != ExitOK {
		t.Fatalf("seed database: %d %s %s", code, out, stderr)
	}
	done := make(chan error, 1)
	go func() {
		done <- watchLoop(context.Background(), e, paths, policy, func() (eventWatcher, error) { return &scriptedWatcher{}, nil }, watchChurnInterval)
	}()
	for first := false; !first; {
		select {
		case report := <-sink.reports:
			first = report.Reason == "capacity" && report.Capacity != nil
		case err := <-done:
			t.Fatalf("watch loop exited before sampling: %v", err)
		case <-time.After(6 * time.Second):
			t.Fatal("no first capacity sample")
		}
	}
	db, err := sql.Open("sqlite", paths.DatabaseFile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// The sampler may be mid-write right now; wait for the lock rather than
	// failing on SQLITE_BUSY (CI flake on #157).
	if _, err := conn.ExecContext(context.Background(), "PRAGMA busy_timeout = 10000"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), "ROLLBACK") }()
	staleReported := false
	deadline := time.After(15 * time.Second)
	for {
		select {
		case report := <-sink.reports:
			staleReported = staleReported || report.Reason == "capacity_stale"
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "capacity sample stale") {
				t.Fatalf("watcher did not exit on its stale sample: %v", err)
			}
			for drained := false; !drained; {
				select {
				case report := <-sink.reports:
					staleReported = staleReported || report.Reason == "capacity_stale"
				default:
					drained = true
				}
			}
			if !staleReported {
				t.Fatal("no capacity_stale report before exit")
			}
			return
		case <-deadline:
			t.Fatal("watcher kept running with a stale capacity sample")
		}
	}
}

// chanWatcher delivers events when the test sends them.
type chanWatcher struct{ events chan watchEvent }

func (w *chanWatcher) next(ctx context.Context) (watchEvent, error) {
	select {
	case event := <-w.events:
		return event, nil
	case <-ctx.Done():
		return watchEvent{}, ctx.Err()
	}
}
func (w *chanWatcher) close() error { return nil }

// Live 2026-11-05: one path rewritten every ~30 s triggered a full scan of
// every root each time and kept the watcher at 0.7 of a core. Changes inside
// watchChangeGap of the previous scan coalesce into one scan when it ends,
// and that scan still reports every changed path.
func TestWatchCoalescesChangesWithinTheGap(t *testing.T) {
	f, root, _ := watchFixture(t)
	saved := watchChangeGap
	watchChangeGap = 1500 * time.Millisecond
	defer func() { watchChangeGap = saved }()
	sink := &watchSink{reports: make(chan watchReport, 32)}
	e := &env{opts: &globalOpts{format: "json"}, stdout: sink, stderr: io.Discard, lookup: config.MapLookup(f.env)}
	paths, err := e.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := e.loadPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	watcher := &chanWatcher{events: make(chan watchEvent)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- watchLoop(ctx, e, paths, policy, func() (eventWatcher, error) { return watcher, nil }, watchChurnInterval)
	}()
	waitFor := func(reason string) watchReport {
		t.Helper()
		deadline := time.After(20 * time.Second)
		for {
			select {
			case report := <-sink.reports:
				if report.Reason == reason {
					return report
				}
			case err := <-done:
				t.Fatalf("watch loop exited: %v", err)
			case <-deadline:
				t.Fatalf("no %s report", reason)
			}
		}
	}
	waitFor("startup")
	start := time.Now()
	names := []string{"a", "b", "c"}
	for _, name := range names {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
		watcher.events <- watchEvent{Root: root, Name: name}
		time.Sleep(100 * time.Millisecond)
	}
	report := waitFor("change")
	if elapsed := time.Since(start); elapsed < time.Second {
		t.Fatalf("change scan ran %s after the first change, inside the gap", elapsed)
	}
	got := map[string]bool{}
	for _, guidance := range report.Paths {
		got[filepath.Base(guidance.Path)] = true
	}
	for _, name := range names {
		if !got[name] {
			t.Fatalf("coalesced scan did not report %s: %+v", name, report.Paths)
		}
	}
	select {
	case extra := <-sink.reports:
		if extra.Reason == "change" {
			t.Fatalf("three changes inside the gap produced more than one scan: %+v", extra)
		}
	case <-time.After(300 * time.Millisecond):
	}
}
