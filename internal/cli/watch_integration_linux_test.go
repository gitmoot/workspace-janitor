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
	if err := reconcileWatch(context.Background(), e, paths, policy, "startup", nil, true); err != nil {
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
	first := &scriptedWatcher{events: []watchEvent{{Overflow: true}}, before: func() {
		if err := os.Mkdir(lost, 0700); err != nil {
			t.Error(err)
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
		})
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
	if err := reconcileWatch(context.Background(), e, paths, policy, "startup", nil, true); err != nil {
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
