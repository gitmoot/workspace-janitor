#!/usr/bin/env python3
"""Exercise real reporting storage/sampling on old and new code, not a prune race."""
import json
import os
from pathlib import Path
import subprocess
import sys

base = 'b197b8c47744a5f100e6abfeac7ed3175d794130'
root = Path.cwd()
old = Path(os.environ['RUNNER_TEMP']) / 'capacity-activity-before'
source = r'''package cli

import (
    "context"
    "errors"
    "path/filepath"
    "reflect"
    "testing"

    "github.com/gitmoot/workspace-janitor/internal/core"
    "github.com/gitmoot/workspace-janitor/internal/store"
)

func smokeActivity(t *testing.T) (*activityMonitor, *store.Store) {
    t.Helper()
    ctx := context.Background()
    home := t.TempDir()
    db, err := store.Open(ctx, filepath.Join(home, "report.db"))
    if err != nil { t.Fatal(err) }
    t.Cleanup(func() { db.Close() })
    missing := filepath.Join(home, "missing-cache")
    // The constructor gained an explicit sampler. Reflection keeps this
    // throwaway instrument executable against both real source revisions.
    start := reflect.ValueOf(startCapacityActivity)
    args := []reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(db),
        reflect.ValueOf("official_prune"), reflect.ValueOf("fixture"),
        reflect.ValueOf(missing), reflect.ValueOf("fixture-owner"), reflect.ValueOf(missing)}
    if start.Type().NumIn() == len(args)+1 { args = append(args, reflect.ValueOf(measureDisk)) }
    result := start.Call(args)
    if !result[1].IsNil() { t.Fatal(result[1].Interface()) }
    return result[0].Interface().(*activityMonitor), db
}

func TestCapacityActivityExactPathSmoke(t *testing.T) {
    monitor, _ := smokeActivity(t)
    if monitor.activity.AvailableBeforeBytes != nil || monitor.activity.MeasurementError == "" {
        t.Fatalf("missing cache borrowed ancestor sample: %+v", monitor.activity)
    }
    t.Log("missing exact path has no before sample and retains its filesystem error")
}

func TestCapacityActivitySpecificFailureSmoke(t *testing.T) {
    monitor, db := smokeActivity(t)
    // This is the same invalidation performed after a cache-device mismatch.
    monitor.activity.AvailableBeforeBytes = nil
    monitor.activity.MeasurementError = "cache filesystem identity changed"
    refused := errors.New("fixture operation refused")
    if err := monitor.finish(context.Background(), refused); !errors.Is(err, refused) { t.Fatal(err) }
    var activities []core.CapacityActivity
    if err := db.Read(context.Background(), func(tx *store.Tx) error {
        var err error
        activities, err = tx.CapacityActivities(context.Background())
        return err
    }); err != nil { t.Fatal(err) }
    if len(activities) != 1 { t.Fatal(activities) }
    activity := activities[0]
    if activity.MeasurementError != "cache filesystem identity changed" || activity.State != "failed" || activity.AvailableChangeBytes != nil {
        t.Fatalf("specific failure lost or unknown measurement became recovery: %+v", activity)
    }
    t.Log("persisted failed activity preserves the specific cause and unknown delta")
}
'''
results = {'base': base, 'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(), 'scope': 'real reporting monitor, filesystem sampling and SQLite persistence; not a live prune TOCTOU reproduction'}
subprocess.run(['git', 'worktree', 'add', '--detach', str(old), base], check=True)
try:
    for name, checkout in [('before', old), ('after', root)]:
        fixture = checkout / 'internal/cli/capacity_activity_throwaway_test.go'
        assert not fixture.exists()
        fixture.write_text(source)
        try:
            command = ['go', 'test', '-p', '1', './internal/cli', '-v', '-count=1', '-run', '^TestCapacityActivity(ExactPath|SpecificFailure)Smoke$']
            done = subprocess.run(command, cwd=checkout, text=True, capture_output=True, timeout=120)
            results[name] = {'command': command, 'exit': done.returncode, 'stdout': done.stdout, 'stderr': done.stderr}
            for test in ['TestCapacityActivityExactPathSmoke', 'TestCapacityActivitySpecificFailureSmoke']:
                assert '=== RUN   '+test in done.stdout, results[name]
                expected = 'FAIL' if name == 'before' else 'PASS'
                assert '--- '+expected+': '+test in done.stdout, results[name]
            assert (done.returncode == 0) == (name == 'after'), results[name]
        finally:
            fixture.unlink()
finally:
    subprocess.run(['git', 'worktree', 'remove', str(old)], check=True)
Path(sys.argv[1]).write_text(json.dumps(results, indent=2)+'\n')
print(json.dumps({'before_exit': results['before']['exit'], 'after_exit': results['after']['exit'], 'scope': results['scope']}))
