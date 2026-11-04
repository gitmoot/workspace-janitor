//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
)

// trimFixture runs the real `janitor cycle` with fake go and docker binaries
// that log their argv and environment, and a fake process table.
type trimFixture struct {
	*fixture
	root, cache, proc, log, gobin, dockerbin string
}

func newTrimFixture(t *testing.T) *trimFixture {
	t.Helper()
	f := newFixture(t)
	x := &trimFixture{fixture: f, root: filepath.Join(f.home, "workspace"), cache: filepath.Join(f.home, "go-build"),
		proc: filepath.Join(f.home, "proc"), log: filepath.Join(f.home, "calls.log")}
	for _, dir := range []string{x.root, x.cache, x.proc} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A fake official binary records its call; the go one empties the cache.
	write := func(name, body string) string {
		path := filepath.Join(f.home, name)
		script := "#!/bin/sh\nprintf '%s|%s|GOCACHE=%s\\n' \"" + name + "\" \"$*\" \"$GOCACHE\" >> " + x.log + "\n" + body
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	x.gobin = write("go", "rm -rf \"$GOCACHE\"/*\n")
	// The fake daemon reports the default data root to the trim guard.
	x.dockerbin = write("docker", "if [ \"$1\" = info ]; then echo /var/lib/docker; fi\n")
	return x
}

func (x *trimFixture) fill(t *testing.T, bytes int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(x.cache, "ab"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(x.cache, "ab", "obj-d"), make([]byte, bytes), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (x *trimFixture) process(t *testing.T, pid string, argv ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(x.proc, pid), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(x.proc, pid, "cmdline"), []byte(strings.Join(argv, "\x00")+"\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// trimResult decodes the public cycle report, not internal types, so the
// old code fails these tests on behavior rather than on compilation.
type trimResult struct {
	Status      string   `json:"status"`
	Kind        string   `json:"kind"`
	SizeBefore  *int64   `json:"size_before_bytes"`
	SizeAfter   *int64   `json:"size_after_bytes"`
	ActiveUsers []string `json:"active_users"`
}

func (x *trimFixture) cycle(t *testing.T) []trimResult {
	t.Helper()
	x.writePolicy(t, fmt.Sprintf(`roots:
  - path: %s
collectors:
  deep_size: false
  git: false
  processes: false
  services: false
  proc_root: %s
prevention:
  min_free_percent: 0
  cache_trims:
    - kind: go-build
      path: %s
      binary: %s
      max_bytes: 65536
    - kind: docker-builder
      binary: %s
      max_bytes: 2147483648
`, x.root, x.proc, x.cache, x.gobin, x.dockerbin))
	out, stderr, code := x.run(t, "cycle")
	if code != ExitOK {
		t.Fatalf("cycle: %d %s %s", code, out, stderr)
	}
	var report struct {
		CacheTrims []trimResult `json:"cache_trims"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.CacheTrims) != 2 {
		t.Fatalf("cache trims not reported: %s", out)
	}
	return report.CacheTrims
}

func (x *trimFixture) calls(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(x.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

// The daily cycle trims an oversized shared Go build cache with the official
// command and prunes only unused Docker build cache, at their bounds.
func TestCycleTrimsOversizedBuildCaches(t *testing.T) {
	x := newTrimFixture(t)
	x.fill(t, 1<<20)
	x.process(t, "4242", "/usr/bin/sleep", "300")
	trims := x.cycle(t)
	goTrim, docker := trims[0], trims[1]
	if goTrim.Status != "trimmed" || goTrim.SizeBefore == nil || *goTrim.SizeBefore <= 65536 || goTrim.SizeAfter == nil || *goTrim.SizeAfter > 65536 {
		t.Fatalf("go-build not trimmed: %+v", goTrim)
	}
	if docker.Status != "trimmed" {
		t.Fatalf("docker builder cache not pruned: %+v", docker)
	}
	calls := x.calls(t)
	want := []string{
		"go|clean -cache|GOCACHE=" + x.cache,
		"docker|info --format {{.DockerRootDir}}|GOCACHE=",
		"docker|builder prune --force --max-used-space 2147483648|GOCACHE=",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("official commands:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
	}
	// Under its bound the Go cache is left alone.
	x.cycle(t)
	for _, call := range x.calls(t)[len(want):] {
		if strings.HasPrefix(call, "go|") {
			t.Fatalf("under-bound cache trimmed again: %s", call)
		}
	}
}

// A running Go build or image build postpones that trim: nothing is run, and
// the cycle still succeeds.
func TestCycleSkipsBuildCachesInLiveUse(t *testing.T) {
	x := newTrimFixture(t)
	x.fill(t, 1<<20)
	x.process(t, "100", "/root/.local/toolchains/go1.26.4/bin/go", "test", "-count=1", "./...")
	x.process(t, "200", "/usr/bin/docker", "buildx", "build", "-t", "app", ".")
	for _, trim := range x.cycle(t) {
		if trim.Status != "skipped_in_use" || len(trim.ActiveUsers) == 0 {
			t.Fatalf("%s trimmed while in use: %+v", trim.Kind, trim)
		}
	}
	// The archive_only guard's read-only `docker info` query may run; no
	// trimming command may.
	for _, call := range x.calls(t) {
		if !strings.HasPrefix(call, "docker|info ") {
			t.Fatalf("trim commands ran during live builds: %v", x.calls(t))
		}
	}
	if _, err := os.Stat(filepath.Join(x.cache, "ab", "obj-d")); err != nil {
		t.Fatalf("live cache was touched: %v", err)
	}
}

// Review of #142: `go -C dir build` must count as a live build, and a process
// that cannot be inspected must postpone the Go trim instead of allowing it.
func TestCycleGoTrimFailsClosedOnHiddenOrUninspectableBuilds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, x *trimFixture)
	}{
		{"global -C flag", func(t *testing.T, x *trimFixture) {
			x.process(t, "300", "/usr/local/go/bin/go", "-C", "/workspace", "build", "./...")
		}},
		{"global -C= flag", func(t *testing.T, x *trimFixture) {
			x.process(t, "301", "/usr/local/go/bin/go", "-C=/workspace", "test", "./...")
		}},
		{"unreadable cmdline", func(t *testing.T, x *trimFixture) {
			// A directory where cmdline should be makes the read fail.
			if err := os.MkdirAll(filepath.Join(x.proc, "302", "cmdline"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"unreadable descriptor table", func(t *testing.T, x *trimFixture) {
			x.process(t, "303", "/usr/bin/python3", "worker.py")
			// A regular file where the fd directory should be.
			if err := os.WriteFile(filepath.Join(x.proc, "303", "fd"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newTrimFixture(t)
			x.fill(t, 1<<20)
			tc.setup(t, x)
			goTrim := x.cycle(t)[0]
			if goTrim.Status != "skipped_in_use" || len(goTrim.ActiveUsers) == 0 {
				t.Fatalf("go-build trimmed: %+v", goTrim)
			}
			for _, call := range x.calls(t) {
				if strings.HasPrefix(call, "go|") {
					t.Fatalf("go clean ran: %s", call)
				}
			}
			if _, err := os.Stat(filepath.Join(x.cache, "ab", "obj-d")); err != nil {
				t.Fatalf("cache was touched: %v", err)
			}
		})
	}
}

// watchTrims runs the real watcher loop with the trim fixture's policy and a
// short trim interval, and returns the first cache_trim report.
func (x *trimFixture) watchTrims(t *testing.T) []trimResult {
	t.Helper()
	x.writePolicy(t, fmt.Sprintf(`roots:
  - path: %s
collectors:
  deep_size: false
  git: false
  processes: false
  services: false
  proc_root: %s
prevention:
  min_free_percent: 0
  cache_trims:
    - kind: go-build
      path: %s
      binary: %s
      max_bytes: 65536
    - kind: docker-builder
      binary: %s
      max_bytes: 2147483648
`, x.root, x.proc, x.cache, x.gobin, x.dockerbin))
	sink := &watchSink{reports: make(chan watchReport, 32)}
	e := &env{opts: &globalOpts{format: "json"}, stdout: sink, stderr: io.Discard, lookup: config.MapLookup(x.env)}
	paths, err := e.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := e.loadPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	policy.Prevention.CacheTrimInterval = config.Duration(200 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- watchLoop(ctx, e, paths, policy, func() (eventWatcher, error) { return &scriptedWatcher{}, nil }, watchChurnInterval)
	}()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case report := <-sink.reports:
			if report.Reason != "cache_trim" {
				continue
			}
			raw, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			var decoded struct {
				CacheTrims []trimResult `json:"cache_trims"`
			}
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatal(err)
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatalf("watch loop: %v", err)
			}
			return decoded.CacheTrims
		case err := <-done:
			t.Fatalf("watch loop exited: %v", err)
		case <-deadline:
			t.Fatal("watcher never ran the cache trims")
		}
	}
}

// Between daily cycles the watcher trims an oversized shared Go cache on its
// own interval (owner 394189: the cache regrows ~1 GB/h).
func TestWatchTrimsOversizedBuildCachesBetweenCycles(t *testing.T) {
	x := newTrimFixture(t)
	x.fill(t, 1<<20)
	trims := x.watchTrims(t)
	if len(trims) != 2 || trims[0].Status != "trimmed" {
		t.Fatalf("watcher did not trim the oversized cache: %+v", trims)
	}
	if _, err := os.Stat(filepath.Join(x.cache, "ab", "obj-d")); !os.IsNotExist(err) {
		t.Fatalf("cache payload survived the watcher trim: %v", err)
	}
}

// A trim already running elsewhere (the daily cycle) makes the watcher's
// attempt a reported no-op: two official trims never run at once.
func TestWatchTrimSkipsWhileAnotherTrimRuns(t *testing.T) {
	x := newTrimFixture(t)
	x.fill(t, 1<<20)
	paths, err := config.ResolvePaths(config.MapLookup(x.env), config.Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	release, held, err := tryLockTrim(paths.StateDir)
	if err != nil || !held {
		t.Fatalf("could not hold the trim lock: %v %v", held, err)
	}
	defer release()
	trims := x.watchTrims(t)
	for _, trim := range trims {
		if trim.Status != "skipped_trim_running" {
			t.Fatalf("trim ran while another held the lock: %+v", trim)
		}
	}
	if calls := x.calls(t); len(calls) != 0 {
		t.Fatalf("official commands ran concurrently: %v", calls)
	}
}

// trimReportFailer accepts every report except a cache_trim one, as if the
// output filled up exactly when a trim reported its deletion.
type trimReportFailer struct{}

func (trimReportFailer) Write(p []byte) (int, error) {
	if strings.Contains(string(p), `"reason":"cache_trim"`) {
		return 0, errors.New("file too large")
	}
	return len(p), nil
}

// A trim that deleted bytes must not lose its only report while the watcher
// stays healthy: the write failure ends the watcher with that error.
func TestWatchFailsWhenATrimReportCannotBeWritten(t *testing.T) {
	x := newTrimFixture(t)
	x.fill(t, 1<<20)
	x.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\ncollectors:\n  deep_size: false\n  git: false\n  processes: false\n  services: false\n  proc_root: %s\nprevention:\n  min_free_percent: 0\n  cache_trims:\n    - kind: go-build\n      path: %s\n      binary: %s\n      max_bytes: 65536\n", x.root, x.proc, x.cache, x.gobin))
	e := &env{opts: &globalOpts{format: "json"}, stdout: trimReportFailer{}, stderr: io.Discard, lookup: config.MapLookup(x.env)}
	paths, err := e.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := e.loadPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	policy.Prevention.CacheTrimInterval = config.Duration(200 * time.Millisecond)
	done := make(chan error, 1)
	go func() {
		done <- watchLoop(context.Background(), e, paths, policy, func() (eventWatcher, error) { return &scriptedWatcher{}, nil }, watchChurnInterval)
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "file too large") {
			t.Fatalf("lost trim report not returned: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("watcher kept running after losing a trim report")
	}
}

// Review #147 round 2 P1: a trim path that reaches an archive_only root
// through a symlinked ancestor is refused before any provider runs.
func TestTrimThroughSymlinkIntoArchiveOnlyRootIsRefused(t *testing.T) {
	x := newTrimFixture(t)
	protected := filepath.Join(x.root, "go-build")
	if err := os.MkdirAll(filepath.Join(protected, "ab"), 0o700); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(protected, "ab", "obj-d")
	if err := os.WriteFile(payload, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(x.home, "cache-alias")
	if err := os.Symlink(x.root, alias); err != nil {
		t.Fatal(err)
	}
	x.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\n    archive_only: true\ncollectors:\n  deep_size: false\n  git: false\n  processes: false\n  services: false\n  proc_root: %s\nprevention:\n  min_free_percent: 0\n  cache_trims:\n    - kind: go-build\n      path: %s\n      binary: %s\n      max_bytes: 65536\n", x.root, x.proc, filepath.Join(alias, "go-build"), x.gobin))
	_, _, _ = x.run(t, "cycle")
	if calls := x.calls(t); len(calls) != 0 {
		t.Fatalf("provider ran on an archive_only cache through a symlink: %v", calls)
	}
	if _, err := os.Stat(payload); err != nil {
		t.Fatalf("unarchived payload deleted: %v", err)
	}
}

// Review #147 round 2 P2: shutdown arriving during a later provider command
// must not drop the report of a trim that already deleted bytes.
func TestWatchReportsCompletedTrimWhenCancelledMidRun(t *testing.T) {
	x := newTrimFixture(t)
	x.fill(t, 1<<20)
	started := filepath.Join(x.home, "docker-started")
	slow := filepath.Join(x.home, "slow-docker")
	if err := os.WriteFile(slow, []byte("#!/bin/sh\n: > "+started+"\nexec sleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	x.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\ncollectors:\n  deep_size: false\n  git: false\n  processes: false\n  services: false\n  proc_root: %s\nprevention:\n  min_free_percent: 0\n  cache_trims:\n    - kind: go-build\n      path: %s\n      binary: %s\n      max_bytes: 65536\n    - kind: docker-builder\n      binary: %s\n      max_bytes: 2147483648\n", x.root, x.proc, x.cache, x.gobin, slow))
	out := &lockedBuffer{}
	e := &env{opts: &globalOpts{format: "json"}, stdout: out, stderr: io.Discard, lookup: config.MapLookup(x.env)}
	paths, err := e.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := e.loadPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	policy.Prevention.CacheTrimInterval = config.Duration(100 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cacheTrimLoop(ctx, e, paths, policy) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("second trim never started")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cancelled loop returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("loop did not stop on cancellation")
	}
	if got := out.String(); !strings.Contains(got, `"reason":"cache_trim"`) || !strings.Contains(got, `"status":"trimmed"`) {
		t.Fatalf("completed trim not reported on shutdown: %q", got)
	}
}

// Review #147 round 3 P1: when an archive_only root cannot be resolved the
// trim guard must refuse, not fall back to comparing the paths as written.
func TestTrimRefusedWhenAnArchiveOnlyRootCannotBeResolved(t *testing.T) {
	x := newTrimFixture(t)
	x.fill(t, 1<<20)
	loop := filepath.Join(x.home, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	x.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\n  - path: %s\n    archive_only: true\ncollectors:\n  deep_size: false\n  git: false\n  processes: false\n  services: false\n  proc_root: %s\nprevention:\n  min_free_percent: 0\n  cache_trims:\n    - kind: go-build\n      path: %s\n      binary: %s\n      max_bytes: 65536\n", x.root, filepath.Join(loop, "state"), x.proc, x.cache, x.gobin))
	_, _, _ = x.run(t, "cycle")
	if calls := x.calls(t); len(calls) != 0 {
		t.Fatalf("provider ran although an archive_only root could not be resolved: %v", calls)
	}
}

// Review #147 round 3 P1: a docker-builder trim is checked against the data
// root the daemon reports, not only Docker's default.
func TestDockerTrimRefusedWhenItsDataRootIsArchiveOnly(t *testing.T) {
	x := newTrimFixture(t)
	relocated := filepath.Join(x.root, "docker-data")
	if err := os.MkdirAll(relocated, 0o700); err != nil {
		t.Fatal(err)
	}
	docker := filepath.Join(x.home, "relocated-docker")
	script := "#!/bin/sh\nprintf 'docker|%s\\n' \"$*\" >> " + x.log + "\nif [ \"$1\" = info ]; then echo " + relocated + "; fi\n"
	if err := os.WriteFile(docker, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	x.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\n    archive_only: true\ncollectors:\n  deep_size: false\n  git: false\n  processes: false\n  services: false\n  proc_root: %s\nprevention:\n  min_free_percent: 0\n  cache_trims:\n    - kind: docker-builder\n      binary: %s\n      max_bytes: 2147483648\n", x.root, x.proc, docker))
	_, _, _ = x.run(t, "cycle")
	for _, call := range x.calls(t) {
		if strings.Contains(call, "builder prune") {
			t.Fatalf("docker pruned a data root inside an archive_only root: %v", x.calls(t))
		}
	}
}

// Issue #150: with capacity sampling and cache trims both configured, the
// watcher's goroutines must not share a reassigned context. The race
// detector (CI's -race step) reports the old code; a plain run checks the
// combination starts, trims and stops cleanly.
func TestWatchSamplesAndTrimsTogether(t *testing.T) {
	x := newTrimFixture(t)
	x.fill(t, 1<<20)
	x.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\ncollectors:\n  deep_size: false\n  git: false\n  processes: false\n  services: false\n  proc_root: %s\nprevention:\n  min_free_bytes: 0\n  min_free_percent: 0\n  capacity_interval: 1h\n  targets:\n    - path: %s\n      target_free_bytes: 1\n      recovery_margin_bytes: 1\n  cache_trims:\n    - kind: go-build\n      path: %s\n      binary: %s\n      max_bytes: 65536\n", x.root, x.proc, x.root, x.cache, x.gobin))
	out := &lockedBuffer{}
	e := &env{opts: &globalOpts{format: "json"}, stdout: out, stderr: io.Discard, lookup: config.MapLookup(x.env)}
	paths, err := e.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := e.loadPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	policy.Prevention.CacheTrimInterval = config.Duration(100 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- watchLoop(ctx, e, paths, policy, func() (eventWatcher, error) { return &scriptedWatcher{}, nil }, watchChurnInterval)
	}()
	deadline := time.After(10 * time.Second)
	for !strings.Contains(out.String(), `"status":"trimmed"`) {
		select {
		case err := <-done:
			t.Fatalf("watcher exited early: %v", err)
		case <-deadline:
			t.Fatalf("watcher never trimmed: %q", out.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("clean shutdown returned %v", err)
	}
}
