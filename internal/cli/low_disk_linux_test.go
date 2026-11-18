//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

// lineSink hands each JSON report line the watcher writes to lines. Tests
// decode the public JSON shape, not internal types, so the old code fails
// them on behavior rather than on compilation.
type lineSink struct {
	mu      sync.Mutex
	pending []byte
	lines   chan []byte
}

func (s *lineSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = append(s.pending, p...)
	for {
		end := bytes.IndexByte(s.pending, '\n')
		if end < 0 {
			return len(p), nil
		}
		select {
		case s.lines <- append([]byte(nil), s.pending[:end]...):
		default: // the test stopped reading
		}
		s.pending = s.pending[end+1:]
	}
}

// startWatch runs the real watch loop on the fixture's policy and returns
// its report lines and a stop function that ends it.
func startWatch(t *testing.T, x *trimFixture) (<-chan []byte, func()) {
	t.Helper()
	sink := &lineSink{lines: make(chan []byte, 4096)}
	e := &env{opts: &globalOpts{format: "json"}, stdout: sink, stderr: io.Discard, lookup: config.MapLookup(x.env)}
	paths, err := e.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := e.loadPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- watchLoop(ctx, e, paths, policy, func() (eventWatcher, error) { return &scriptedWatcher{}, nil }, watchChurnInterval)
	}()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		if err := <-done; err != nil {
			t.Errorf("watch loop: %v", err)
		}
	}
	t.Cleanup(stop)
	return sink.lines, stop
}

type lowDiskLine struct {
	Reason     string       `json:"reason"`
	CacheTrims []trimResult `json:"cache_trims"`
	LowDisk    *struct {
		Status     string   `json:"status"`
		CacheRules []string `json:"cache_rules"`
		Quarantine string   `json:"quarantine"`
		Expiry     string   `json:"expiry"`
	} `json:"low_disk"`
	Error string `json:"error"`
}

// Below prevention.low_disk.min_free_bytes the watcher runs, without waiting
// for the daily cycle, the standing cache trims (not docker-images) and the
// size-bounded cache rules through quarantine and expiry, and nothing else:
// a ttl cache rule the cycle would act on stays. It runs again only after
// min_interval, however low the disk stays.
func TestLowDiskTriggerRunsOnlyCacheTrimsAndIsRateLimited(t *testing.T) {
	x := newTrimFixture(t)
	x.fill(t, 1<<20)
	bounded := filepath.Join(x.root, "uv-cache")
	aged := filepath.Join(x.root, "aged-cache")
	units := filepath.Join(x.home, "systemd")
	for _, dir := range []string{bounded, aged} {
		writeFile(t, filepath.Join(dir, "payload"), strings.Repeat("x", 8192))
	}
	if err := os.MkdirAll(units, 0o700); err != nil {
		t.Fatal(err)
	}
	backdate(t, aged, 48*time.Hour)
	x.writePolicy(t, fmt.Sprintf(`roots:
  - path: %[1]s
collectors:
  deep_size: false
  git: false
  processes: false
  services: true
  proc_root: %[2]s
  systemd_dirs:
    - %[3]s
  cron_paths: []
  pm2_dumps: []
caches:
  - name: uv
    path: %[4]s
    action: quarantine
    retention: none
    max_bytes: 1024
  - name: aged
    path: %[5]s
    action: quarantine
    retention: none
    ttl: 1h
retention:
  delete_enabled: true
prevention:
  min_free_percent: 0
  auto_quarantine: true
  auto_expire: true
  cache_trim_interval: 2h
  low_disk:
    path: %[1]s
    min_free_bytes: 9223372036854775807
    check_interval: 1s
    min_interval: 1h
  cache_trims:
    - kind: go-build
      path: %[6]s
      binary: %[7]s
      max_bytes: 65536
    - kind: docker-builder
      binary: %[8]s
      max_bytes: 2147483648
    - kind: docker-images
      binary: %[8]s
      min_age: 168h
`, x.root, x.proc, units, bounded, aged, x.cache, x.gobin, x.dockerbin))
	lines, stop := startWatch(t, x)
	deadline := time.After(60 * time.Second)
	var ran lowDiskLine
	for ran.LowDisk == nil || ran.LowDisk.Status != "ran" {
		select {
		case line := <-lines:
			var report lowDiskLine
			if err := json.Unmarshal(line, &report); err != nil {
				t.Fatal(err)
			}
			if report.Reason == "low_disk" {
				ran = report
			}
		case <-deadline:
			t.Fatal("the watcher never ran the low-disk trims")
		}
	}
	if ran.Error != "" || ran.LowDisk.Quarantine != "applied" || ran.LowDisk.Expiry != "checked" ||
		len(ran.LowDisk.CacheRules) != 1 || ran.LowDisk.CacheRules[0] != "uv" {
		t.Fatalf("low-disk run: %+v %+v", ran, *ran.LowDisk)
	}
	var kinds []string
	for _, trim := range ran.CacheTrims {
		kinds = append(kinds, trim.Kind+"="+trim.Status)
	}
	if strings.Join(kinds, ",") != "go-build=trimmed,docker-builder=trimmed" {
		t.Fatalf("low-disk cache trims = %v", kinds)
	}
	if _, err := os.Lstat(bounded); !os.IsNotExist(err) {
		t.Fatalf("size-bounded cache was not removed: %v", err)
	}
	if !exists(t, filepath.Join(aged, "payload")) {
		t.Fatal("the low-disk run acted on a cache rule that is not size-bounded")
	}
	// Still low, and the Go cache has regrown: within min_interval nothing
	// runs again.
	x.fill(t, 1<<20)
	quiet := time.After(3500 * time.Millisecond)
	for waiting := true; waiting; {
		select {
		case line := <-lines:
			var report lowDiskLine
			if err := json.Unmarshal(line, &report); err != nil {
				t.Fatal(err)
			}
			if report.Reason == "low_disk" {
				t.Fatalf("low-disk trims ran again within min_interval: %s", line)
			}
		case <-quiet:
			waiting = false
		}
	}
	stop()
	if !exists(t, filepath.Join(x.cache, "ab", "obj-d")) {
		t.Fatal("the regrown cache was trimmed within min_interval")
	}
}

// The notification settings are not part of the capacity contract Gitmoot
// reads: the policy hash and every volume's state, hold, target, reserve,
// recovery bytes and reason are identical with and without them.
func TestNotifyThresholdLeavesCapacityContractUnchanged(t *testing.T) {
	x := newTrimFixture(t)
	notify := filepath.Join(x.home, "notify")
	writeFile(t, notify, "#!/bin/sh\n")
	base := fmt.Sprintf("roots:\n  - path: %s\ncollectors:\n  deep_size: false\n  git: false\n  processes: false\n  services: false\nprevention:\n  min_free_percent: 0\n  targets:\n    - path: %[1]s\n      target_free_bytes: 20000000000\n      reserve_free_bytes: 10000000000\n", x.root)
	sample := func(document string) (string, string) {
		t.Helper()
		x.writePolicy(t, document)
		e := &env{opts: &globalOpts{format: "json"}, stdout: io.Discard, stderr: io.Discard, lookup: config.MapLookup(x.env)}
		paths, err := e.resolvePaths()
		if err != nil {
			t.Fatal(err)
		}
		policy, err := e.loadPolicy(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, _, code := x.run(t, "scan"); code != ExitOK {
			t.Fatal("scan failed")
		}
		snapshot, err := sampleCapacity(context.Background(), policy, paths, time.Now().UTC(), true)
		if err != nil {
			t.Fatal(err)
		}
		for i := range snapshot.Volumes {
			snapshot.Volumes[i].AvailableBytes, snapshot.Volumes[i].TotalBytes = nil, nil
		}
		volumes, err := json.Marshal(snapshot.Volumes)
		if err != nil {
			t.Fatal(err)
		}
		return snapshot.PolicyHash, string(volumes)
	}
	hash, volumes := sample(base)
	notifyHash, notifyVolumes := sample(base + "  notify_command: [" + notify + ", jarvis]\n  notify_below_bytes: 40000000000\n  notify_cooldown: 1h\n  notify_timeout: 30s\n")
	if hash != notifyHash || volumes != notifyVolumes {
		t.Fatalf("notify settings changed the capacity contract:\nwithout %s %s\nwith    %s %s", hash, volumes, notifyHash, notifyVolumes)
	}
}

// notifierFixture drives the capacity notifier directly with synthetic
// samples and sample times, so no test depends on the watcher's sampling
// clock. Its command logs each call and, while hold exists, waits for it to
// be removed.
type notifierFixture struct {
	x                       *trimFixture
	log, hold, started, pid string
	lines                   <-chan []byte
	publish                 func(*core.CapacitySnapshot, time.Time)
	stop                    func()
	t0                      time.Time
}

func newNotifierFixture(t *testing.T, script string) *notifierFixture {
	t.Helper()
	x := newTrimFixture(t)
	n := &notifierFixture{x: x, log: filepath.Join(x.home, "notified.log"), hold: filepath.Join(x.home, "hold"),
		started: filepath.Join(x.home, "started"), pid: filepath.Join(x.home, "child.pid"),
		t0: time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)}
	if script != "" {
		script = strings.ReplaceAll(script, "{pid}", n.pid)
	} else {
		script = "printf '%s\\n' \"$1\" >> " + n.log + "\ntouch " + n.started + "\ni=0\nwhile [ -e " + n.hold + " ] && [ $i -lt 1200 ]; do sleep 0.05; i=$((i+1)); done\n"
	}
	notify := filepath.Join(x.home, "notify")
	writeFile(t, notify, "#!/bin/sh\n"+script)
	if err := os.Chmod(notify, 0o700); err != nil {
		t.Fatal(err)
	}
	x.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\ncollectors:\n  deep_size: false\n  git: false\n  processes: false\n  services: false\n", x.root))
	sink := &lineSink{lines: make(chan []byte, 4096)}
	e := &env{opts: &globalOpts{format: "json"}, stdout: sink, stderr: io.Discard, lookup: config.MapLookup(x.env)}
	paths, err := e.resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := e.loadPolicy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	policy.Prevention.NotifyCommand = []string{notify}
	policy.Prevention.NotifyBelowBytes = 40_000_000_000
	policy.Prevention.NotifyCooldown = config.Duration(time.Hour)
	policy.Prevention.NotifyTimeout = config.Duration(time.Minute)
	n.lines = sink.lines
	n.publish, _, n.stop = startCapacityNotifier(context.Background(), e, paths, policy)
	t.Cleanup(n.stop)
	return n
}

// sample publishes a sample with free bytes available, taken offset after
// the fixture's start, and waits until the notifier has checked delivery
// for it: its persisted state names that sample time.
func (n *notifierFixture) sample(t *testing.T, free uint64, offset time.Duration) {
	t.Helper()
	at := n.t0.Add(offset)
	total := uint64(1_000_000_000_000)
	n.publish(&core.CapacitySnapshot{Volumes: []core.CapacityState{{Key: "root:/", Roots: []string{"/"},
		AvailableBytes: &free, TotalBytes: &total, TargetBytes: 20_000_000_000, ReserveBytes: 10_000_000_000}}}, at)
	n.processed(t, at)
}

func (n *notifierFixture) processed(t *testing.T, at time.Time) {
	t.Helper()
	path := filepath.Join(n.x.home, ".local", "state", "workspace-janitor", "capacity-notify.json")
	deadline := time.Now().Add(time.Minute)
	for {
		var state struct {
			SampledAt time.Time `json:"sampled_at"`
		}
		if raw, err := os.ReadFile(path); err == nil && json.Unmarshal(raw, &state) == nil && !state.SampledAt.Before(at) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the notifier never checked delivery for the sample at %s", at.Format(time.RFC3339))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (n *notifierFixture) calls(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(n.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

func (n *notifierFixture) waitFor(t *testing.T, path string) {
	t.Helper()
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never appeared", path)
		}
	}
}

// A sample below notify_below_bytes runs notify_command once with the
// warning as its last argument: on the transition below, not on every
// sample that stays below, even long after the cooldown. A recovery and a
// new fall below notify again.
func TestCapacityWarningNotifiesOncePerTransition(t *testing.T) {
	n := newNotifierFixture(t, "")
	n.sample(t, 30_000_000_000, 0)
	for i, offset := range []time.Duration{time.Minute, 3 * time.Hour, 5 * time.Hour} {
		n.sample(t, 29_000_000_000-uint64(i), offset)
	}
	calls := n.calls(t)
	if len(calls) != 1 || !strings.HasPrefix(calls[0], "workspace-janitor on ") || !strings.Contains(calls[0], "/ has 30.0 GB free, below 40.0 GB (warning target 20.0 GB, blocking below 10.0 GB)") {
		t.Fatalf("notify_command calls while staying below: %q", calls)
	}
	n.sample(t, 50_000_000_000, 6*time.Hour)
	n.sample(t, 35_000_000_000, 7*time.Hour)
	if calls := n.calls(t); len(calls) != 2 {
		t.Fatalf("a new fall below the threshold was not notified: %q", calls)
	}
}

// Samples published while the command runs still change the transition
// state: below, then recovered, then below again during the first
// notification is a new episode, notified once the cooldown has passed.
func TestCapacityNotifyKeepsTransitionsDuringRun(t *testing.T) {
	n := newNotifierFixture(t, "")
	writeFile(t, n.hold, "")
	total := uint64(1_000_000_000_000)
	snapshot := func(free uint64) *core.CapacitySnapshot {
		return &core.CapacitySnapshot{Volumes: []core.CapacityState{{Key: "root:/", Roots: []string{"/"},
			AvailableBytes: &free, TotalBytes: &total, TargetBytes: 20_000_000_000, ReserveBytes: 10_000_000_000}}}
	}
	n.publish(snapshot(30_000_000_000), n.t0)
	n.waitFor(t, n.started)
	// While the first notification runs: recovered, then below again.
	n.publish(snapshot(50_000_000_000), n.t0.Add(time.Minute))
	n.publish(snapshot(30_000_000_000), n.t0.Add(2*time.Minute))
	if err := os.Remove(n.hold); err != nil {
		t.Fatal(err)
	}
	n.processed(t, n.t0.Add(2*time.Minute))
	if calls := n.calls(t); len(calls) != 1 {
		t.Fatalf("calls within the cooldown: %q", calls)
	}
	n.sample(t, 30_000_000_000, 2*time.Hour)
	if calls := n.calls(t); len(calls) != 2 {
		t.Fatalf("the fall below during the first run was never notified: %q", calls)
	}
}

// A notify command that exits while a child it forked keeps its output
// open and sleeps holds neither publication nor the notifier: publish
// returns at once throughout, the run ends within notify_timeout and the
// pipe drain bound, and the child is killed with its process group.
func TestCapacityNotifyCannotStallSampling(t *testing.T) {
	n := newNotifierFixture(t, "sleep 60 &\necho $! > {pid}\necho sent\n")
	total, free := uint64(1_000_000_000_000), uint64(30_000_000_000)
	snapshot := &core.CapacitySnapshot{Volumes: []core.CapacityState{{Key: "root:/", Roots: []string{"/"},
		AvailableBytes: &free, TotalBytes: &total, TargetBytes: 20_000_000_000, ReserveBytes: 10_000_000_000}}}
	start := time.Now()
	published := make(chan struct{})
	go func() {
		defer close(published)
		for i := range 50 {
			n.publish(snapshot, n.t0.Add(time.Duration(i)*time.Second))
		}
	}()
	select {
	case <-published:
	case <-time.After(30 * time.Second):
		t.Fatal("publish blocked while the notify command ran")
	}
	n.processed(t, n.t0.Add(49*time.Second))
	// The child sleeps 60s holding the output; the run must not wait for it.
	if took := time.Since(start); took > 30*time.Second {
		t.Fatalf("the notify run waited %s for the child holding its output", took)
	}
	raw, err := os.ReadFile(n.pid)
	if err != nil {
		t.Fatal(err)
	}
	stat := filepath.Join("/proc", strings.TrimSpace(string(raw)), "stat")
	for wait := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		data, err := os.ReadFile(stat)
		// Gone, or a zombie awaiting its reaper: either way not running.
		if err != nil || strings.Contains(string(data), ") Z ") {
			break
		}
		if time.Now().After(wait) {
			t.Fatalf("the notify command's child outlived it: %s", data)
		}
	}
}
