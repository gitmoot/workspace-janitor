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

// A capacity sample below prevention.notify_below_bytes runs notify_command
// once with the warning as its last argument: on the transition below it,
// not on every sample that stays below it. The threshold is informational:
// a volume above its own warning target stays target_recovered, no hold.
func TestCapacityWarningNotifiesOncePerTransition(t *testing.T) {
	x := newTrimFixture(t)
	log := filepath.Join(x.home, "notified.log")
	notify := filepath.Join(x.home, "notify")
	writeFile(t, notify, "#!/bin/sh\nprintf '%s|%s\\n' \"$1\" \"$2\" >> "+log+"\n")
	if err := os.Chmod(notify, 0o700); err != nil {
		t.Fatal(err)
	}
	x.writePolicy(t, fmt.Sprintf(`roots:
  - path: %s
collectors:
  deep_size: false
  git: false
  processes: false
  services: false
prevention:
  min_free_percent: 0
  capacity_interval: 1s
  targets:
    - path: %[1]s
      target_free_bytes: 1
      reserve_free_bytes: 0
  notify_command: [%s, jarvis]
  notify_below_bytes: 9000000000000000000
  notify_timeout: 1s
`, x.root, notify))
	lines, stop := startWatch(t, x)
	samples := 0
	deadline := time.After(30 * time.Second)
	for samples < 4 {
		select {
		case line := <-lines:
			var report struct {
				Reason   string `json:"reason"`
				Capacity *struct {
					Volumes []struct {
						State         string `json:"state"`
						AdmissionHold bool   `json:"admission_hold"`
					} `json:"volumes"`
				} `json:"capacity"`
			}
			if err := json.Unmarshal(line, &report); err != nil {
				t.Fatal(err)
			}
			if report.Reason != "capacity" || report.Capacity == nil {
				continue
			}
			for _, volume := range report.Capacity.Volumes {
				// An unmeasured sample is unknown whatever the policy says.
				if volume.State != "measurement_unknown" && (volume.State != "target_recovered" || volume.AdmissionHold) {
					t.Fatalf("the notify threshold changed capacity state: %s", line)
				}
			}
			samples++
		case <-deadline:
			t.Fatalf("only %d capacity samples", samples)
		}
	}
	stop()
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("notify_command never ran: %v", err)
	}
	calls := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(calls) != 1 || !strings.HasPrefix(calls[0], "jarvis|workspace-janitor on ") || !strings.Contains(calls[0], "below 9000000000.0 GB (warning target 0.0 GB") {
		t.Fatalf("notify_command calls over %d samples below the threshold: %q", samples, calls)
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
