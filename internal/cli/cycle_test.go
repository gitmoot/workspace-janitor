package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCycleDailyMetadataWeeklyDeepAndNoModelCalls(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.home, "workspace")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	f.env["OPENROUTER_API_KEY"] = "fixture-only"
	f.writePolicy(t, "roots:\n  - path: "+root+"\ncollectors:\n  deep_size: true\n  git: false\n  processes: false\n  services: false\nprevention:\n  deep_interval: 168h\n  min_free_percent: 0\njev:\n  enabled: true\n  endpoint: "+server.URL+"/api/v1/systemone\n")
	out, stderr, code := f.run(t, "cycle")
	if code != ExitOK {
		t.Fatalf("first cycle: %s %s", out, stderr)
	}
	var first cycleReport
	if err := json.Unmarshal([]byte(out), &first); err != nil || !first.Deep || first.ScanID == "" {
		t.Fatalf("initial deep scan: %+v %v", first, err)
	}
	out, stderr, code = f.run(t, "cycle")
	if code != ExitOK {
		t.Fatalf("second cycle: %s %s", out, stderr)
	}
	var second cycleReport
	if err := json.Unmarshal([]byte(out), &second); err != nil || second.Deep || second.ScanID == first.ScanID {
		t.Fatalf("daily metadata scan: %+v %v", second, err)
	}
	if requests.Load() != 0 {
		t.Fatalf("background cycle made %d model/network requests", requests.Load())
	}
	// Policy cadence changes take effect without rewriting scan history.
	f.writePolicy(t, "roots:\n  - path: "+root+"\ncollectors:\n  git: false\n  processes: false\n  services: false\nprevention:\n  deep_interval: 1ns\n  min_free_percent: 0\n")
	out, stderr, code = f.run(t, "cycle")
	if code != ExitOK {
		t.Fatalf("third cycle: %s %s", out, stderr)
	}
	var third cycleReport
	if err := json.Unmarshal([]byte(out), &third); err != nil || !third.Deep {
		t.Fatalf("overdue deep scan: %+v %v", third, err)
	}
}

func TestDiskAlertSeparatesBytesAndDeduplicatesAcrossCycles(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.home, "workspace")
	for _, path := range []string{filepath.Join(root, "dist"), filepath.Join(root, "protected"), filepath.Join(root, "mystery")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "payload"), []byte(strings.Repeat("x", 8192)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	proc, units := filepath.Join(f.home, "proc"), filepath.Join(f.home, "units")
	for _, path := range []string{proc, units} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	f.writePolicy(t, "roots:\n  - path: "+root+"\ncollectors:\n  proc_root: "+proc+"\n  systemd_dirs:\n    - "+units+"\n  cron_paths: []\n  pm2_dumps: []\nprotect:\n  paths:\n    - "+filepath.Join(root, "protected")+"\nprevention:\n  min_free_bytes: 1152921504606846976\n  min_free_percent: 0\n  alert_interval: 24h\n")
	out, stderr, code := f.run(t, "cycle")
	if code != ExitOK {
		t.Fatalf("first disk cycle: %s %s", out, stderr)
	}
	var first cycleReport
	if err := json.Unmarshal([]byte(out), &first); err != nil || len(first.DiskAlerts) != 1 {
		t.Fatalf("missing disk alert: %+v %v", first, err)
	}
	alert := first.DiskAlerts[0]
	if alert.ReclaimableBytes == nil || alert.ProtectedBytes == nil || alert.UnknownBytes == nil ||
		*alert.ReclaimableBytes == 0 || *alert.ProtectedBytes == 0 || *alert.UnknownBytes == 0 {
		t.Fatalf("disk categories were not separately measured: %+v", alert)
	}
	out, stderr, code = f.run(t, "cycle")
	if code != ExitOK {
		t.Fatalf("second disk cycle: %s %s", out, stderr)
	}
	var second cycleReport
	if err := json.Unmarshal([]byte(out), &second); err != nil || len(second.DiskAlerts) != 0 {
		t.Fatalf("duplicate alert within cooldown: %+v %v", second, err)
	}
}

func TestDiskAlertDoesNotCallSkippedSafetyEvidenceReclaimable(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.home, "workspace")
	cache := filepath.Join(root, "dist")
	if err := os.MkdirAll(cache, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "payload"), []byte(strings.Repeat("x", 8192)), 0600); err != nil {
		t.Fatal(err)
	}
	f.writePolicy(t, "roots:\n  - path: "+root+"\ncollectors:\n  git: false\n  processes: false\n  services: false\nprevention:\n  min_free_bytes: 1152921504606846976\n  min_free_percent: 0\n")
	out, stderr, code := f.run(t, "cycle")
	if code != ExitOK {
		t.Fatalf("disk cycle: %s %s", out, stderr)
	}
	var report cycleReport
	if err := json.Unmarshal([]byte(out), &report); err != nil || len(report.DiskAlerts) != 1 {
		t.Fatalf("missing disk alert: %+v %v", report, err)
	}
	alert := report.DiskAlerts[0]
	if alert.ReclaimableBytes == nil || *alert.ReclaimableBytes != 0 || alert.UnknownBytes == nil || *alert.UnknownBytes == 0 {
		t.Fatalf("skipped safety evidence counted as reclaimable: %+v", alert)
	}
}
