package cli

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCapacityPersistsHysteresisAcrossCLIInvocations(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.home, "workspace")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	disk, err := measureDisk(root)
	if err != nil {
		t.Fatal(err)
	}
	if disk.FreeBytes <= disk.TotalBytes/20+1 {
		t.Skip("fixture filesystem lacks recovery headroom")
	}
	policy := func(target, reserve, margin uint64) {
		f.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\ncollectors:\n  git: false\n  processes: false\n  services: false\nprevention:\n  min_free_bytes: 0\n  min_free_percent: 0\n  capacity_interval: 1h\n  targets:\n    - path: %s\n      target_free_bytes: %d\n      reserve_free_bytes: %d\n      recovery_margin_bytes: %d\n", root, root, target, reserve, margin))
	}
	assertState := func(command, want string, hold bool) string {
		out, stderr, code := f.run(t, "--format", "json", command)
		if code != ExitOK {
			t.Fatalf("%s: %d %s %s", command, code, out, stderr)
		}
		var report map[string]json.RawMessage
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatal(err)
		}
		if data, ok := report["data"]; ok {
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
		}
		var snapshot struct {
			SampledAt string `json:"sampled_at"`
			Volumes   []struct {
				State string `json:"state"`
				Hold  bool   `json:"admission_hold"`
			} `json:"volumes"`
		}
		if err := json.Unmarshal(report["capacity"], &snapshot); err != nil {
			t.Fatal(err)
		}
		if len(snapshot.Volumes) != 1 || snapshot.Volumes[0].State != want || snapshot.Volumes[0].Hold != hold {
			t.Fatalf("unexpected capacity: %s", out)
		}
		return snapshot.SampledAt
	}
	// More than the filesystem's entire capacity forces critical pressure,
	// without filling a shared disk or relying on a mocked measurement.
	policy(disk.TotalBytes*3, disk.TotalBytes*2, 1)
	stamp := assertState("cycle", "critical", true)
	if readStamp := assertState("status", "critical", true); stamp != readStamp {
		t.Fatal("read-only status resampled capacity")
	}
	if nextStamp := assertState("cycle", "critical", true); stamp != nextStamp {
		t.Fatal("second process ignored persistent sampling interval")
	}
	// Above reserve is not recovery: preserve the hold through hysteresis.
	policy(1, 0, disk.TotalBytes*2)
	assertState("cycle", "cleanup_needed", true)
	assertState("status", "cleanup_needed", true)
	policy(1, 0, 1)
	assertState("cycle", "target_recovered", false)
	assertState("status", "target_recovered", false)
}

func TestCapacityGroupsSharedFilesystemRoots(t *testing.T) {
	f := newFixture(t)
	first, second := filepath.Join(f.home, "one"), filepath.Join(f.home, "two")
	for _, root := range []string{first, second} {
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal(err)
		}
	}
	f.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\n  - path: %s\ncollectors:\n  git: false\n  processes: false\n  services: false\nprevention:\n  min_free_percent: 0\n  targets:\n    - path: %s\n      target_free_bytes: 1\n      recovery_margin_bytes: 1\n    - path: %s\n      target_free_bytes: 2\n      recovery_margin_bytes: 2\n", first, second, first, second))
	out, stderr, code := f.run(t, "cycle")
	if code != ExitOK {
		t.Fatalf("cycle: %d %s %s", code, out, stderr)
	}
	var report struct {
		Capacity struct {
			Volumes []struct {
				Roots     []string `json:"roots"`
				Available *uint64  `json:"available_bytes"`
			} `json:"volumes"`
		} `json:"capacity"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Capacity.Volumes) != 1 || len(report.Capacity.Volumes[0].Roots) != 2 || report.Capacity.Volumes[0].Available == nil {
		t.Fatalf("shared device duplicated or not measured: %s", out)
	}
}

func TestCapacityMissingSampleIsUnknown(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.home, "missing")
	f.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\nprevention:\n  targets:\n    - path: %s\n      target_free_bytes: 100\n      recovery_margin_bytes: 10\n", root, root))
	out, stderr, code := f.run(t, "--format", "json", "status")
	if code != ExitOK {
		t.Fatalf("status: %d %s %s", code, out, stderr)
	}
	var report struct {
		Data struct {
			Capacity struct {
				Volumes []struct {
					State     string  `json:"state"`
					Hold      bool    `json:"admission_hold"`
					Available *uint64 `json:"available_bytes"`
				} `json:"volumes"`
			} `json:"capacity"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Data.Capacity.Volumes) != 1 {
		t.Fatalf("missing target state: %s", out)
	}
	volume := report.Data.Capacity.Volumes[0]
	if volume.State != "measurement_unknown" || !volume.Hold || volume.Available != nil {
		t.Fatalf("missing measurement looks healthy: %s", out)
	}
}

func TestCapacityMeasurementFailurePersistsUnknown(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.home, "workspace")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	f.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\ncollectors:\n  git: false\n  processes: false\n  services: false\nprevention:\n  min_free_percent: 0\n  targets:\n    - path: %s\n      target_free_bytes: 1\n      recovery_margin_bytes: 1\n", root, root))
	if out, stderr, code := f.run(t, "scan"); code != ExitOK {
		t.Fatalf("seed capacity: %s %s", out, stderr)
	}
	dbPath := filepath.Join(f.home, ".local", "state", "workspace-janitor", "janitor.db")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE capacity_snapshot SET snapshot = json_set(snapshot,
		'$.sampled_at', '2000-01-01T00:00:00Z', '$.valid_until', '2000-01-01T00:01:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	// The inventory may fail too; the independently measured pressure must
	// already have persisted a fresh unknown observation, not stale health.
	f.run(t, "scan")
	out, stderr, code := f.run(t, "--format", "json", "status")
	if code != ExitOK {
		t.Fatalf("status after measurement failure: %s %s", out, stderr)
	}
	var report struct {
		Data struct {
			Capacity struct {
				SampledAt string `json:"sampled_at"`
				Volumes   []struct {
					State     string  `json:"state"`
					Hold      bool    `json:"admission_hold"`
					Available *uint64 `json:"available_bytes"`
				} `json:"volumes"`
			} `json:"capacity"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	snapshot := report.Data.Capacity
	if snapshot.SampledAt == "2000-01-01T00:00:00Z" || len(snapshot.Volumes) != 1 {
		t.Fatalf("failed measurement was not persisted: %s", out)
	}
	volume := snapshot.Volumes[0]
	if volume.State != "measurement_unknown" || !volume.Hold || volume.Available != nil {
		t.Fatalf("failed measurement looked healthy: %s", out)
	}
}
