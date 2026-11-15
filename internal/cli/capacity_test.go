package cli

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/store"
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

// statusData returns the data object of `janitor --format json status args`.
func statusData(t *testing.T, f *fixture, args ...string) map[string]json.RawMessage {
	t.Helper()
	out, stderr, code := f.run(t, append([]string{"--format", "json", "status"}, args...)...)
	if code != ExitOK {
		t.Fatalf("status %v: %d %s %s", args, code, out, stderr)
	}
	var envelope struct {
		Kind string                     `json:"kind"`
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Kind != "status" {
		t.Fatalf("status %v: kind %q: %s", args, envelope.Kind, out)
	}
	return envelope.Data
}

func compactJSON(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		t.Fatalf("compact %s: %v", raw, err)
	}
	return buf.String()
}

// Admission consumers poll `status --capacity` under load: it must publish
// exactly the full status's capacity decision while skipping the costly store
// summaries, and the full status must keep them.
func TestStatusCapacityOnlyMatchesFullStatus(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.home, "workspace")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	f.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\ncollectors:\n  git: false\n  processes: false\n  services: false\nprevention:\n  min_free_percent: 0\n  targets:\n    - path: %s\n      target_free_bytes: 1\n      recovery_margin_bytes: 1\n", root, root))
	if out, stderr, code := f.run(t, "cycle"); code != ExitOK {
		t.Fatalf("cycle: %d %s %s", code, out, stderr)
	}
	full := statusData(t, f)
	capacityOnly := statusData(t, f, "--capacity")
	if len(full["capacity"]) == 0 || compactJSON(t, full["capacity"]) != compactJSON(t, capacityOnly["capacity"]) {
		t.Fatalf("capacity differs:\nfull:     %s\ncapacity: %s", full["capacity"], capacityOnly["capacity"])
	}
	var sampled struct {
		SampledAt string `json:"sampled_at"`
	}
	if err := json.Unmarshal(capacityOnly["capacity"], &sampled); err != nil || sampled.SampledAt == "" {
		t.Fatalf("capacity-only status missed the stored sample: %s", capacityOnly["capacity"])
	}
	for _, key := range []string{"build", "contract_version", "paths", "policy"} {
		if compactJSON(t, full[key]) != compactJSON(t, capacityOnly[key]) {
			t.Errorf("%s differs:\nfull:     %s\ncapacity: %s", key, full[key], capacityOnly[key])
		}
	}
	type storeFields struct {
		Initialized bool            `json:"initialized"`
		Stats       json.RawMessage `json:"stats"`
		ModelUsage  json.RawMessage `json:"model_usage"`
	}
	var fullStore, capacityStore storeFields
	if err := json.Unmarshal(full["store"], &fullStore); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(capacityOnly["store"], &capacityStore); err != nil {
		t.Fatal(err)
	}
	if !fullStore.Initialized || fullStore.Stats == nil || fullStore.ModelUsage == nil || string(full["inventory_report"]) == "null" {
		t.Errorf("full status lost its store summaries: %s inventory=%s", full["store"], full["inventory_report"])
	}
	if !capacityStore.Initialized || capacityStore.Stats != nil || capacityStore.ModelUsage != nil || string(capacityOnly["inventory_report"]) != "null" {
		t.Errorf("capacity-only status read store summaries: %s inventory=%s", capacityOnly["store"], capacityOnly["inventory_report"])
	}
}

// Without a readable database the capacity-only status gives the same
// unknown answer as the full status and, being read-only, neither creates nor
// migrates the database.
func TestStatusCapacityOnlyUnknownWithoutReadableStore(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.home, "workspace")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	f.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\ncollectors:\n  git: false\n  processes: false\n  services: false\nprevention:\n  min_free_percent: 0\n  targets:\n    - path: %s\n      target_free_bytes: 1\n      recovery_margin_bytes: 1\n", root, root))
	dbPath := filepath.Join(f.home, ".local", "state", "workspace-janitor", "janitor.db")
	unknown := compactJSON(t, statusData(t, f, "--capacity")["capacity"])
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("capacity-only status created the database: %v", err)
	}
	if full := compactJSON(t, statusData(t, f)["capacity"]); full != unknown {
		t.Fatalf("uninitialized capacity differs:\nfull:     %s\ncapacity: %s", full, unknown)
	}
	var snapshot struct {
		Volumes []struct {
			State string `json:"state"`
			Hold  bool   `json:"admission_hold"`
		} `json:"volumes"`
	}
	if err := json.Unmarshal([]byte(unknown), &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Volumes) != 1 || snapshot.Volumes[0].State != "measurement_unknown" || !snapshot.Volumes[0].Hold {
		t.Fatalf("uninitialized capacity looks healthy: %s", unknown)
	}
	if out, stderr, code := f.run(t, "cycle"); code != ExitOK {
		t.Fatalf("cycle: %d %s %s", code, out, stderr)
	}
	for _, version := range []int{store.SchemaVersion() - 1, store.SchemaVersion() + 1} {
		setUserVersion(t, dbPath, version)
		if got := compactJSON(t, statusData(t, f, "--capacity")["capacity"]); got != unknown {
			t.Errorf("schema %d: capacity is not unknown:\ngot:  %s\nwant: %s", version, got, unknown)
		}
		if got := userVersion(t, dbPath); got != version {
			t.Errorf("capacity-only status changed schema %d to %d", version, got)
		}
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

func TestCapacityZeroMarginReleasesPriorHoldWithoutPercentageFloor(t *testing.T) {
	f := newFixture(t)
	root := filepath.Join(f.home, "workspace")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	disk, err := measureDisk(root)
	if err != nil {
		t.Fatal(err)
	}
	setPolicy := func(reserve, margin uint64) {
		f.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\ncollectors:\n  git: false\n  processes: false\n  services: false\nprevention:\n  min_free_percent: 0\n  targets:\n    - path: %s\n      target_free_bytes: %d\n      reserve_free_bytes: %d\n      recovery_margin_bytes: %d\n", root, root, disk.TotalBytes*3, reserve, margin))
	}
	setPolicy(disk.TotalBytes*2, 1)
	if out, stderr, code := f.run(t, "scan"); code != ExitOK {
		t.Fatalf("seed critical: %d %s %s", code, out, stderr)
	}
	setPolicy(1, 0)
	if out, stderr, code := f.run(t, "scan"); code != ExitOK {
		t.Fatalf("sample zero margin: %d %s %s", code, out, stderr)
	}
	out, stderr, code := f.run(t, "--format", "json", "status")
	if code != ExitOK {
		t.Fatalf("status: %d %s %s", code, out, stderr)
	}
	var report struct {
		Data struct {
			Capacity struct {
				Volumes []struct {
					State    string `json:"state"`
					Hold     bool   `json:"admission_hold"`
					Reserve  uint64 `json:"reserve_bytes"`
					Recovery uint64 `json:"recovery_bytes"`
				} `json:"volumes"`
			} `json:"capacity"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	volumes := report.Data.Capacity.Volumes
	if len(volumes) != 1 {
		t.Fatalf("missing measured device: %s", out)
	}
	v := volumes[0]
	if v.State != "cleanup_needed" || v.Hold || v.Reserve != 1 || v.Recovery != 1 {
		t.Fatalf("warning retained hold or hidden floor: %s", out)
	}
	// A second root adds real hysteresis without turning the first root's
	// warning-only target into an admission requirement.
	second := filepath.Join(f.home, "second")
	if err := os.Mkdir(second, 0700); err != nil {
		t.Fatal(err)
	}
	setPolicy(disk.TotalBytes*2, 1)
	if out, stderr, code := f.run(t, "scan"); code != ExitOK {
		t.Fatalf("reseed critical: %d %s %s", code, out, stderr)
	}
	f.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\n  - path: %s\ncollectors:\n  git: false\n  processes: false\n  services: false\nprevention:\n  min_free_percent: 0\n  targets:\n    - path: %s\n      target_free_bytes: %d\n      reserve_free_bytes: 1\n      recovery_margin_bytes: 0\n    - path: %s\n      target_free_bytes: 1\n      reserve_free_bytes: 0\n      recovery_margin_bytes: 1\n", root, second, root, disk.TotalBytes*3, second))
	if out, stderr, code := f.run(t, "scan"); code != ExitOK {
		t.Fatalf("mixed-margin sample: %d %s %s", code, out, stderr)
	}
	out, stderr, code = f.run(t, "--format", "json", "status")
	if code != ExitOK {
		t.Fatalf("mixed-margin status: %d %s %s", code, out, stderr)
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Data.Capacity.Volumes) != 1 {
		t.Fatalf("shared roots must produce one device: %s", out)
	}
	v = report.Data.Capacity.Volumes[0]
	if v.State != "cleanup_needed" || v.Hold || v.Reserve != 1 || v.Recovery != 2 {
		t.Fatalf("mixed-margin warning retained hold: %s", out)
	}
}
