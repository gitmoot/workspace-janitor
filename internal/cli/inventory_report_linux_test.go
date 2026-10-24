//go:build linux

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type inventoryStatusDocument struct {
	Data struct {
		Inventory *struct {
			Growth struct {
				Status         string
				ScanID         string `json:"scan_id"`
				PreviousScanID string `json:"previous_scan_id"`
				Changes        []struct {
					Path   string
					Change *int64 `json:"change_apparent_bytes"`
					Reason string
				} `json:"changes"`
			} `json:"growth"`
			Activities []struct {
				Kind, State         string
				Completed, Replayed int
				Actual              *int64  `json:"actual_reclaimed_bytes"`
				Before              *uint64 `json:"available_before_bytes"`
				After               *uint64 `json:"available_after_bytes"`
			} `json:"activities"`
		} `json:"inventory_report"`
	} `json:"data"`
}

func decodeInventoryStatus(t *testing.T, data string) inventoryStatusDocument {
	t.Helper()
	var doc inventoryStatusDocument
	if err := json.Unmarshal([]byte(data), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Data.Inventory == nil {
		t.Fatal("status omitted inventory and operation evidence")
	}
	return doc
}

func scanInventoryStatus(t *testing.T, f *scanFixture) inventoryStatusDocument {
	t.Helper()
	out, stderr, code := f.run(t, "--format", "json", "status")
	if code != ExitOK {
		t.Fatalf("status failed: %s", stderr)
	}
	return decodeInventoryStatus(t, out)
}

func TestInventoryGrowthKeepsDeepBaselineAcrossMetadataScans(t *testing.T) {
	f := newScanFixture(t)
	first := f.scanJSON(t, "--deep-size")
	if err := os.WriteFile(filepath.Join(f.root, "project", "nested", "deep.txt"), []byte("deep+growth"), 0644); err != nil {
		t.Fatal(err)
	}
	f.scanJSON(t)
	latest := f.scanJSON(t, "--deep-size")
	f.scanJSON(t)
	doc := scanInventoryStatus(t, f)
	if doc.Data.Inventory.Growth.ScanID != latest.Data.Scan.ID || doc.Data.Inventory.Growth.PreviousScanID != first.Data.Scan.ID {
		t.Fatalf("metadata scans displaced comparable deep observations: %+v", doc.Data.Inventory.Growth)
	}
	for _, row := range doc.Data.Inventory.Growth.Changes {
		if row.Path == filepath.Join(f.root, "project") {
			if row.Change == nil || *row.Change != 7 {
				t.Fatalf("real seven-byte growth misreported: %+v", row)
			}
			return
		}
	}
	t.Fatal("grown project missing")
}

func TestInventoryGrowthDoesNotTurnIncompleteTreesIntoZero(t *testing.T) {
	f := newScanFixture(t)
	f.writePolicy(t, "roots:\n  - path: "+f.root+"\n    max_depth: 1\ncollectors:\n  git: false\n  processes: false\n  services: false\nlimits:\n  deep_size_max_depth: 1\n")
	f.scanJSON(t, "--deep-size")
	f.scanJSON(t, "--deep-size")
	doc := scanInventoryStatus(t, f)
	for _, row := range doc.Data.Inventory.Growth.Changes {
		if row.Path == filepath.Join(f.root, "project") {
			if row.Change != nil || row.Reason != "measurement_incomplete_or_shallow" {
				t.Fatalf("bounded tree became measured zero growth: %+v", row)
			}
			return
		}
	}
	t.Fatal("incomplete tree was hidden from the report")
}

func TestInventoryGrowthRejectsChangedPolicyScope(t *testing.T) {
	f := newScanFixture(t)
	f.scanJSON(t, "--deep-size")
	f.scanJSON(t, "--deep-size")
	f.writePolicy(t, "roots:\n  - path: "+f.root+"\n    max_depth: 2\ncollectors:\n  git: false\n  processes: false\n  services: false\n")
	doc := scanInventoryStatus(t, f)
	if doc.Data.Inventory.Growth.Status != "configured_scope_mismatch" {
		t.Fatalf("old observations inherited new scope: %+v", doc.Data.Inventory.Growth)
	}
	for _, row := range doc.Data.Inventory.Growth.Changes {
		if row.Change != nil {
			t.Fatalf("non-comparable growth presented as measured: %+v", row)
		}
	}
}

func TestCapacityHistoryDistinguishesArchiveExpiryAndReplay(t *testing.T) {
	x := newExportFixture(t)
	x.archiveNow(t)
	action := x.approve(t)
	x.ok(t, "apply", "--quarantine", "--action", action.ID, "--dry-run=false", "--confirm")
	receipt := x.receipt(t)
	x.ok(t, "apply", "--expire", "--cleanup", receipt.CleanupID, "--dry-run=false", "--confirm")
	x.ok(t, "apply", "--expire", "--cleanup", receipt.CleanupID, "--dry-run=false", "--confirm")
	doc := decodeInventoryStatus(t, x.ok(t, "status"))
	seen := map[string]int{}
	for _, event := range doc.Data.Inventory.Activities {
		if event.State != "completed" {
			t.Fatalf("completed fixture operation lost outcome: %+v", event)
		}
		if event.Before == nil || event.After == nil {
			t.Fatalf("actual filesystem observations missing: %+v", event)
		}
		seen[event.Kind]++
		switch event.Kind {
		case "verified_archive", "quarantine":
			if event.Actual == nil || *event.Actual != 0 {
				t.Fatalf("copy/rename reported as unknown or recovered capacity: %+v", event)
			}
		case "expiry":
			if event.Actual != nil {
				t.Fatalf("shared-volume delta attributed to deletion: %+v", event)
			}
			if event.Completed == 0 && event.Replayed != 1 {
				t.Fatalf("historical receipt replay claimed fresh deletion: %+v", event)
			}
		default:
			t.Fatalf("unexpected activity: %+v", event)
		}
	}
	if seen["verified_archive"] != 1 || seen["quarantine"] != 1 || seen["expiry"] != 2 {
		t.Fatalf("operation history lost distinct effects: %+v", seen)
	}
	if _, err := os.Stat(receipt.Destination); !os.IsNotExist(err) {
		t.Fatalf("test did not actually expire local export: %v", err)
	}
	restored := filepath.Join(x.home, "history-recovered-export")
	x.ok(t, "archive", "--rule", "completed-report", "--restore-to", restored, "--dry-run=false", "--confirm")
	x.preserved(t, restored)
}
