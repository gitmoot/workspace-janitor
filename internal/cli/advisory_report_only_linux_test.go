//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/jev"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

func TestDailyAdvisoryReportOnlyRootKeepsSafetyAndActionsOff(t *testing.T) {
	binary := advisoryTestBinary(t)
	for _, globalFailure := range []bool{false, true} {
		name := "per-entry protections"
		if globalFailure {
			name = "global references unknown"
		}
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			var offered []jev.Projection
			server, calls := advisoryFakeServer(t, http.StatusOK, func(_ int, request jev.Request) {
				mu.Lock()
				offered = append(offered, request.State.Entries...)
				mu.Unlock()
			})
			f, keyFile := advisoryFixture(t, server.URL)
			paths := map[string]string{}
			for _, name := range []string{"mystery", "mystery-secret", "mystery-protected", "mystery-unknown", "mystery-active"} {
				paths[name] = filepath.Join(f.root, name)
				if name != "mystery" {
					if err := os.Mkdir(paths[name], 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			marker := filepath.Join(paths["mystery"], "sentinel")
			if err := os.WriteFile(marker, []byte("fixture-only-private-content"), 0600); err != nil {
				t.Fatal(err)
			}
			f.writePolicy(t, strings.Join([]string{
				"roots:", "  - path: " + f.root, "    max_depth: 1", "    report_only: true",
				"protect:", "  paths:", "    - " + paths["mystery-protected"],
				"  name_patterns:", "    - mystery-secret",
				"collectors:", "  git: false", "  processes: false", "  services: false",
				"canonical_roots:", "  - class: primary_project", "    path: " + f.repos,
				"retention:", "  delete_enabled: false",
				"prevention:", "  auto_expire: false", "  min_free_percent: 0",
				"jev:", "  enabled: true", "  endpoint: " + server.URL + "/api/v1/systemone",
				"  max_retries: 0", "  min_interval: 0s", "",
			}, "\n"))
			if _, stderr, err := advisoryCLI(t, binary, f, "cycle"); err != nil {
				t.Fatalf("report-only cycle: %v %s", err, stderr)
			}
			ctx := context.Background()
			database := filepath.Join(f.home, ".local", "state", "workspace-janitor", "janitor.db")
			db, err := store.Open(ctx, database)
			if err != nil {
				t.Fatal(err)
			}
			err = db.Write(ctx, func(tx *store.Tx) error {
				id, err := tx.CompletedCycle(ctx, time.Now().UTC().Format("2006-01-02"))
				if err != nil {
					return err
				}
				entries, err := tx.Entries(ctx, id)
				if err != nil {
					return err
				}
				found := 0
				for _, entry := range entries {
					switch entry.Path {
					case paths["mystery-unknown"]:
						entry.Evidence = append(entry.Evidence, core.Evidence{
							Source: core.SourceFilesystem, Signal: "unknown:fixture", Detail: "incomplete fixture observation", ObservedAt: time.Now().UTC(),
						})
						found++
					case paths["mystery-active"]:
						entry.Protections = append(entry.Protections, core.Protection{
							Kind: core.ProtectActiveProcess, Source: core.SourceProcess, Reason: "synthetic active process", Blocking: true,
						})
						found++
					default:
						continue
					}
					if err := tx.PutEntry(ctx, id, entry); err != nil {
						return err
					}
				}
				if found != 2 {
					return fmt.Errorf("missing protected fixture entries: %d", found)
				}
				if globalFailure {
					scan, err := tx.Scan(ctx, id)
					if err != nil {
						return err
					}
					for i := range scan.Collectors {
						if scan.Collectors[i].Name == collect.CollectorServices {
							scan.Collectors[i].Status = core.CollectorPartial
							scan.Collectors[i].Unknowns++
							return tx.UpdateScan(ctx, scan)
						}
					}
					return fmt.Errorf("missing synthetic global collector")
				}
				return nil
			})
			if closeErr := db.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				t.Fatal(err)
			}
			out, stderr, err := advisoryCLI(t, binary, f, "advisory", "run", "--key-file", keyFile)
			if err != nil {
				t.Fatalf("report-only advisory: %v %s %s", err, stderr, out)
			}
			var summary advisorySummary
			if err := json.Unmarshal([]byte(out), &summary); err != nil {
				t.Fatalf("summary: %v %s", err, out)
			}
			mu.Lock()
			projection := append([]jev.Projection(nil), offered...)
			mu.Unlock()
			if globalFailure {
				if calls.Load() != 0 || summary.Candidates != 0 || !summary.Incomplete || summary.SkippedUnknown == 0 {
					t.Fatalf("global unknown references admitted advice: %+v calls=%d", summary, calls.Load())
				}
			} else {
				if calls.Load() == 0 || summary.Candidates == 0 || summary.SkippedUnknown == 0 {
					t.Fatalf("report-only root blocked safe advice: %+v calls=%d", summary, calls.Load())
				}
				foundSafe := false
				for _, entry := range projection {
					if entry.Name == "mystery" {
						foundSafe = true
					}
				}
				encoded, _ := json.Marshal(projection)
				if !foundSafe || strings.Contains(string(encoded), f.home) || strings.Contains(string(encoded), "fixture-only-private-content") || strings.Contains(string(encoded), "synthetic-only-key") {
					t.Fatalf("safe metadata projection missing or leaked fixture data: %s", encoded)
				}
			}
			out, stderr, err = advisoryCLI(t, binary, f, "advisory", "report")
			if err != nil {
				t.Fatalf("private report: %v %s", err, stderr)
			}
			var report advisoryReport
			if err := json.Unmarshal([]byte(out), &report); err != nil {
				t.Fatalf("report: %v %s", err, out)
			}
			seenSafe := false
			for _, suggestion := range report.Suggestions {
				if suggestion.Path == paths["mystery"] {
					seenSafe = true
				}
				for _, excluded := range []string{"mystery-secret", "mystery-protected", "mystery-unknown", "mystery-active"} {
					if suggestion.Path == paths[excluded] {
						t.Fatalf("blocking %s was offered for advice", excluded)
					}
				}
			}
			if !globalFailure && !seenSafe {
				t.Fatal("safe report-only entry absent from private advice")
			}
			if bytes, err := os.ReadFile(marker); err != nil || string(bytes) != "fixture-only-private-content" {
				t.Fatalf("advisory mutated report-only content: %q %v", bytes, err)
			}
			db, err = store.OpenExisting(ctx, database)
			if err != nil {
				t.Fatal(err)
			}
			var plans []core.Plan
			err = db.Read(ctx, func(tx *store.Tx) error {
				var err error
				plans, err = tx.ListPlans(ctx, 0)
				return err
			})
			if closeErr := db.Close(); err == nil {
				err = closeErr
			}
			if err != nil || len(plans) != 0 {
				t.Fatalf("advisory persisted executable actions: plans=%d err=%v", len(plans), err)
			}
		})
	}
}
