//go:build linux

package cli

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDailyAdvisoryServiceAliasesPreserveGlobalSafetyGate(t *testing.T) {
	binary := advisoryTestBinary(t)
	for _, unsafe := range []bool{false, true} {
		name := "proven alias"
		if unsafe {
			name = "escaping alias"
		}
		t.Run(name, func(t *testing.T) {
			server, calls := advisoryFakeServer(t, http.StatusOK)
			f, keyFile := advisoryFixture(t, server.URL)
			units := t.TempDir()
			if err := os.WriteFile(filepath.Join(units, "canonical.service"), []byte("[Service]\nExecStart=/usr/bin/true\n"), 0600); err != nil {
				t.Fatal(err)
			}
			target := "canonical.service"
			if unsafe {
				outside := t.TempDir()
				if err := os.WriteFile(filepath.Join(outside, "outside.service"), []byte("[Service]\n"), 0600); err != nil {
					t.Fatal(err)
				}
				target = filepath.Join(outside, "outside.service")
			}
			if err := os.Symlink(target, filepath.Join(units, "alias.service")); err != nil {
				t.Fatal(err)
			}
			f.writePolicy(t, strings.Join([]string{
				"roots:", "  - path: " + f.root, "    max_depth: 1",
				"collectors:", "  git: false", "  processes: false", "  services: true",
				"  systemd_dirs:", "    - " + units, "  cron_paths: []", "  pm2_dumps: []",
				"canonical_roots:", "  - class: primary_project", "    path: " + f.repos,
				"prevention:", "  min_free_percent: 0",
				"jev:", "  enabled: true", "  endpoint: " + server.URL + "/api/v1/systemone",
				"  max_retries: 0", "  min_interval: 0s", "",
			}, "\n"))
			if _, stderr, err := advisoryCLI(t, binary, f, "cycle"); err != nil {
				t.Fatalf("cycle: %v %s", err, stderr)
			}
			out, stderr, err := advisoryCLI(t, binary, f, "advisory", "run", "--key-file", keyFile)
			if err != nil {
				t.Fatalf("advisory: %v %s %s", err, stderr, out)
			}
			var summary advisorySummary
			if parseErr := json.Unmarshal([]byte(out), &summary); parseErr != nil {
				t.Fatalf("summary: %v %s", parseErr, out)
			}
			if unsafe {
				if !summary.Incomplete || summary.SkippedUnknown == 0 || calls.Load() != 0 {
					t.Fatalf("unsafe alias bypassed global unknown: %+v calls=%d", summary, calls.Load())
				}
			} else if summary.Candidates == 0 || calls.Load() == 0 {
				t.Fatalf("ordinary alias suppressed bounded advice: %+v calls=%d", summary, calls.Load())
			}
		})
	}
}
