package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCycleSkipsOverlappingActiveReceipt(t *testing.T) {
	for _, relationship := range []string{"parent", "child"} {
		t.Run(relationship, func(t *testing.T) {
			f := newFixture(t)
			root := filepath.Join(f.home, "workspace")
			parent := filepath.Join(root, "cache")
			child := filepath.Join(parent, "nested")
			source, next := parent, child
			if relationship == "parent" {
				source, next = child, parent
			}
			proc, units := filepath.Join(f.home, "proc"), filepath.Join(f.home, "units")
			for _, path := range []string{source, proc, units} {
				if err := os.MkdirAll(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			policy := func(path string) {
				f.writePolicy(t, "roots:\n  - path: "+filepath.Dir(path)+"\n    max_depth: 1\ncollectors:\n  git: false\n  processes: false\n  services: true\n  proc_root: "+proc+"\n  systemd_dirs:\n    - "+units+"\n  cron_paths: []\n  pm2_dumps: []\ncaches:\n  - name: tool\n    path: "+path+"\n    action: quarantine\n    retention: 7d\nprevention:\n  auto_quarantine: true\n  min_free_percent: 0\n")
			}
			if err := os.WriteFile(filepath.Join(source, "payload"), []byte("old"), 0600); err != nil {
				t.Fatal(err)
			}
			policy(source)
			out, stderr, code := f.run(t, "cycle")
			if code != ExitOK {
				t.Fatalf("first cycle: %s %s", out, stderr)
			}
			if _, err := os.Stat(source); !os.IsNotExist(err) {
				t.Fatalf("source not quarantined: %v", err)
			}
			if err := os.MkdirAll(next, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(next, "payload"), []byte("new"), 0600); err != nil {
				t.Fatal(err)
			}
			policy(next)
			out, stderr, code = f.run(t, "cycle")
			var report cycleReport
			if code != ExitOK || json.Unmarshal([]byte(out), &report) != nil || report.Quarantine != "none" || !strings.Contains(report.QuarantineReport, next) || !strings.Contains(report.QuarantineReport, "active cleanup receipt") {
				t.Fatalf("overlap not safely reported: %d %s %s", code, out, stderr)
			}
			if raw, err := os.ReadFile(filepath.Join(next, "payload")); err != nil || string(raw) != "new" {
				t.Fatalf("overlapping source changed: %q %v", raw, err)
			}
		})
	}
}
