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

func TestDailyAdvisoryZeroCandidatesNeverReadsKeyOrCallsServer(t *testing.T) {
	binary := advisoryTestBinary(t)
	server, calls := advisoryFakeServer(t, http.StatusOK)
	f := &planFixture{fixture: newFixture(t)}
	f.root = filepath.Join(f.home, "empty-root")
	if err := os.Mkdir(f.root, 0700); err != nil {
		t.Fatal(err)
	}
	f.writePolicy(t, strings.Join([]string{
		"roots:", "  - path: " + f.root,
		"collectors:", "  git: false", "  processes: false", "  services: false",
		"jev:", "  enabled: true", "  endpoint: " + server.URL + "/api/v1/systemone", "",
	}, "\n"))
	if _, stderr, err := advisoryCLI(t, binary, f, "cycle"); err != nil {
		t.Fatalf("empty cycle: %v %s", err, stderr)
	}
	out, stderr, err := advisoryCLI(t, binary, f, "advisory", "run", "--key-file", filepath.Join(f.home, "missing.env"))
	if err != nil {
		t.Fatalf("empty advisory required a key: %v %s %s", err, stderr, out)
	}
	var summary advisorySummary
	if err := json.Unmarshal([]byte(out), &summary); err != nil || summary.Candidates != 0 || summary.Budget.Attempts != 0 || calls.Load() != 0 {
		t.Fatalf("empty run used network or budget: %+v err=%v calls=%d", summary, err, calls.Load())
	}
}
