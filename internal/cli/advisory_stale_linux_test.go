//go:build linux

package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/jev"
)

func TestDailyAdvisoryRefusesSupersededSuccessfulCycle(t *testing.T) {
	binary := advisoryTestBinary(t)
	server, calls := advisoryFakeServer(t, http.StatusOK)
	f, keyFile := advisoryFixture(t, server.URL)
	if _, stderr, err := advisoryCLI(t, binary, f, "cycle"); err != nil {
		t.Fatalf("cycle: %v %s", err, stderr)
	}
	if _, stderr, err := advisoryCLI(t, binary, f, "scan"); err != nil {
		t.Fatalf("later inventory: %v %s", err, stderr)
	}
	_, stderr, err := advisoryCLI(t, binary, f, "advisory", "run", "--key-file", keyFile)
	if err == nil || !strings.Contains(stderr, "superseded") || calls.Load() != 0 {
		t.Fatalf("stale cycle admitted advice: %v %s calls=%d", err, stderr, calls.Load())
	}
}

func TestDailyAdvisoryLaterScanStopsSecondBatchWithReason(t *testing.T) {
	binary := advisoryTestBinary(t)
	var f *planFixture
	ready := make(chan struct{})
	server, calls := advisoryFakeServer(t, http.StatusOK, func(n int, _ jev.Request) {
		<-ready
		if n == 1 {
			if _, stderr, err := advisoryCLI(t, binary, f, "scan"); err != nil {
				t.Errorf("later inventory: %v %s", err, stderr)
			}
		}
	})
	var keyFile string
	f, keyFile = advisoryFixture(t, server.URL)
	close(ready)
	for i := range 25 {
		if err := os.Mkdir(filepath.Join(f.root, fmt.Sprintf("mystery-%02d", i)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if _, stderr, err := advisoryCLI(t, binary, f, "cycle"); err != nil {
		t.Fatalf("cycle: %v %s", err, stderr)
	}
	out, stderr, err := advisoryCLI(t, binary, f, "advisory", "run", "--key-file", keyFile)
	if err == nil {
		t.Fatalf("later inventory did not stop second batch: %s %s", out, stderr)
	}
	var summary advisorySummary
	if parseErr := json.Unmarshal([]byte(out), &summary); parseErr != nil ||
		!strings.Contains(summary.Reason, "superseded") || summary.Budget.Attempts != 1 || calls.Load() != 1 {
		t.Fatalf("later inventory reported as budget exhaustion: %+v %v calls=%d stderr=%s", summary, parseErr, calls.Load(), stderr)
	}
}
