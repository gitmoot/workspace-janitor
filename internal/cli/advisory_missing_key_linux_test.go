//go:build linux

package cli

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestDailyAdvisoryMissingKeyWritesBlockedReportWithoutCall(t *testing.T) {
	binary := advisoryTestBinary(t)
	server, calls := advisoryFakeServer(t, http.StatusOK)
	f, keyFile := advisoryFixture(t, server.URL)
	if _, stderr, err := advisoryCLI(t, binary, f, "cycle"); err != nil {
		t.Fatalf("cycle: %v %s", err, stderr)
	}
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	out, stderr, err := advisoryCLI(t, binary, f, "advisory", "run", "--key-file", keyFile)
	if err == nil || !strings.Contains(stderr, "key file is absent") || calls.Load() != 0 {
		t.Fatalf("missing key was not refused: %v %s %s calls=%d", err, out, stderr, calls.Load())
	}
	out, stderr, err = advisoryCLI(t, binary, f, "advisory", "report")
	if err != nil {
		t.Fatalf("read blocked report: %v %s", err, stderr)
	}
	var report advisoryReport
	if err := json.Unmarshal([]byte(out), &report); err != nil || report.Status != "blocked" || report.Budget.Attempts != 0 {
		t.Fatalf("missing-key report = %+v, %v", report, err)
	}
}
