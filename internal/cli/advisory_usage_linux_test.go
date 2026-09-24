//go:build linux

package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestDailyAdvisoryMissingProviderUsageStopsLaterBatches(t *testing.T) {
	binary := advisoryTestBinary(t)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"model":"typesafe/jev-1.13","answers":{},"usage":{}}`))
	}))
	defer server.Close()
	f, keyFile := advisoryFixture(t, server.URL)
	for i := range 30 {
		if err := os.Mkdir(filepath.Join(f.root, fmt.Sprintf("mystery-%02d", i)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if _, stderr, err := advisoryCLI(t, binary, f, "cycle"); err != nil {
		t.Fatalf("cycle: %v %s", err, stderr)
	}
	out, stderr, err := advisoryCLI(t, binary, f, "advisory", "run", "--key-file", keyFile)
	if err != nil {
		t.Fatalf("missing usage report failed: %v %s %s", err, stderr, out)
	}
	var summary advisorySummary
	if err := json.Unmarshal([]byte(out), &summary); err != nil || summary.Status != "incomplete" || summary.Budget.Attempts != 1 || calls.Load() != 1 {
		t.Fatalf("unknown usage allowed later calls or complete report: %+v %v calls=%d", summary, err, calls.Load())
	}
	out, stderr, err = advisoryCLI(t, binary, f, "advisory", "report")
	if err != nil {
		t.Fatalf("read report: %v %s", err, stderr)
	}
	var report advisoryReport
	if err := json.Unmarshal([]byte(out), &report); err != nil || report.Advisor.FailedRequests != 1 || !report.Advisor.CircuitOpen || len(report.Suggestions) != 0 {
		t.Fatalf("unknown usage advice was trusted: %+v %v", report, err)
	}
}
