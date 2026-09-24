//go:build linux

package cli

import (
	"net/http"
	"strings"
	"testing"
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
