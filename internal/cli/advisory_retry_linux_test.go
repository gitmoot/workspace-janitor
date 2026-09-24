//go:build linux

package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/store"
)

// A retryable provider failure consumes each attempt before HTTP Do; later
// batches cannot obtain an eighth request even after an error or restart.
func TestDailyAdvisoryRetryExhaustionIsDurable(t *testing.T) {
	binary := advisoryTestBinary(t)
	server, calls := advisoryFakeServer(t, http.StatusTooManyRequests)
	f, keyFile := advisoryFixture(t, server.URL, 5)
	for i := range 42 {
		if err := os.Mkdir(filepath.Join(f.root, fmt.Sprintf("mystery-%02d", i)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if _, stderr, err := advisoryCLI(t, binary, f, "cycle"); err != nil {
		t.Fatalf("cycle: %v %s", err, stderr)
	}
	out, stderr, err := advisoryCLI(t, binary, f, "advisory", "run", "--key-file", keyFile)
	if err == nil {
		t.Fatalf("repeated provider failures looked successful: %s %s", out, stderr)
	}
	var summary advisorySummary
	if parseErr := json.Unmarshal([]byte(out), &summary); parseErr != nil {
		t.Fatalf("no failure summary: %v %s", parseErr, out)
	}
	if summary.Status != "incomplete" || summary.Budget.Attempts != store.AdvisoryMaxAttempts || calls.Load() != store.AdvisoryMaxAttempts {
		t.Fatalf("daily retry cap not enforced: %+v requests=%d", summary, calls.Load())
	}
	if _, _, err := advisoryCLI(t, binary, f, "advisory", "run", "--key-file", keyFile); err == nil || calls.Load() != store.AdvisoryMaxAttempts {
		t.Fatalf("restart bypassed retry budget: %v requests=%d", err, calls.Load())
	}
}
