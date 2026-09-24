//go:build linux

package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDailyAdvisoryKilledAfterRequestCannotRepeat(t *testing.T) {
	binary := advisoryTestBinary(t)
	var calls atomic.Int64
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		entered <- struct{}{}
		<-release
	}))
	defer server.Close()
	defer close(release)
	f, keyFile := advisoryFixture(t, server.URL)
	if _, stderr, err := advisoryCLI(t, binary, f, "cycle"); err != nil {
		t.Fatalf("cycle: %v %s", err, stderr)
	}
	cmd := exec.Command(binary, "advisory", "run", "--key-file", keyFile)
	cmd.Env = []string{"HOME=" + f.home, "PATH=" + os.Getenv("PATH"), "OPENROUTER_API_KEY="}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("request never reached fake server")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	out, stderr, err := advisoryCLI(t, binary, f, "advisory", "run", "--key-file", keyFile)
	if err == nil || !strings.Contains(out+stderr, "earlier run still active or interrupted") || calls.Load() != 1 {
		t.Fatalf("crash reopened request: %v %s %s calls=%d", err, out, stderr, calls.Load())
	}
	var summary advisorySummary
	if parseErr := json.Unmarshal([]byte(out), &summary); parseErr != nil ||
		summary.Budget.Attempts != 1 || summary.Budget.EstimatedInputTokens == 0 {
		t.Fatalf("interrupted summary concealed durable reservation: %+v %v", summary, parseErr)
	}
	out, stderr, err = advisoryCLI(t, binary, f, "advisory", "report")
	if err != nil {
		t.Fatalf("interrupted report: %v %s", err, stderr)
	}
	var report advisoryReport
	if parseErr := json.Unmarshal([]byte(out), &report); parseErr != nil ||
		report.Budget.Attempts != 1 || !report.ProviderUsageUnknown || report.Advisor.Mode != "" {
		t.Fatalf("interrupted report claimed no spend or known usage: %+v %v", report, parseErr)
	}
}
