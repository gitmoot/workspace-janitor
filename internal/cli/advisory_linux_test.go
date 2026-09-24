//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/jev"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

func advisoryTestBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "janitor")
	cmd := exec.Command("go", "build", "-o", binary, "./cmd/janitor")
	cmd.Dir = filepath.Join("..", "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build real CLI: %v\n%s", err, out)
	}
	return binary
}

func advisoryCLI(t *testing.T, binary string, f *planFixture, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = []string{"HOME=" + f.home, "PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null", "OPENROUTER_API_KEY="}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	return out.String(), errOut.String(), err
}

func advisoryFixture(t *testing.T, endpoint string, maxRetries ...int) (*planFixture, string) {
	t.Helper()
	retries := 0
	if len(maxRetries) != 0 {
		retries = maxRetries[0]
	}
	f := newPlanFixture(t)
	f.writePolicy(t, strings.Join([]string{
		"roots:", "  - path: " + f.root, "    max_depth: 1",
		"collectors:", "  git: false", "  processes: false", "  services: false",
		"canonical_roots:", "  - class: primary_project", "    path: " + f.repos,
		"prevention:", "  min_free_percent: 0",
		"jev:", "  enabled: true", "  endpoint: " + endpoint + "/api/v1/systemone",
		fmt.Sprintf("  max_retries: %d", retries), "  min_interval: 0s", "",
	}, "\n"))
	keyFile := filepath.Join(f.home, "synthetic.env")
	if err := os.WriteFile(keyFile, []byte("UNRELATED=ignored\nOPENROUTER_API_KEY='synthetic-only-key'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return f, keyFile
}

func advisoryFakeServer(t *testing.T, status int) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	calls := &atomic.Int64{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/systemone" ||
			r.Header.Get("Authorization") != "Bearer synthetic-only-key" {
			t.Errorf("invalid synthetic advisory request")
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		var request jev.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte("synthetic error"))
			return
		}
		confidence, unsafe := .92, .01
		answers := map[string]jev.Answer{}
		for _, entry := range request.State.Entries {
			answers[entry.Ref+"_class"] = jev.Answer{Type: "choice", Choice: "operational_tool", Confidence: &confidence}
			answers[entry.Ref+"_action"] = jev.Answer{Type: "choice", Choice: "keep", Confidence: &confidence}
			answers[entry.Ref+"_retention"] = jev.Answer{Type: "choice", Choice: "none", Confidence: &confidence}
			answers[entry.Ref+"_unsafe"] = jev.Answer{Type: "noul", Noul: &unsafe}
		}
		_ = json.NewEncoder(w).Encode(jev.Response{Model: "typesafe/jev-1.13", Answers: answers,
			Usage: jev.Usage{InputTokens: 1000, OutputTokens: 40}})
	}))
	t.Cleanup(server.Close)
	return server, calls
}

func TestDailyAdvisoryRealCLIIsReviewOnlyAndIdempotent(t *testing.T) {
	binary := advisoryTestBinary(t)
	server, calls := advisoryFakeServer(t, http.StatusOK)
	f, keyFile := advisoryFixture(t, server.URL)
	marker := filepath.Join(f.root, "mystery", "sentinel")
	if err := os.WriteFile(marker, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, err := advisoryCLI(t, binary, f, "scan"); err != nil {
		t.Fatalf("scan: %v %s", err, stderr)
	}
	if _, stderr, err := advisoryCLI(t, binary, f, "advisory", "run", "--key-file", keyFile); err == nil || !strings.Contains(stderr, "no successful inventory cycle") {
		t.Fatalf("standalone scan admitted advice: %v %s", err, stderr)
	}
	if calls.Load() != 0 {
		t.Fatal("advice sent without a successful cycle")
	}
	if _, stderr, err := advisoryCLI(t, binary, f, "cycle"); err != nil {
		t.Fatalf("cycle: %v %s", err, stderr)
	}
	out, stderr, err := advisoryCLI(t, binary, f, "advisory", "run", "--key-file", keyFile)
	if err != nil {
		t.Fatalf("advice: %v %s %s", err, stderr, out)
	}
	var summary advisorySummary
	if err := json.Unmarshal([]byte(out), &summary); err != nil || summary.Status != "complete" || summary.Candidates == 0 ||
		summary.Budget.Attempts != calls.Load() || summary.Budget.EstimatedInputTokens <= 0 || summary.Budget.EstimatedCostMicroUSD <= 0 {
		t.Fatalf("daily summary = %+v, err=%v calls=%d", summary, err, calls.Load())
	}
	if strings.Contains(out+stderr, "synthetic-only-key") || strings.Contains(out, marker) {
		t.Fatal("scheduled output leaked key or private paths")
	}
	if content, err := os.ReadFile(marker); err != nil || string(content) != "untouched" {
		t.Fatalf("advice mutated file: %q %v", content, err)
	}
	before := calls.Load()
	out, stderr, err = advisoryCLI(t, binary, f, "advisory", "run", "--key-file", keyFile)
	if err != nil || calls.Load() != before {
		t.Fatalf("repeat daily run sent request: %v %s %s", err, stderr, out)
	}
	out, stderr, err = advisoryCLI(t, binary, f, "advisory", "report")
	if err != nil {
		t.Fatalf("report: %v %s", err, stderr)
	}
	var report advisoryReport
	if err := json.Unmarshal([]byte(out), &report); err != nil || report.ScanID != summary.ScanID ||
		report.Advisor.Usage.InputTokens == 0 || report.Advisor.Usage.EstimatedCostUSD <= 0 || len(report.Suggestions) == 0 {
		t.Fatalf("private report missing scan/advice/usage: %+v, err=%v", report, err)
	}
	if strings.Contains(out, "approval_id") || strings.Contains(out, "apply_command") || strings.Contains(out, "synthetic-only-key") {
		t.Fatal("report gained mutation authority or credential")
	}
	state := filepath.Join(f.home, ".local", "state", "workspace-janitor")
	if info, err := os.Stat(state); err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatalf("state not private: %v", err)
	}
}

func TestDailyAdvisoryConcurrentLaunchesAndUnsafeKeys(t *testing.T) {
	binary := advisoryTestBinary(t)
	var calls atomic.Int64
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("synthetic error"))
	}))
	defer server.Close()
	f, keyFile := advisoryFixture(t, server.URL)
	if _, stderr, err := advisoryCLI(t, binary, f, "cycle"); err != nil {
		t.Fatalf("cycle: %v %s", err, stderr)
	}
	if err := os.Chmod(keyFile, 0644); err != nil {
		t.Fatal(err)
	}
	if _, stderr, err := advisoryCLI(t, binary, f, "advisory", "run", "--key-file", keyFile); err == nil || !strings.Contains(stderr, "unsafe") {
		t.Fatalf("unsafe key accepted: %v %s", err, stderr)
	}
	if calls.Load() != 0 {
		t.Fatal("unsafe key reached server")
	}
	// Use a fresh completed cycle in an independent home: a blocked day is
	// deliberately not recycled after correcting a dangerous key file.
	g, safeKey := advisoryFixture(t, server.URL)
	if _, stderr, err := advisoryCLI(t, binary, g, "cycle"); err != nil {
		t.Fatalf("cycle: %v %s", err, stderr)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _, _, _ = advisoryCLI(t, binary, g, "advisory", "run", "--key-file", safeKey) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		wg.Wait()
		t.Fatal("first run did not reach fake server")
	}
	out, stderr, err := advisoryCLI(t, binary, g, "advisory", "run", "--key-file", safeKey)
	if err == nil || !strings.Contains(out+stderr, "earlier run still active") {
		t.Fatalf("concurrent launch admitted: %v %s %s", err, stderr, out)
	}
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("concurrent launches sent %d requests", calls.Load())
	}
	out, _, err = advisoryCLI(t, binary, g, "advisory", "report")
	if err != nil || !strings.Contains(out, `"attempts":1`) {
		t.Fatalf("failed attempt was not durably counted: %v %s", err, out)
	}
	out, stderr, err = advisoryCLI(t, binary, g, "advisory", "run", "--key-file", safeKey)
	if err == nil || calls.Load() != 1 {
		t.Fatalf("restart bypassed used attempt: %v %s %s", err, stderr, out)
	}
}

func TestDailyAdvisoryPartialEvidenceSkipsOnlyUnknown(t *testing.T) {
	binary := advisoryTestBinary(t)
	server, calls := advisoryFakeServer(t, http.StatusOK)
	f, keyFile := advisoryFixture(t, server.URL)
	unknownPath := filepath.Join(f.root, "mystery")
	unaffected := filepath.Join(f.root, "mystery-2")
	if err := os.Mkdir(unaffected, 0700); err != nil {
		t.Fatal(err)
	}
	if _, stderr, err := advisoryCLI(t, binary, f, "cycle"); err != nil {
		t.Fatalf("cycle: %v %s", err, stderr)
	}
	path := filepath.Join(f.home, ".local", "state", "workspace-janitor", "janitor.db")
	db, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	day := time.Now().UTC().Format("2006-01-02")
	err = db.Write(context.Background(), func(tx *store.Tx) error {
		id, err := tx.CompletedCycle(context.Background(), day)
		if err != nil {
			return err
		}
		scan, err := tx.Scan(context.Background(), id)
		if err != nil {
			return err
		}
		for i := range scan.Collectors {
			if scan.Collectors[i].Name == collect.CollectorFilesystem {
				scan.Collectors[i].Status = core.CollectorPartial
				scan.Collectors[i].Unknowns++
			}
		}
		if err := tx.UpdateScan(context.Background(), scan); err != nil {
			return err
		}
		entries, err := tx.Entries(context.Background(), id)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Path != unknownPath {
				continue
			}
			entry.Evidence = append(entry.Evidence, core.Evidence{Source: core.SourceFilesystem, Signal: "unknown:fixture", Detail: "synthetic partial observation", ObservedAt: time.Now().UTC()})
			entry.Protections = append(entry.Protections, core.Protection{Kind: core.ProtectCollectorFailure, Source: core.SourceFilesystem, Reason: "unknown fixture", Blocking: true})
			return tx.PutEntry(context.Background(), id, entry)
		}
		return fmt.Errorf("missing synthetic unknown entry")
	})
	_ = db.Close()
	if err != nil {
		t.Fatal(err)
	}
	out, stderr, err := advisoryCLI(t, binary, f, "advisory", "run", "--key-file", keyFile)
	if err != nil {
		t.Fatalf("partial advice: %v %s %s", err, stderr, out)
	}
	if calls.Load() == 0 {
		t.Fatal("unaffected entry was not offered")
	}
	out, _, err = advisoryCLI(t, binary, f, "advisory", "report")
	if err != nil {
		t.Fatal(err)
	}
	var report advisoryReport
	if err := json.Unmarshal([]byte(out), &report); err != nil || !report.Incomplete || report.SkippedUnknown == 0 {
		t.Fatalf("partial report did not disclose unknown: %+v %v", report, err)
	}
	for _, suggestion := range report.Suggestions {
		if suggestion.Path == unknownPath {
			t.Fatal("unknown safety evidence sent for advice")
		}
	}
	found := false
	for _, suggestion := range report.Suggestions {
		if suggestion.Path == unaffected {
			found = true
		}
	}
	if !found {
		t.Fatal("unaffected ambiguous entry missing from review report")
	}
}
