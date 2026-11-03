//go:build linux

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// trimFixture runs the real `janitor cycle` with fake go and docker binaries
// that log their argv and environment, and a fake process table.
type trimFixture struct {
	*fixture
	root, cache, proc, log, gobin, dockerbin string
}

func newTrimFixture(t *testing.T) *trimFixture {
	t.Helper()
	f := newFixture(t)
	x := &trimFixture{fixture: f, root: filepath.Join(f.home, "workspace"), cache: filepath.Join(f.home, "go-build"),
		proc: filepath.Join(f.home, "proc"), log: filepath.Join(f.home, "calls.log")}
	for _, dir := range []string{x.root, x.cache, x.proc} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A fake official binary records its call; the go one empties the cache.
	write := func(name, body string) string {
		path := filepath.Join(f.home, name)
		script := "#!/bin/sh\nprintf '%s|%s|GOCACHE=%s\\n' \"" + name + "\" \"$*\" \"$GOCACHE\" >> " + x.log + "\n" + body
		if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	x.gobin = write("go", "rm -rf \"$GOCACHE\"/*\n")
	x.dockerbin = write("docker", "")
	return x
}

func (x *trimFixture) fill(t *testing.T, bytes int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(x.cache, "ab"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(x.cache, "ab", "obj-d"), make([]byte, bytes), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (x *trimFixture) process(t *testing.T, pid string, argv ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(x.proc, pid), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(x.proc, pid, "cmdline"), []byte(strings.Join(argv, "\x00")+"\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// trimResult decodes the public cycle report, not internal types, so the
// old code fails these tests on behavior rather than on compilation.
type trimResult struct {
	Status      string   `json:"status"`
	Kind        string   `json:"kind"`
	SizeBefore  *int64   `json:"size_before_bytes"`
	SizeAfter   *int64   `json:"size_after_bytes"`
	ActiveUsers []string `json:"active_users"`
}

func (x *trimFixture) cycle(t *testing.T) []trimResult {
	t.Helper()
	x.writePolicy(t, fmt.Sprintf(`roots:
  - path: %s
collectors:
  deep_size: false
  git: false
  processes: false
  services: false
  proc_root: %s
prevention:
  min_free_percent: 0
  cache_trims:
    - kind: go-build
      path: %s
      binary: %s
      max_bytes: 65536
    - kind: docker-builder
      binary: %s
      max_bytes: 2147483648
`, x.root, x.proc, x.cache, x.gobin, x.dockerbin))
	out, stderr, code := x.run(t, "cycle")
	if code != ExitOK {
		t.Fatalf("cycle: %d %s %s", code, out, stderr)
	}
	var report struct {
		CacheTrims []trimResult `json:"cache_trims"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.CacheTrims) != 2 {
		t.Fatalf("cache trims not reported: %s", out)
	}
	return report.CacheTrims
}

func (x *trimFixture) calls(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(x.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

// The daily cycle trims an oversized shared Go build cache with the official
// command and prunes only unused Docker build cache, at their bounds.
func TestCycleTrimsOversizedBuildCaches(t *testing.T) {
	x := newTrimFixture(t)
	x.fill(t, 1<<20)
	x.process(t, "4242", "/usr/bin/sleep", "300")
	trims := x.cycle(t)
	goTrim, docker := trims[0], trims[1]
	if goTrim.Status != "trimmed" || goTrim.SizeBefore == nil || *goTrim.SizeBefore <= 65536 || goTrim.SizeAfter == nil || *goTrim.SizeAfter > 65536 {
		t.Fatalf("go-build not trimmed: %+v", goTrim)
	}
	if docker.Status != "trimmed" {
		t.Fatalf("docker builder cache not pruned: %+v", docker)
	}
	calls := x.calls(t)
	want := []string{
		"go|clean -cache|GOCACHE=" + x.cache,
		"docker|builder prune --force --max-used-space 2147483648|GOCACHE=",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("official commands:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
	}
	// Under its bound the Go cache is left alone.
	x.cycle(t)
	for _, call := range x.calls(t)[2:] {
		if strings.HasPrefix(call, "go|") {
			t.Fatalf("under-bound cache trimmed again: %s", call)
		}
	}
}

// A running Go build or image build postpones that trim: nothing is run, and
// the cycle still succeeds.
func TestCycleSkipsBuildCachesInLiveUse(t *testing.T) {
	x := newTrimFixture(t)
	x.fill(t, 1<<20)
	x.process(t, "100", "/root/.local/toolchains/go1.26.4/bin/go", "test", "-count=1", "./...")
	x.process(t, "200", "/usr/bin/docker", "buildx", "build", "-t", "app", ".")
	for _, trim := range x.cycle(t) {
		if trim.Status != "skipped_in_use" || len(trim.ActiveUsers) == 0 {
			t.Fatalf("%s trimmed while in use: %+v", trim.Kind, trim)
		}
	}
	if calls := x.calls(t); len(calls) != 0 {
		t.Fatalf("trim commands ran during live builds: %v", calls)
	}
	if _, err := os.Stat(filepath.Join(x.cache, "ab", "obj-d")); err != nil {
		t.Fatalf("live cache was touched: %v", err)
	}
}
