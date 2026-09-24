//go:build linux

package cli

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDailyAdvisoryRefusesPublicStateDirectory(t *testing.T) {
	binary := advisoryTestBinary(t)
	server, calls := advisoryFakeServer(t, http.StatusOK)
	f, keyFile := advisoryFixture(t, server.URL)
	if _, stderr, err := advisoryCLI(t, binary, f, "cycle"); err != nil {
		t.Fatalf("cycle: %v %s", err, stderr)
	}
	state := filepath.Join(f.home, ".local", "state", "workspace-janitor")
	if err := os.Chmod(state, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(state, 0700) })
	_, stderr, err := advisoryCLI(t, binary, f, "advisory", "run", "--key-file", keyFile)
	if err == nil || !strings.Contains(stderr, "state directory is not private") || calls.Load() != 0 {
		t.Fatalf("public report state admitted provider call: %v %s calls=%d", err, stderr, calls.Load())
	}
}
