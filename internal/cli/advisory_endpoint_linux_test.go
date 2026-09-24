//go:build linux

package cli

import (
	"net/http"
	"strings"
	"testing"
)

func TestDailyAdvisoryLoopbackCannotUseHostCredentialPath(t *testing.T) {
	binary := advisoryTestBinary(t)
	server, calls := advisoryFakeServer(t, http.StatusOK)
	f, _ := advisoryFixture(t, server.URL)
	if _, stderr, err := advisoryCLI(t, binary, f, "cycle"); err != nil {
		t.Fatalf("cycle: %v %s", err, stderr)
	}
	_, stderr, err := advisoryCLI(t, binary, f, "advisory", "run")
	if err == nil || !strings.Contains(stderr, "synthetic key file") || calls.Load() != 0 {
		t.Fatalf("loopback could read host key: %v %s calls=%d", err, stderr, calls.Load())
	}
}
