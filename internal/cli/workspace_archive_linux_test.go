//go:build linux

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/config"
)

type workspaceArchiveFixture struct {
	*fixture
	work, source, archive, proc string
}

func newWorkspaceArchiveFixture(t *testing.T) *workspaceArchiveFixture {
	t.Helper()
	f := newFixture(t)
	home, err := filepath.EvalSymlinks(f.home)
	if err != nil {
		t.Fatal(err)
	}
	f.home, f.env[config.EnvHome] = home, home
	x := &workspaceArchiveFixture{fixture: f, work: filepath.Join(home, "work"), archive: filepath.Join(home, "archive"), proc: filepath.Join(home, "proc")}
	x.source = filepath.Join(x.work, "released")
	for _, dir := range []string{filepath.Join(x.source, "sub"), x.archive, x.proc} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range map[string]string{"README.md": "released\n", "sub/data.txt": strings.Repeat("payload\n", 1024)} {
		if err := os.WriteFile(filepath.Join(x.source, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return x
}

func (x *workspaceArchiveFixture) policy(t *testing.T, extra string) {
	t.Helper()
	x.writePolicy(t, fmt.Sprintf(`roots:
  - path: %s
    max_depth: 1
protect:
  paths: [%s]
collectors:
  proc_root: %s
  systemd_dirs: []
  cron_paths: []
  pm2_dumps: []
limits:
  command_timeout: 30s
workspace_archives:
  - name: released
    path: %s
    owner: seat-a
    release: release-msg-1
    archive:
      directory: %s
%s`, x.work, x.archive, x.proc, x.source, x.archive, extra))
}

func (x *workspaceArchiveFixture) data(t *testing.T, args ...string) map[string]json.RawMessage {
	t.Helper()
	out, stderr, code := x.run(t, append([]string{"--format", "json"}, args...)...)
	if code != ExitOK {
		t.Fatalf("%v: exit=%d stderr=%s stdout=%s", args, code, stderr, out)
	}
	var doc struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return doc.Data
}

func field(t *testing.T, data map[string]json.RawMessage, name string, into any) {
	t.Helper()
	if err := json.Unmarshal(data[name], into); err != nil {
		t.Fatalf("field %s: %v (%s)", name, err, data[name])
	}
}

func TestWorkspaceArchiveCommandCreatesVerifiesAndRestoresCopyOnly(t *testing.T) {
	x := newWorkspaceArchiveFixture(t)
	x.policy(t, "")

	preview := x.data(t, "archive", "--workspace", "released")
	var status string
	field(t, preview, "status", &status)
	if status != "preview" {
		t.Fatalf("dry run status = %q", status)
	}
	if entries, _ := os.ReadDir(x.archive); len(entries) != 0 {
		t.Fatalf("dry run wrote %d archive entries", len(entries))
	}

	created := x.data(t, "archive", "--workspace", "released", "--dry-run=false", "--confirm")
	var binding struct {
		Manifest string `json:"manifest"`
		SHA      string `json:"manifest_sha256"`
	}
	var freed uint64
	field(t, created, "status", &status)
	field(t, created, "binding", &binding)
	field(t, created, "local_freed_bytes", &freed)
	if status != "archived_and_readback_verified" || freed != 0 || binding.Manifest != filepath.Join(x.archive, "released.manifest.json") || len(binding.SHA) != 64 {
		t.Fatalf("create report status=%q freed=%d binding=%+v", status, freed, binding)
	}
	if data, err := os.ReadFile(filepath.Join(x.source, "sub", "data.txt")); err != nil || len(data) != 8192 {
		t.Fatalf("copy-only archive changed its source: %v", err)
	}

	x.policy(t, fmt.Sprintf("      manifest: %s\n      manifest_sha256: %s\n", binding.Manifest, binding.SHA))
	verified := x.data(t, "archive", "--workspace", "released", "--verify")
	field(t, verified, "status", &status)
	if status != "verified" {
		t.Fatalf("verify status = %q", status)
	}

	restored := filepath.Join(x.home, "restored")
	preview = x.data(t, "archive", "--workspace", "released", "--restore-to", restored)
	field(t, preview, "status", &status)
	if _, err := os.Lstat(restored); status != "preview" || !os.IsNotExist(err) {
		t.Fatalf("restore preview status=%q wrote %v", status, err)
	}
	done := x.data(t, "archive", "--workspace", "released", "--restore-to", restored, "--dry-run=false", "--confirm")
	field(t, done, "status", &status)
	if status != "restored" {
		t.Fatalf("restore status = %q", status)
	}
	for _, name := range []string{"README.md", "sub/data.txt"} {
		want, _ := os.ReadFile(filepath.Join(x.source, name))
		got, err := os.ReadFile(filepath.Join(restored, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("restored %s differs: %v", name, err)
		}
	}
}

func TestWorkspaceArchiveCommandRefusesAmbiguousSelectionAndKeepConflict(t *testing.T) {
	x := newWorkspaceArchiveFixture(t)
	x.policy(t, "")
	if _, _, code := x.run(t, "archive", "--workspace", "released", "--rule", "completed-report"); code != ExitUsage {
		t.Fatalf("--workspace with --rule exit = %d, want usage error", code)
	}
	if _, _, code := x.run(t, "archive"); code != ExitUsage {
		t.Fatalf("archive without a selection exit = %d, want usage error", code)
	}
	x.policy(t, fmt.Sprintf("workspace_archive_keep:\n  - path: %s\n    owner: seat-b\n    reference: keep-msg-7\n", x.source))
	_, stderr, code := x.run(t, "archive", "--workspace", "released", "--dry-run=false", "--confirm")
	if code == ExitOK || !strings.Contains(stderr, "KEEP/release conflict") {
		t.Fatalf("KEEP conflict exit=%d stderr=%s", code, stderr)
	}
	if entries, _ := os.ReadDir(x.archive); len(entries) != 0 {
		t.Fatalf("refused archive wrote %d entries", len(entries))
	}
}
