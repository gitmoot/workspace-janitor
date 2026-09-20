package collect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// fakeProc builds a procfs-shaped fixture so process reference collection is
// tested without reading the machine's real process table.
func fakeProc(t *testing.T, entries map[string]map[string]string) string {
	t.Helper()
	procRoot := t.TempDir()
	for pid, links := range entries {
		dir := mustMkdir(t, filepath.Join(procRoot, pid))
		for name, target := range links {
			if name == "comm" {
				mustWrite(t, filepath.Join(dir, "comm"), target+"\n")
				continue
			}
			mustSymlink(t, target, filepath.Join(dir, name))
		}
	}
	return procRoot
}

func TestProcessReferencesProtectEntries(t *testing.T) {
	root := t.TempDir()
	used := mustMkdir(t, filepath.Join(root, "in-use"))
	idle := mustMkdir(t, filepath.Join(root, "idle"))

	opts := fixtureOptions(root)
	opts.Processes = true
	opts.ProcRoot = fakeProc(t, map[string]map[string]string{
		"4242":      {"cwd": filepath.Join(used, "src"), "exe": "/usr/bin/node", "comm": "node"},
		"not-a-pid": {"cwd": idle},
		"self":      {"cwd": idle},
	})

	result := run(t, opts)

	usedEntry := entryFor(t, result, used)
	if !hasProtection(usedEntry, core.ProtectActiveProcess) {
		t.Errorf("a directory holding a live process CWD is not protected: %+v", usedEntry.Protections)
	}
	if !hasSignal(usedEntry, "process_cwd") {
		t.Errorf("process evidence missing: %+v", usedEntry.Evidence)
	}
	detail := ""
	for _, evidence := range usedEntry.Evidence {
		if evidence.Signal == "process_cwd" {
			detail = evidence.Detail
		}
	}
	if !strings.Contains(detail, "pid 4242") || !strings.Contains(detail, "node") {
		t.Errorf("evidence detail = %q, want the pid and process name", detail)
	}

	idleEntry := entryFor(t, result, idle)
	if hasProtection(idleEntry, core.ProtectActiveProcess) {
		t.Errorf("non-numeric procfs entries must be ignored: %+v", idleEntry.Protections)
	}

	report := reportFor(t, result, CollectorProcesses)
	if report.Visited != 1 {
		t.Errorf("visited = %d, want only the numeric pid inspected", report.Visited)
	}
}

// The real process collector must find a live process working directory.
func TestProcessCollectorReadsRealProcfs(t *testing.T) {
	if _, err := os.Stat("/proc/self/cwd"); err != nil {
		t.Skipf("procfs is unavailable: %v", err)
	}
	root := t.TempDir()
	workdir := mustMkdir(t, filepath.Join(root, "live"))

	cmd := exec.Command("sleep", "30")
	cmd.Dir = workdir
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a fixture process: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	opts := fixtureOptions(root)
	opts.Processes = true
	opts.ProcRoot = "/proc"
	opts.Limits.MaxDirEntries = 100000

	entry := entryFor(t, run(t, opts), workdir)
	if !hasProtection(entry, core.ProtectActiveProcess) {
		t.Errorf("a directory used by a running process is not protected: %+v", entry.Protections)
	}
}

// The collector must not read the command line or environment of a process:
// both routinely carry credentials.
func TestProcessCollectorReadsNeitherCmdlineNorEnviron(t *testing.T) {
	root := t.TempDir()
	used := mustMkdir(t, filepath.Join(root, "in-use"))
	procRoot := fakeProc(t, map[string]map[string]string{
		"77": {"cwd": used, "comm": "worker"},
	})
	secret := "SUPER_SECRET_TOKEN=abc123"
	mustWrite(t, filepath.Join(procRoot, "77", "cmdline"), "worker --token=abc123")
	mustWrite(t, filepath.Join(procRoot, "77", "environ"), secret)

	opts := fixtureOptions(root)
	opts.Processes = true
	opts.ProcRoot = procRoot

	result := run(t, opts)
	assertNoSecretRecorded(t, result, "abc123")
}

// stubAgents is a registered-agent adapter fixture.
type stubAgents struct {
	name string
	dirs []AgentRef
	err  error
}

func (s stubAgents) Name() string { return s.name }

func (s stubAgents) ActiveDirectories(context.Context) ([]AgentRef, error) {
	return s.dirs, s.err
}

func TestRegisteredAgentDirectoriesAreProtected(t *testing.T) {
	root := t.TempDir()
	agentDir := mustMkdir(t, filepath.Join(root, "agent-worktree"))
	other := mustMkdir(t, filepath.Join(root, "plain"))

	opts := fixtureOptions(root)
	opts.AgentSources = []AgentSource{stubAgents{
		name: "gitmoot",
		dirs: []AgentRef{{Agent: "reviewer-1", Path: agentDir, Detail: "job local-review-1"}},
	}}

	result := run(t, opts)
	entry := entryFor(t, result, agentDir)
	if !hasProtection(entry, core.ProtectRegisteredAgent) {
		t.Errorf("registered agent directory is not protected: %+v", entry.Protections)
	}
	if hasProtection(entryFor(t, result, other), core.ProtectRegisteredAgent) {
		t.Error("an unrelated directory was protected as an agent directory")
	}
	if report := reportFor(t, result, CollectorAgents); report.Status != core.CollectorRan || report.Recorded != 1 {
		t.Errorf("agents report = %+v", report)
	}
}

// An agent registry that cannot answer leaves agent occupancy unknown, which
// must be reported rather than read as "no agents".
func TestAgentSourceFailureIsReportedAsUnknown(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "worktree"))

	opts := fixtureOptions(root)
	opts.AgentSources = []AgentSource{stubAgents{name: "gitmoot", err: errors.New("daemon unreachable")}}

	report := reportFor(t, run(t, opts), CollectorAgents)
	if report.Status != core.CollectorPartial || report.Unknowns != 1 {
		t.Fatalf("agents report = %+v, want partial with one unknown", report)
	}
	if !strings.Contains(report.Detail, "daemon unreachable") {
		t.Errorf("detail = %q, want the adapter failure named", report.Detail)
	}
}

func TestServiceReferencesProtectEntries(t *testing.T) {
	root := t.TempDir()
	service := mustMkdir(t, filepath.Join(root, "service"))
	cronTarget := mustMkdir(t, filepath.Join(root, "backup"))
	pm2Target := mustMkdir(t, filepath.Join(root, "web"))
	unrelated := mustMkdir(t, filepath.Join(root, "unrelated"))

	systemdDir := t.TempDir()
	mustWrite(t, filepath.Join(systemdDir, "fixture.service"), strings.Join([]string{
		"[Service]",
		"WorkingDirectory=" + service,
		"ExecStart=-/usr/bin/env node " + filepath.Join(service, "server.js"),
		"Environment=API_TOKEN=shhh-do-not-read-me",
		"EnvironmentFile=/etc/fixture.env",
		"",
	}, "\n"))
	mustWrite(t, filepath.Join(systemdDir, "ignored.timer"), "WorkingDirectory="+unrelated+"\n")

	cronDir := t.TempDir()
	mustWrite(t, filepath.Join(cronDir, "fixture"), strings.Join([]string{
		"# fixture crontab",
		"CRON_SECRET=shhh-do-not-read-me",
		"0 3 * * * root " + filepath.Join(cronTarget, "run.sh"),
		"",
	}, "\n"))

	pm2Dump := filepath.Join(t.TempDir(), "dump.pm2")
	mustWrite(t, pm2Dump, fmt.Sprintf(
		`[{"name":"web","pm2_env":{"pm_cwd":%q,"pm_exec_path":%q}}]`,
		pm2Target, filepath.Join(pm2Target, "index.js")))

	opts := fixtureOptions(root)
	opts.Services = true
	opts.ServiceSources = ServiceSources{
		SystemdDirs: []string{systemdDir, filepath.Join(systemdDir, "missing")},
		CronPaths:   []string{cronDir},
		PM2Dumps:    []string{pm2Dump},
	}

	result := run(t, opts)
	for _, path := range []string{service, cronTarget, pm2Target} {
		entry := entryFor(t, result, path)
		if !hasProtection(entry, core.ProtectServiceReference) {
			t.Errorf("%s is referenced by a service but not protected: %+v", path, entry.Protections)
		}
	}
	if hasProtection(entryFor(t, result, unrelated), core.ProtectServiceReference) {
		t.Error("a non-service unit type produced a reference")
	}

	// Environment directives and crontab assignments must never be read.
	assertNoSecretRecorded(t, result, "shhh-do-not-read-me")

	report := reportFor(t, result, CollectorServices)
	if report.Status != core.CollectorRan {
		t.Errorf("services report = %+v, want a clean run (a missing directory is not a failure)", report)
	}
	if report.Visited != 3 {
		t.Errorf("visited = %d, want the unit, cron file, and pm2 dump", report.Visited)
	}
}

func TestServiceCollectorSkippedWithoutSources(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "project"))

	opts := fixtureOptions(root)
	opts.Services = true
	report := reportFor(t, run(t, opts), CollectorServices)
	if report.Status != core.CollectorSkipped || report.Detail == "" {
		t.Errorf("services report = %+v, want skipped with a reason", report)
	}
}

func TestUnreadablePM2DumpIsUnknownNotEmpty(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "web"))
	dump := mustWrite(t, filepath.Join(t.TempDir(), "dump.pm2"), "{not json")

	opts := fixtureOptions(root)
	opts.Services = true
	opts.ServiceSources = ServiceSources{PM2Dumps: []string{dump}}

	report := reportFor(t, run(t, opts), CollectorServices)
	if report.Status != core.CollectorPartial || report.Unknowns != 1 {
		t.Errorf("services report = %+v, want partial with one unknown", report)
	}
}

func TestCronEnvironmentAssignmentsAreNotTreatedAsPaths(t *testing.T) {
	refs := cronReferences("/etc/cron.d/fixture", strings.Join([]string{
		"MAILTO=/root/mail",
		"PATH=/usr/bin:/bin",
		"# comment /commented/path",
		"*/5 * * * * root /srv/app/run.sh --flag",
		"",
	}, "\n"))
	if len(refs) != 1 {
		t.Fatalf("references = %+v, want only the command path", refs)
	}
	if refs[0].Path != "/srv/app/run.sh" {
		t.Errorf("path = %q, want the cron command", refs[0].Path)
	}
}

func TestIsEnvName(t *testing.T) {
	cases := map[string]bool{
		"MAILTO": true, "PATH": true, "_private": true, "A1": true,
		"": false, "1BAD": false, "/usr/bin": false, "two words": false,
	}
	for token, want := range cases {
		if got := isEnvName(token); got != want {
			t.Errorf("isEnvName(%q) = %t, want %t", token, got, want)
		}
	}
}

func TestFirstAbsolutePathSkipsExecPrefixes(t *testing.T) {
	cases := map[string]string{
		"-/usr/bin/env node app.js": "/usr/bin/env",
		"@/usr/bin/true arg":        "/usr/bin/true",
		"relative/cmd":              "",
		"+!/opt/tool/run":           "/opt/tool/run",
	}
	for value, want := range cases {
		if got := firstAbsolutePath(value); got != want {
			t.Errorf("firstAbsolutePath(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestProcessCollectorSkippedWhenProcfsMissing(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "project"))

	opts := fixtureOptions(root)
	opts.Processes = true
	opts.ProcRoot = filepath.Join(t.TempDir(), "absent")

	report := reportFor(t, run(t, opts), CollectorProcesses)
	if report.Status != core.CollectorSkipped {
		t.Errorf("report = %+v, want skipped when procfs is unavailable", report)
	}
}

// assertNoSecretRecorded fails when a sensitive value reached any evidence,
// protection, or report text.
func assertNoSecretRecorded(t *testing.T, result Result, secret string) {
	t.Helper()
	for _, entry := range result.Entries {
		for _, evidence := range entry.Evidence {
			if strings.Contains(evidence.Detail, secret) || strings.Contains(evidence.Signal, secret) {
				t.Errorf("%s evidence leaked a sensitive value: %+v", entry.Path, evidence)
			}
		}
		for _, protection := range entry.Protections {
			if strings.Contains(protection.Reason, secret) {
				t.Errorf("%s protection leaked a sensitive value: %+v", entry.Path, protection)
			}
		}
	}
	for _, report := range result.Reports {
		if strings.Contains(report.Detail, secret) {
			t.Errorf("collector %q leaked a sensitive value: %s", report.Name, report.Detail)
		}
	}
}

func TestAttachReferencesIgnoresRelativePaths(t *testing.T) {
	entries := []core.Entry{{Path: "/repos/app"}}
	matched := attachReferences(entries, []Reference{
		{Path: "relative/path", Source: core.SourceProcess, Protection: core.ProtectActiveProcess, Signal: "process_cwd"},
	}, time.Now())
	if matched != 0 || len(entries[0].Protections) != 0 {
		t.Errorf("relative reference was attached: matched=%d protections=%+v", matched, entries[0].Protections)
	}
}
