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

func TestSystemdAliasesReuseProvenUnitWithoutPartial(t *testing.T) {
	workspace := t.TempDir()
	service := mustMkdir(t, filepath.Join(workspace, "service"))
	units := t.TempDir()
	system := t.TempDir()
	canonical := filepath.Join(system, "canonical.service")
	mustWrite(t, canonical, "WorkingDirectory="+service+"\n")
	if err := os.Symlink("canonical.service", filepath.Join(system, "same-dir.service")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(canonical, filepath.Join(units, "cross-root.service")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(units, "masked.service")); err != nil {
		t.Fatal(err)
	}
	opts := fixtureOptions(workspace)
	opts.Services = true
	opts.ServiceSources = ServiceSources{SystemdDirs: []string{units, system}}
	refs, report := gatherServiceReferences(context.Background(), &opts)
	if report.Status != core.CollectorRan || report.Unknowns != 0 {
		t.Fatalf("ordinary aliases treated as unknown: %+v", report)
	}
	if len(refs) != 1 || refs[0].Path != service {
		t.Fatalf("alias duplicated or dropped the canonical reference: %+v", refs)
	}
}

func TestSystemdAliasesFailClosedWhenTargetUnproven(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(t *testing.T, units, outside string)
	}{
		{"broken", func(t *testing.T, units, _ string) {
			t.Helper()
			if err := os.Symlink("missing.service", filepath.Join(units, "alias.service")); err != nil {
				t.Fatal(err)
			}
		}},
		{"escaping", func(t *testing.T, units, outside string) {
			t.Helper()
			if err := os.Symlink(filepath.Join(outside, "unscanned.service"), filepath.Join(units, "alias.service")); err != nil {
				t.Fatal(err)
			}
		}},
		{"relative escape", func(t *testing.T, units, _ string) {
			t.Helper()
			if err := os.Symlink("../outside.service", filepath.Join(units, "alias.service")); err != nil {
				t.Fatal(err)
			}
		}},
		{"loop", func(t *testing.T, units, _ string) {
			t.Helper()
			if err := os.Symlink("other.service", filepath.Join(units, "alias.service")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("alias.service", filepath.Join(units, "other.service")); err != nil {
				t.Fatal(err)
			}
		}},
		{"unscanned", func(t *testing.T, units, _ string) {
			t.Helper()
			mustWrite(t, filepath.Join(units, "large.service"), strings.Repeat("x", maxUnitFileBytes+1))
			if err := os.Symlink("large.service", filepath.Join(units, "alias.service")); err != nil {
				t.Fatal(err)
			}
		}},
		{"external device", func(t *testing.T, units, _ string) {
			t.Helper()
			if err := os.Symlink("/dev/zero", filepath.Join(units, "alias.service")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workspace := t.TempDir()
			units := t.TempDir()
			outside := t.TempDir()
			mustWrite(t, filepath.Join(outside, "unscanned.service"), "WorkingDirectory="+workspace+"\n")
			tc.build(t, units, outside)
			opts := fixtureOptions(workspace)
			opts.Services = true
			opts.ServiceSources = ServiceSources{SystemdDirs: []string{units}}
			refs, report := gatherServiceReferences(context.Background(), &opts)
			if report.Status != core.CollectorPartial || report.Unknowns == 0 || len(refs) != 0 {
				t.Fatalf("unproven alias was trusted: report=%+v refs=%+v", report, refs)
			}
		})
	}
}

func TestSystemdAliasChangedAfterListingIsUnknown(t *testing.T) {
	units := t.TempDir()
	canonical := filepath.Join(units, "canonical.service")
	mustWrite(t, canonical, "[Service]\n")
	link := filepath.Join(units, "alias.service")
	if err := os.Symlink("canonical.service", link); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(units)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	initial, err := root.Lstat("alias.service")
	if err != nil {
		t.Fatal(err)
	}
	target, err := root.Lstat("canonical.service")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/zero", link); err != nil {
		t.Fatal(err)
	}
	alias := unitLocation{directory: 0, name: "alias.service"}
	regular := unitLocation{directory: 0, name: "canonical.service"}
	err = proveSystemdAlias(alias, initial, []systemdDirectory{{path: units, root: root}},
		map[unitLocation]os.FileInfo{regular: target}, map[unitLocation]os.FileInfo{alias: initial})
	if err == nil {
		t.Fatal("changed alias was proven from its stale listing")
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

// A truncated service directory hides definitions, and a hidden definition
// may be the only thing protecting a workspace path. The bound must surface
// as an unknown, never as a clean listing.
func TestServiceDirectoryBoundsAreReportedAsUnknown(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "service"))

	systemdDir := t.TempDir()
	for _, name := range []string{"a.service", "b.service", "c.service"} {
		mustWrite(t, filepath.Join(systemdDir, name), "[Service]\nWorkingDirectory=/srv/"+name+"\n")
	}
	cronDir := t.TempDir()
	for _, name := range []string{"one", "two", "three"} {
		mustWrite(t, filepath.Join(cronDir, name), "0 * * * * root /srv/"+name+"/run.sh\n")
	}

	opts := fixtureOptions(root)
	opts.Services = true
	opts.Limits.MaxDirEntries = 1
	opts.ServiceSources = ServiceSources{SystemdDirs: []string{systemdDir}, CronPaths: []string{cronDir}}

	report := reportFor(t, run(t, opts), CollectorServices)
	if report.Status != core.CollectorPartial {
		t.Fatalf("services report = %+v, want partial once a listing is truncated", report)
	}
	if report.Unknowns < 2 {
		t.Errorf("unknowns = %d, want both truncated directories counted", report.Unknowns)
	}
	if !strings.Contains(report.Detail, "truncated") {
		t.Errorf("detail = %q, want it to name the truncation", report.Detail)
	}
}

// A definition path that is not a regular file — a FIFO, for instance —
// would block an ordinary read forever. It must be refused and reported.
func TestServiceCollectorRefusesNonRegularDefinitionFiles(t *testing.T) {
	if _, err := exec.LookPath("mkfifo"); err != nil {
		t.Skipf("mkfifo is unavailable: %v", err)
	}
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "service"))
	fifo := filepath.Join(t.TempDir(), "dump.pm2")
	if out, err := exec.Command("mkfifo", fifo).CombinedOutput(); err != nil {
		t.Skipf("cannot create a fifo: %v (%s)", err, out)
	}

	opts := fixtureOptions(root)
	opts.Services = true
	opts.Limits.CommandTimeout = 2 * time.Second
	opts.ServiceSources = ServiceSources{PM2Dumps: []string{fifo}}

	done := make(chan Result, 1)
	go func() {
		result, err := Run(context.Background(), opts)
		if err != nil {
			t.Errorf("Run: %v", err)
		}
		done <- result
	}()
	select {
	case result := <-done:
		report := reportFor(t, result, CollectorServices)
		if report.Status != core.CollectorPartial || report.Unknowns == 0 {
			t.Errorf("services report = %+v, want partial with an unknown", report)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the service collector blocked on a fifo")
	}
}

// stallingAgents ignores cancellation, as third-party code may.
type stallingAgents struct{ release chan struct{} }

func (stallingAgents) Name() string { return "stalling" }

func (s stallingAgents) ActiveDirectories(context.Context) ([]AgentRef, error) {
	<-s.release
	return nil, nil
}

// The advertised command timeout must hold even when an adapter ignores the
// context it was given.
func TestAgentSourceIgnoringCancellationIsStillBounded(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "worktree"))
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	opts := fixtureOptions(root)
	opts.Limits.CommandTimeout = 150 * time.Millisecond
	opts.AgentSources = []AgentSource{stallingAgents{release: release}}

	start := time.Now()
	result := run(t, opts)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("scan took %s: the adapter timeout did not bound the call", elapsed)
	}
	report := reportFor(t, result, CollectorAgents)
	if report.Status != core.CollectorPartial || report.Unknowns == 0 {
		t.Errorf("agents report = %+v, want partial with an unknown", report)
	}
	if !strings.Contains(report.Detail, "timeout") {
		t.Errorf("detail = %q, want it to name the timeout", report.Detail)
	}
}

// blockingSource simulates a collector stuck in a syscall no cancellation
// interrupts: it ignores its context entirely.
type blockingSource struct{ release chan struct{} }

func (blockingSource) Name() string { return "blocking" }

func (b blockingSource) ActiveDirectories(context.Context) ([]AgentRef, error) {
	<-b.release
	return nil, nil
}

// The command timeout is a wall-clock guarantee, enforced by the caller. A
// collector wedged in an uninterruptible operation must not extend the scan.
func TestRunBoundedStopsAtTheCommandTimeout(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	opts := fixtureOptions(t.TempDir())
	opts.Limits.CommandTimeout = 120 * time.Millisecond

	blocked := func(ctx context.Context, _ *Options) ([]Reference, core.CollectorReport) {
		<-release
		return nil, core.CollectorReport{Name: CollectorProcesses, Status: core.CollectorRan}
	}

	start := time.Now()
	refs, report := runBounded(context.Background(), &opts, CollectorProcesses, blocked)
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Fatalf("runBounded took %s: the deadline was not enforced by the caller", elapsed)
	}
	if len(refs) != 0 {
		t.Errorf("refs = %+v, want none from a collector that never answered", refs)
	}
	if report.Name != CollectorProcesses {
		t.Errorf("report name = %q, want the collector that overran", report.Name)
	}
	if report.Status != core.CollectorPartial || report.Unknowns != 1 {
		t.Errorf("report = %+v, want partial with one unknown", report)
	}
	if !strings.Contains(report.Detail, "command timeout") {
		t.Errorf("detail = %q, want it to name the timeout", report.Detail)
	}
}

// The same guarantee must hold through a full scan, for a collector wedged
// in an ordinary blocking syscall rather than in cooperative code. A fifo
// standing in for a stalled procfs read is the reproducible version of
// "an OS operation that never returns".
func TestScanFinishesWhenAReferenceCollectorWedges(t *testing.T) {
	if _, err := exec.LookPath("mkfifo"); err != nil {
		t.Skipf("mkfifo is unavailable: %v", err)
	}
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "project"))

	procRoot := t.TempDir()
	pidDir := mustMkdir(t, filepath.Join(procRoot, "99"))
	mustSymlink(t, root, filepath.Join(pidDir, "cwd"))
	if out, err := exec.Command("mkfifo", filepath.Join(pidDir, "comm")).CombinedOutput(); err != nil {
		t.Skipf("cannot create a fifo: %v (%s)", err, out)
	}

	opts := fixtureOptions(root)
	opts.Limits.CommandTimeout = 120 * time.Millisecond
	opts.Processes = true
	opts.ProcRoot = procRoot

	start := time.Now()
	result := run(t, opts)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("scan took %s despite a %s command timeout", elapsed, opts.Limits.CommandTimeout)
	}
	report := reportFor(t, result, CollectorProcesses)
	if report.Status != core.CollectorPartial || report.Unknowns == 0 {
		t.Errorf("processes report = %+v, want partial with an unknown", report)
	}
	if !strings.Contains(report.Detail, "timeout") {
		t.Errorf("detail = %q, want it to name the timeout", report.Detail)
	}
	if len(result.Entries) == 0 {
		t.Error("the scan must still return the entries it did observe")
	}
}
