package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// stateStoreDoc configures the roots the state-store category tests use:
// the exact OMP sessions and Gitmoot job-log stores (the latter inside the
// default Gitmoot home, which is protected), and nearby raw-state roots of
// other shapes.
func stateStoreDoc(paths Paths) string {
	jobs := filepath.Join(paths.Home, ".gitmoot", "logs", "jobs")
	return `roots:
  - path: /srv/u/.omp/agent/sessions
    max_depth: 2
  - path: /srv/shallow/.omp/agent/sessions
  - path: /srv/u/.omp/agent
    max_depth: 2
  - path: /srv/u/.omp/run/daemons
    max_depth: 2
  - path: /srv/u/.gitmoot
  - path: /srv/u/.gitmoot/logs/jobs
  - path: /srv/u/.ssh/.omp/agent/sessions
    max_depth: 2
  - path: ` + jobs + `
protect:
  paths: [/srv/archive, /srv/u/.omp/agent/sessions/-kept-project]
`
}

// The narrow raw-state exemption: each state-store kind accepts exactly its
// own store shape, and every other kind still refuses those roots.
func TestStateStoreCategoryRootsAreExact(t *testing.T) {
	paths := fixturePaths(t)
	jobs := filepath.Join(paths.Home, ".gitmoot", "logs", "jobs")
	accepted := stateStoreDoc(paths) + "workspace_archive_categories:\n" +
		categoryEntry("sessions", "omp_sessions", "/srv/u/.omp/agent/sessions") +
		categoryEntry("job-logs", "gitmoot_job_logs", jobs)
	policy, err := parse(t, paths, accepted)
	if err != nil {
		t.Fatalf("exact OMP sessions and Gitmoot job-log roots refused: %v", err)
	}
	if got := policy.WorkspaceArchiveCategories[0].Idle.String(); got != "14d" {
		t.Fatalf("omp_sessions default idle = %s", got)
	}
	for _, tc := range []struct{ name, entry, fragment string }{
		{"omp agent dir", categoryEntry("s", "omp_sessions", "/srv/u/.omp/agent"), "exactly a .../.omp/agent/sessions directory"},
		{"omp daemons", categoryEntry("s", "omp_sessions", "/srv/u/.omp/run/daemons"), "exactly a .../.omp/agent/sessions directory"},
		{"gitmoot home", categoryEntry("g", "gitmoot_job_logs", "/srv/u/.gitmoot"), "exactly a .../.gitmoot/logs/jobs directory"},
		{"sessions as job logs", categoryEntry("g", "gitmoot_job_logs", "/srv/u/.omp/agent/sessions"), "exactly a .../.gitmoot/logs/jobs directory"},
		{"store below a credential dir", categoryEntry("s", "omp_sessions", "/srv/u/.ssh/.omp/agent/sessions"), "credential containers cannot be category roots"},
		{"sessions root one level deep", categoryEntry("s", "omp_sessions", "/srv/shallow/.omp/agent/sessions"), "max_depth of at least 2"},
		{"scratch over sessions", categoryEntry("s", "root_scratch", "/srv/u/.omp/agent/sessions"), "credential containers cannot be category roots"},
		{"scratch over daemons", categoryEntry("s", "root_scratch", "/srv/u/.omp/run/daemons"), "credential containers cannot be category roots"},
		{"scratch over job logs", categoryEntry("s", "root_scratch", "/srv/u/.gitmoot/logs/jobs"), "credential containers cannot be category roots"},
		{"scratch over gitmoot home logs", categoryEntry("s", "root_scratch", jobs), "lies inside protect.paths entry"},
		{"sessions idle under a day", categoryEntry("s", "omp_sessions", "/srv/u/.omp/agent/sessions") + "    idle: 23h\n", "at least 1d"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(t, paths, stateStoreDoc(paths)+"workspace_archive_categories:\n"+tc.entry)
			if err == nil || !strings.Contains(err.Error(), tc.fragment) {
				t.Fatalf("want an error containing %q, got %v", tc.fragment, err)
			}
		})
	}
}

// Only the units of a configured state-store root escape the raw-state and
// Gitmoot-home refusals; any deeper or other raw-state path, and every other
// protection, still refuses.
func TestStateStoreUnitRefusals(t *testing.T) {
	paths := fixturePaths(t)
	jobs := filepath.Join(paths.Home, ".gitmoot", "logs", "jobs")
	policy, err := parse(t, paths, stateStoreDoc(paths)+"workspace_archive_keep:\n  - path: /srv/u/.omp/agent/sessions/-p/kept\n    owner: seat-b\n    reference: keep-1\n"+
		"workspace_archive_categories:\n"+
		categoryEntry("sessions", "omp_sessions", "/srv/u/.omp/agent/sessions")+
		categoryEntry("job-logs", "gitmoot_job_logs", jobs))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	for _, path := range []string{"/srv/u/.omp/agent/sessions/-p/2026-01-01T00-00-00-000Z_01a0", "/srv/u/.omp/agent/sessions/-p/s.jsonl", jobs + "/coordinator.log"} {
		if refusals := policy.CategoryArchiveRefusals(path); len(refusals) != 0 {
			t.Errorf("%s refused: %v", path, refusals)
		}
	}
	for path, fragment := range map[string]string{
		"/srv/u/.omp/agent/sessions/-p":                "raw runtime/session stores",
		"/srv/u/.omp/agent/sessions/-p/s/inner":        "raw runtime/session stores",
		"/srv/u/.omp/run/daemons/d":                    "raw runtime/session stores",
		"/srv/u/.omp/agent/sessions/-p/kept":           "KEEP",
		"/srv/u/.omp/agent/sessions/-kept-project/s":   "protect.paths",
		jobs + "/sub/a.log":                            "Gitmoot's managed state",
		filepath.Join(paths.Home, ".gitmoot", "x.log"): "Gitmoot's managed state",
	} {
		if refusals := strings.Join(policy.CategoryArchiveRefusals(path), "\n"); !strings.Contains(refusals, fragment) {
			t.Errorf("%s: refusals %q lack %q", path, refusals, fragment)
		}
	}
}

func TestOMPSessionUnitShape(t *testing.T) {
	dir := "/srv/u/.omp/agent/sessions/-p/2026-09-07T15-00-22-554Z_01a07c62-759a-7452-a1c8-f3ebf00ff14f"
	if got := CategoryOMPSessions.UnitCompanion(dir); got != dir+".jsonl" {
		t.Fatalf("session companion = %q", got)
	}
	if got := CategoryOMPSessions.UnitCompanion(dir + ".jsonl"); got != "" {
		t.Fatalf("a lone transcript has companion %q", got)
	}
	if got := CategoryGitmootJobLogs.UnitCompanion("/x/.gitmoot/logs/jobs/a"); got != "" {
		t.Fatalf("job log has companion %q", got)
	}
	want := []string{dir, "01a07c62-759a-7452-a1c8-f3ebf00ff14f"}
	for _, path := range []string{dir, dir + ".jsonl"} {
		if got := CategoryOMPSessions.UnitMentions(path); strings.Join(got, "|") != strings.Join(want, "|") {
			t.Fatalf("mentions of %s = %q, want %q", path, got, want)
		}
	}
}
