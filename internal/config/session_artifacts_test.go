package config

import (
	"strings"
	"testing"
)

// omp_session_artifacts takes exactly an .../.omp/agent/sessions root, as
// omp_sessions does; every other .omp root, a sub-day idle and a batch
// bound on another kind are refused.
func TestSessionArtifactRootsAreExact(t *testing.T) {
	paths := fixturePaths(t)
	sessions := "/srv/u/.omp/agent/sessions"
	policy, err := parse(t, paths, stateStoreDoc(paths)+"workspace_archive_categories:\n"+
		categoryEntry("artifacts", "omp_session_artifacts", sessions)+"    idle: 1d\n"+
		categoryEntry("sessions", "omp_sessions", sessions))
	if err != nil {
		t.Fatalf("exact sessions root refused for omp_session_artifacts beside omp_sessions: %v", err)
	}
	if got := policy.WorkspaceArchiveCategories[0].MaxFilesPerBatch; got != DefaultCategoryMaxFilesPerBatch {
		t.Fatalf("default max_files_per_batch = %d", got)
	}
	for _, tc := range []struct{ name, entry, fragment string }{
		{"omp agent dir", categoryEntry("a", "omp_session_artifacts", "/srv/u/.omp/agent"), "exactly a .../.omp/agent/sessions directory"},
		{"omp daemons", categoryEntry("a", "omp_session_artifacts", "/srv/u/.omp/run/daemons"), "exactly a .../.omp/agent/sessions directory"},
		{"store below a credential dir", categoryEntry("a", "omp_session_artifacts", "/srv/u/.ssh/.omp/agent/sessions"), "credential containers cannot be category roots"},
		{"idle under a day", categoryEntry("a", "omp_session_artifacts", sessions) + "    idle: 23h\n", "at least 1d"},
		{"batch bound above its cap", categoryEntry("a", "omp_session_artifacts", sessions) + "    max_files_per_batch: 50001\n", "max_files_per_batch"},
		{"batch bound on another kind", categoryEntry("s", "omp_sessions", sessions) + "    max_files_per_batch: 10\n", "applies to omp_session_artifacts only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(t, paths, stateStoreDoc(paths)+"workspace_archive_categories:\n"+tc.entry)
			if err == nil || !strings.Contains(err.Error(), tc.fragment) {
				t.Fatalf("want an error containing %q, got %v", tc.fragment, err)
			}
		})
	}
}

// A session artifact is a file strictly inside a session folder: the
// session's own transcript beside it, raw-state or credential components
// below it, and KEEP or protected paths still refuse.
func TestSessionArtifactRefusals(t *testing.T) {
	paths := fixturePaths(t)
	policy, err := parse(t, paths, stateStoreDoc(paths)+"workspace_archive_keep:\n  - path: /srv/u/.omp/agent/sessions/-p/s/kept\n    owner: seat-b\n    reference: keep-1\n"+
		"workspace_archive_categories:\n"+categoryEntry("artifacts", "omp_session_artifacts", "/srv/u/.omp/agent/sessions"))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	for _, path := range []string{"/srv/u/.omp/agent/sessions/-p/s/0.bash.log", "/srv/u/.omp/agent/sessions/-p/s/sub/deep/__advisor.jsonl"} {
		if refusals := policy.CategoryArchiveRefusals(path); len(refusals) != 0 {
			t.Errorf("%s refused: %v", path, refusals)
		}
	}
	for path, fragment := range map[string]string{
		"/srv/u/.omp/agent/sessions/-p/s.jsonl":        "raw runtime/session stores",
		"/srv/u/.omp/agent/sessions/-p/s/.ssh/id":      "inside a session folder",
		"/srv/u/.omp/agent/sessions/-p/s/kept/a.log":   "KEEP",
		"/srv/u/.omp/agent/sessions/-kept-project/s/a": "protect.paths",
		"/srv/u/.omp/agent/agent.db":                   "raw runtime/session stores",
		"/srv/u/.omp/run/daemons/d/s/x":                "raw runtime/session stores",
	} {
		if refusals := strings.Join(policy.CategoryArchiveRefusals(path), "\n"); !strings.Contains(refusals, fragment) {
			t.Errorf("%s: refusals %q lack %q", path, refusals, fragment)
		}
	}
}
