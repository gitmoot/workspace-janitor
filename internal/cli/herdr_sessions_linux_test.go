//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

// fakeHerdr installs an executable herdr stand-in that prints whatever the
// returned answer file holds, and configures collectors.herdr with it over
// the fixture's sessions root. A test rewrites the answer file between runs.
func fakeHerdr(t *testing.T, x *stateStoreFixture) string {
	t.Helper()
	dir := t.TempDir()
	answer := filepath.Join(dir, "answer.json")
	writeHerdrAnswer(t, answer, herdrAgentList())
	binary := filepath.Join(dir, "herdr")
	script := "#!/bin/sh\n[ \"$*\" = 'agent list --json' ] || exit 64\nexec /bin/cat " + answer + "\n"
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	x.collectors = fmt.Sprintf("  herdr:\n    binary: %s\n    session_roots: [%s]\n", binary, x.sessions)
	return answer
}

func writeHerdrAnswer(t *testing.T, path, answer string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(answer), 0o644); err != nil {
		t.Fatal(err)
	}
}

// herdrAgentList is a "herdr agent list --json" answer whose OMP agents
// resume the given transcripts, plus one Claude agent with an id session
// and one OMP agent of another machine.
func herdrAgentList(transcripts ...string) string {
	agents := []any{
		map[string]any{"agent": "claude", "name": "discovery", "pane_id": "",
			"agent_session": map[string]any{"agent": "claude", "kind": "id", "source": "herdr:claude", "value": "d3963389-8e73-4043-8a33-bb193a5bf5bb"}},
		map[string]any{"agent": "omp", "name": "mac-seat", "pane_id": "w1:p2",
			"agent_session": map[string]any{"agent": "omp", "kind": "path", "source": "herdr:omp", "value": "/Users/jerry/.omp/agent/sessions/-x/2026-09-23T12-34-59-978Z_01a0ce43.jsonl"}},
	}
	for i, transcript := range transcripts {
		agents = append(agents, map[string]any{"agent": "omp", "name": fmt.Sprintf("seat-%d", i), "pane_id": fmt.Sprintf("w6536:p%d", 70+i),
			"agent_status": "idle", "cwd": "/root",
			"agent_session": map[string]any{"agent": "omp", "kind": "path", "source": "herdr:omp", "value": transcript}})
	}
	data, _ := json.Marshal(map[string]any{"id": "cli:agent:list", "result": map[string]any{"type": "agent_list", "agents": agents}})
	return string(data)
}

const herdrNotRunning = `{"id":"cli:agent:list","error":{"code":"server_not_running","message":"no herdr server is running"}}`

// failingCategories runs a confirmed category archive that must fail and
// returns its report.
func failingCategories(t *testing.T, x *stateStoreFixture) categoryArchiveReport {
	t.Helper()
	out, stderr, code := x.runAgents(t, "--format", "json", "archive", "--categories", "--dry-run=false", "--confirm")
	if code == ExitOK {
		t.Fatalf("category archive succeeded while herdr gave no answer: %s", out)
	}
	var doc struct {
		Data categoryArchiveReport `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v\n%s\n%s", err, out, stderr)
	}
	return doc.Data
}

// expire runs a confirmed expiry of one receipt and returns its report.
func expire(t *testing.T, x *stateStoreFixture, cleanupID string) (cleanupReport, ExitCode) {
	t.Helper()
	out, stderr, code := x.run(t, "--format", "json", "apply", "--expire", "--cleanup", cleanupID, "--dry-run=false", "--confirm")
	var doc struct {
		Data cleanupReport `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("expiry output: %v\n%s\n%s", err, out, stderr)
	}
	return doc.Data, code
}

// A session whose transcript a live herdr agent resumes stays local as a
// whole: herdr names only the .jsonl, yet the session folder (the unit
// omp_sessions archives) is refused with the agent and its pane named. An
// unreferenced idle session is still archived.
func TestHerdrLiveSessionIsNeverArchived(t *testing.T) {
	x := newStateStoreFixture(t)
	answer := fakeHerdr(t, x)
	x.writeStores(t, "")
	live := x.session(t, "-proj", sessionA, categoryIdleAge)
	idle := x.session(t, "-proj", sessionB, categoryIdleAge)
	writeHerdrAnswer(t, answer, herdrAgentList(live+".jsonl"))
	before := snapshot(t, live, live+".jsonl")

	report := x.categories(t, false)
	item := categoryItem(t, report, live)
	reasons := strings.Join(item.Reasons, ";")
	if item.Status != categoryRefused || !strings.Contains(reasons, "live_agent_session") || !strings.Contains(reasons, "pane w6536:p70") {
		t.Fatalf("herdr-referenced session not refused as live_agent_session: %+v", item)
	}
	sameSnapshot(t, "live session", snapshot(t, live, live+".jsonl"), before)
	archived := categoryItem(t, report, idle)
	if archived.Status != categoryArchived || archived.Companion != idle+".jsonl" {
		t.Fatalf("unreferenced idle session not archived: %+v", archived)
	}
	if report.Failed != 0 {
		t.Fatalf("a live session counted as a failure: %+v", report)
	}
}

// An archived session that a herdr agent resumes afterwards is not
// quarantined, and once quarantined it is not expired: the original names
// of the unit and of its transcript are live.
func TestHerdrLiveSessionIsNeverQuarantinedOrExpired(t *testing.T) {
	x := newStateStoreFixture(t)
	answer := fakeHerdr(t, x)
	x.writeStores(t, "")
	held := x.session(t, "-proj", sessionA, categoryIdleAge)
	moved := x.session(t, "-proj", sessionB, categoryIdleAge)
	report := x.categories(t, false)
	for _, session := range []string{held, moved} {
		if item := categoryItem(t, report, session); item.Status != categoryArchived {
			t.Fatalf("idle session not archived: %+v", item)
		}
	}
	receipt := x.quarantineUnit(t, moved)

	writeHerdrAnswer(t, answer, herdrAgentList(held+".jsonl", moved+".jsonl"))
	if _, action := x.action(t, held); action.Kind == core.ActionQuarantine {
		t.Fatalf("herdr-referenced archived session proposed for quarantine: %+v", action)
	}
	got, code := expire(t, x, receipt.CleanupID)
	if code == ExitOK || len(got.Errors) != 0 || len(got.Refused) != 1 || !strings.Contains(got.Refused[0], "live_agent_session") {
		t.Fatalf("expiry of a herdr-referenced session not refused (exit %d): %+v", code, got)
	}
	if _, err := os.Lstat(receipt.Destination); err != nil {
		t.Fatalf("quarantined copy of a live session is gone: %v", err)
	}
	if _, err := os.Lstat(receipt.Destination + ".jsonl"); err != nil {
		t.Fatalf("quarantined transcript of a live session is gone: %v", err)
	}
}

// Herdr configured but not answering leaves every session unit unknown: the
// category run fails each one instead of refusing it and archives nothing,
// expiry of a quarantined unit is a failure, and the cycle fails.
func TestHerdrFailureFailsEverySessionUnit(t *testing.T) {
	for name, broken := range map[string]string{
		"error document": herdrNotRunning,
		"not JSON":       "herdr: socket closed\n",
		"no agent list":  `{"id":"cli:agent:list","result":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			x := newStateStoreFixture(t)
			answer := fakeHerdr(t, x)
			x.writeStores(t, "")
			quarantined := x.session(t, "-proj", sessionA, categoryIdleAge)
			if item := categoryItem(t, x.categories(t, false), quarantined); item.Status != categoryArchived {
				t.Fatalf("idle session not archived: %+v", item)
			}
			receipt := x.quarantineUnit(t, quarantined)
			idle := x.session(t, "-other", sessionB, categoryIdleAge)
			archives, err := os.ReadDir(x.archive)
			if err != nil {
				t.Fatal(err)
			}

			writeHerdrAnswer(t, answer, broken)
			report := failingCategories(t, x)
			item := categoryItem(t, report, idle)
			if item.Status != categoryFailed || !strings.Contains(strings.Join(item.Reasons, ";"), "herdr") || report.Refused != 0 {
				t.Fatalf("session under a failing herdr not failed: %+v (report %+v)", item, report)
			}
			if after, err := os.ReadDir(x.archive); err != nil || len(after) != len(archives) {
				t.Fatalf("archived under a failing herdr: %d -> %d entries (%v)", len(archives), len(after), err)
			}
			got, code := expire(t, x, receipt.CleanupID)
			if code == ExitOK || len(got.Errors) != 1 || len(got.Refused) != 0 || !strings.Contains(got.Errors[0], "herdr") {
				t.Fatalf("expiry under a failing herdr not a failure (exit %d): %+v", code, got)
			}
			if _, err := os.Lstat(receipt.Destination); err != nil {
				t.Fatalf("quarantined session expired under a failing herdr: %v", err)
			}
			out, stderr, code := x.run(t, "cycle")
			if code == ExitOK || !strings.Contains(stderr, "herdr") {
				t.Fatalf("cycle did not fail under a failing herdr: exit=%d %s %s", code, out, stderr)
			}
		})
	}
}

// omp_session_artifacts keeps moving old single files out of a live seat's
// folder (owner decision 2026-11-09, boundary set 2026-11-18): a herdr
// reference to the session, or a herdr that does not answer, changes
// nothing for them, and the referenced transcript itself is never selected.
func TestHerdrSessionArtifactsStillMoveButNeverTheTranscript(t *testing.T) {
	for name, live := range map[string]bool{"referenced": true, "herdr failing": false} {
		t.Run(name, func(t *testing.T) {
			x := newArtifactFixture(t)
			answer := fakeHerdr(t, x.stateStoreFixture)
			x.prevention = "  auto_quarantine: true\n"
			x.writeArtifacts(t)
			session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"old.log": oldArtifact})
			transcript, err := os.ReadFile(session + ".jsonl")
			if err != nil {
				t.Fatal(err)
			}
			if live {
				writeHerdrAnswer(t, answer, herdrAgentList(session+".jsonl"))
			} else {
				writeHerdrAnswer(t, answer, herdrNotRunning)
			}
			item := categoryItem(t, x.categories(t, false), session)
			if item.Status != categoryArchived || item.Files != 1 {
				t.Fatalf("old artifact of a herdr session not archived: %+v", item)
			}
			for member := range x.tarMembers(t, item.Name) {
				if strings.HasSuffix(member, ".jsonl") {
					t.Fatalf("session transcript archived as %s", member)
				}
			}
			if report := x.quarantineArtifacts(t); len(report.Batches) != 1 || report.Batches[0].Moved != 1 {
				t.Fatalf("artifact batch of a herdr session not moved: %+v", report)
			}
			if got := contents(t, session, "old.log"); got["old.log"] != "<absent>" {
				t.Fatalf("artifact still in place: %v", got)
			}
			if got, err := os.ReadFile(session + ".jsonl"); err != nil || !bytes.Equal(got, transcript) {
				t.Fatalf("session transcript changed or moved: %v %q", err, got)
			}
			if _, err := os.Stat(session); err != nil {
				t.Fatalf("session folder moved: %v", err)
			}
		})
	}
}

// herdrScript installs a herdr stand-in running body and configures
// collectors.herdr with it over root.
func herdrScript(t *testing.T, x *stateStoreFixture, root, body string) {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "herdr")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n[ \"$*\" = 'agent list --json' ] || exit 64\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	x.collectors = fmt.Sprintf("  herdr:\n    binary: %s\n    session_roots: [%s]\n", binary, root)
	x.writeStores(t, "")
}

// Review of #222: session_roots may name a symlinked alias of the store
// that inventory and omp_sessions observe by its real path. Herdr still
// runs, the referenced session is refused, and a failing herdr still fails
// every session unit.
func TestHerdrAliasedSessionRootStillGuards(t *testing.T) {
	setup := func(t *testing.T, answer string) (*stateStoreFixture, string) {
		x := newStateStoreFixture(t)
		alias := filepath.Join(t.TempDir(), "alias")
		if err := os.Symlink(x.home, alias); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(alias, ".omp", "agent", "sessions")
		file := filepath.Join(t.TempDir(), "answer.json")
		herdrScript(t, x, root, "exec /bin/cat "+file)
		session := x.session(t, "-proj", sessionA, categoryIdleAge)
		if answer == "" {
			answer = herdrAgentList(filepath.Join(root, "-proj", sessionA+".jsonl"))
		}
		writeHerdrAnswer(t, file, answer)
		return x, session
	}
	t.Run("live session", func(t *testing.T) {
		x, session := setup(t, "")
		report := x.categories(t, false)
		item := categoryItem(t, report, session)
		if item.Status != categoryRefused || !strings.Contains(strings.Join(item.Reasons, ";"), "live_agent_session") || report.Failed != 0 {
			t.Fatalf("session named through an aliased root not refused as live: %+v (report %+v)", item, report)
		}
	})
	t.Run("herdr failing", func(t *testing.T) {
		x, session := setup(t, herdrNotRunning)
		item := categoryItem(t, failingCategories(t, x), session)
		if item.Status != categoryFailed || !strings.Contains(strings.Join(item.Reasons, ";"), "herdr") {
			t.Fatalf("session under an aliased root and a failing herdr not failed: %+v", item)
		}
	})
}

// Review of #222: a session can wait in the archive queue behind earlier
// copies, so herdr is asked again before the copy and again before the
// archive is published. A session that became live meanwhile is refused
// (not failed) and nothing is recorded for it.
func TestHerdrIsAskedAgainBeforeCopyAndPublication(t *testing.T) {
	// herdr call 1 is the run's observation; 2 the archive preflight before
	// the copy; 3 the preflight before publication.
	for name, liveFrom := range map[string]int{"before the copy": 2, "before publication": 3} {
		t.Run(name, func(t *testing.T) {
			x := newStateStoreFixture(t)
			dir := t.TempDir()
			session := x.session(t, "-proj", sessionA, categoryIdleAge)
			writeHerdrAnswer(t, filepath.Join(dir, "idle.json"), herdrAgentList())
			writeHerdrAnswer(t, filepath.Join(dir, "live.json"), herdrAgentList(session+".jsonl"))
			herdrScript(t, x, x.sessions, fmt.Sprintf(`n=$(/bin/cat %[1]s/count 2>/dev/null || echo 0); n=$((n+1)); echo $n > %[1]s/count
if [ $n -ge %[2]d ]; then exec /bin/cat %[1]s/live.json; fi
exec /bin/cat %[1]s/idle.json`, dir, liveFrom))

			report := x.categories(t, false)
			item := categoryItem(t, report, session)
			if item.Status != categoryRefused || !strings.Contains(strings.Join(item.Reasons, ";"), "live_agent_session") || report.Failed != 0 {
				t.Fatalf("session that became live %s not refused: %+v (report %+v)", name, item, report)
			}
			records, err := store.ReadCategoryArchives(context.Background(), x.paths(t).DatabaseFile)
			if err != nil {
				t.Fatal(err)
			}
			for _, record := range records {
				if record.Path == session {
					t.Fatalf("archive of a live session recorded: %+v", record)
				}
			}
		})
	}
}

// A restore never replaces a session path that exists again: the
// recreated folder or transcript is left as it is, and the quarantined unit
// stays in quarantine.
func TestRestoreNeverOverwritesARecreatedSession(t *testing.T) {
	for name, recreate := range map[string]func(session string) string{
		"session folder": func(session string) string { return filepath.Join(session, "new.log") },
		"transcript":     func(session string) string { return session + ".jsonl" },
	} {
		t.Run(name, func(t *testing.T) {
			x := newStateStoreFixture(t)
			session := x.session(t, "-proj", sessionA, categoryIdleAge)
			if item := categoryItem(t, x.categories(t, false), session); item.Status != categoryArchived {
				t.Fatalf("idle session not archived: %+v", item)
			}
			receipt := x.quarantineUnit(t, session)
			path := recreate(session)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("written by a live agent\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, _, code := x.run(t, "restore", "--confirm", receipt.CleanupID); code == ExitOK {
				t.Fatal("restore over a recreated session path succeeded")
			}
			if data, err := os.ReadFile(path); err != nil || string(data) != "written by a live agent\n" {
				t.Fatalf("recreated %s overwritten: %q %v", filepath.Base(path), data, err)
			}
			for _, moved := range []string{receipt.Destination, receipt.Destination + ".jsonl"} {
				if _, err := os.Lstat(moved); err != nil {
					t.Fatalf("quarantined %s left quarantine: %v", filepath.Base(moved), err)
				}
			}
		})
	}
}

// Review round 2 of #222, the reviewer's setup: session_roots names the
// real store and an inventory root a symlinked alias of it (beside the real
// root the category requires). The scan runs
// herdr and protects the live folder and its transcript as the alias spells
// them; a failing herdr leaves them unknown.
func TestHerdrInventoryAliasScanStillGuards(t *testing.T) {
	for name, answer := range map[string]string{"live session": "", "herdr failing": herdrNotRunning} {
		t.Run(name, func(t *testing.T) {
			x := newStateStoreFixture(t)
			file := filepath.Join(t.TempDir(), "answer.json")
			herdrScript(t, x, x.sessions, "exec /bin/cat "+file)
			session := x.session(t, "-proj", sessionA, categoryIdleAge)
			if answer == "" {
				answer = herdrAgentList(session + ".jsonl")
			}
			writeHerdrAnswer(t, file, answer)
			home := filepath.Join(t.TempDir(), "home")
			if err := os.Symlink(x.home, home); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(home, ".omp", "agent", "sessions")
			raw, err := os.ReadFile(x.paths(t).PolicyFile)
			if err != nil {
				t.Fatal(err)
			}
			x.writePolicy(t, strings.Replace(string(raw), "roots:\n", "roots:\n  - path: "+alias+"\n    max_depth: 2\n", 1))
			want := "live_agent_session"
			if answer == herdrNotRunning {
				want = "collector_failure"
			}
			x.data(t, "scan")
			x.data(t, "plan", "--no-jev")
			for _, path := range []string{filepath.Join(alias, "-proj", sessionA), filepath.Join(alias, "-proj", sessionA+".jsonl")} {
				var verdict core.Verdict
				field(t, x.data(t, "explain", path), "safety_verdict", &verdict)
				found := false
				for _, protection := range verdict.Protections {
					found = found || string(protection.Kind) == want
				}
				if !found {
					t.Errorf("%s through the alias lacks %s: %+v", path, want, verdict.Protections)
				}
			}
		})
	}
}
