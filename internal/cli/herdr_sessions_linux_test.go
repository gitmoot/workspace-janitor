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
// Issue #235: neither is a topic transcript (a .jsonl directly inside the
// referenced session's folder), nor, while herdr does not answer, any .jsonl
// directly inside a session folder.
func TestHerdrSessionArtifactsStillMoveButNeverTheTranscript(t *testing.T) {
	for name, live := range map[string]bool{"referenced": true, "herdr failing": false} {
		t.Run(name, func(t *testing.T) {
			x := newArtifactFixture(t)
			answer := fakeHerdr(t, x.stateStoreFixture)
			x.prevention = "  auto_quarantine: true\n"
			x.writeArtifacts(t)
			session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"old.log": 15 * 24 * time.Hour, "Topic.jsonl": 15 * 24 * time.Hour})
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
			if got := contents(t, session, "Topic.jsonl"); got["Topic.jsonl"] == "<absent>" {
				t.Fatalf("topic transcript of a herdr session moved: %v", got)
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

// Review of #238 (#244): herdr is asked afresh for each batch right before
// its quarantine. A topic transcript batched while herdr kept nothing stays
// in place when its session became live, when herdr now lists it, or when
// herdr no longer answers; its eligible sibling still moves.
func TestHerdrArtifactQuarantineRechecksTopics(t *testing.T) {
	for name, answer := range map[string]func(session string) string{
		"session became live": func(session string) string { return herdrAgentList(session + ".jsonl") },
		"topic now listed":    func(session string) string { return herdrAgentList(session + "/Topic.jsonl") },
		"herdr down":          func(string) string { return herdrNotRunning },
	} {
		t.Run(name, func(t *testing.T) {
			x := newArtifactFixture(t)
			herdr := fakeHerdr(t, x.stateStoreFixture)
			x.prevention = "  auto_quarantine: true\n"
			x.writeArtifacts(t)
			session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"old.log": 15 * 24 * time.Hour, "Topic.jsonl": 15 * 24 * time.Hour})
			item := categoryItem(t, x.categories(t, false), session)
			if item.Status != categoryArchived || item.Files != 2 {
				t.Fatalf("batch of an unreferenced session = %+v", item)
			}
			writeHerdrAnswer(t, herdr, answer(session))
			report := x.quarantineArtifacts(t)
			if len(report.Batches) != 1 || report.Batches[0].Moved != 1 || report.Batches[0].Kept != 1 {
				t.Fatalf("quarantine = %+v", report)
			}
			if got := contents(t, session, "old.log", "Topic.jsonl"); got["old.log"] != "<absent>" || got["Topic.jsonl"] == "<absent>" {
				t.Fatalf("after quarantine: %v", got)
			}
		})
	}
}

// Review of #238 (#245): an omp_session_artifacts root that
// collectors.herdr.session_roots does not name is still in herdr's scope
// for artifacts: a topic herdr lists there is not selected, while an
// ordinary log beside it still is.
func TestHerdrArtifactRootOutsideSessionRootsKeepsListedTopic(t *testing.T) {
	x := newArtifactFixture(t)
	herdr := fakeHerdr(t, x.stateStoreFixture)
	other := filepath.Join(t.TempDir(), ".omp", "agent", "sessions")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	x.collectors = strings.Replace(x.collectors, "["+x.sessions+"]", "["+other+"]", 1)
	x.writeArtifacts(t)
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"old.log": 15 * 24 * time.Hour, "Topic.jsonl": 15 * 24 * time.Hour})
	writeHerdrAnswer(t, herdr, herdrAgentList(session+"/Topic.jsonl"))
	item := categoryItem(t, x.categories(t, false), session)
	if item.Status != categoryArchived || item.Files != 1 || !reasonsContain(item, string(core.ProtectLiveAgentSession)) {
		t.Fatalf("artifacts under a root outside session_roots = %+v", item)
	}
	for member := range x.tarMembers(t, item.Name) {
		if strings.HasSuffix(member, ".jsonl") {
			t.Fatalf("listed topic archived as %s", member)
		}
	}
}

// Issue #246: a topic herdr lists below the top of its session folder is
// kept by the listing itself while the answer is clean, and, once herdr's
// answer is rejected (a duplicate title member), by the outage rule: every
// .jsonl at any depth in a session folder stays. A nested log still moves.
func TestHerdrArtifactNestedListedTopicStaysWhenTheAnswerIsRejected(t *testing.T) {
	for name, rejected := range map[string]bool{"clean answer": false, "rejected answer": true} {
		t.Run(name, func(t *testing.T) {
			x := newArtifactFixture(t)
			herdr := fakeHerdr(t, x.stateStoreFixture)
			x.prevention = "  auto_quarantine: true\n"
			x.writeArtifacts(t)
			session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"sub/old.log": 15 * 24 * time.Hour, "sub/Topic.jsonl": 15 * 24 * time.Hour})
			title, reason := `"title":"Topic"`, string(core.ProtectLiveAgentSession)
			if rejected {
				title, reason = `"title":"Topic","title":"Other"`, "herdr agent sessions are unknown"
			}
			writeHerdrAnswer(t, herdr, `{"id":"cli:agent:list","result":{"type":"agent_list","agents":[{"agent":"omp","name":"seat","pane_id":"w1:p1",`+
				`"agent_session":{"agent":"omp","kind":"path","source":"herdr:omp","value":"`+session+`.jsonl"},`+
				`"topic_sessions":[{"path":"`+session+`/sub/Topic.jsonl",`+title+`,"topic_id":"Topic"}]}]}}`)
			item := categoryItem(t, x.categories(t, false), session)
			if item.Status != categoryArchived || item.Files != 1 || !reasonsContain(item, reason) {
				t.Fatalf("artifacts with a nested listed topic = %+v", item)
			}
			for member := range x.tarMembers(t, item.Name) {
				if strings.HasSuffix(member, ".jsonl") {
					t.Fatalf("nested listed topic archived as %s", member)
				}
			}
			if report := x.quarantineArtifacts(t); len(report.Batches) != 1 || report.Batches[0].Moved != 1 {
				t.Fatalf("quarantine = %+v", report)
			}
			if got := contents(t, session, "sub/old.log", "sub/Topic.jsonl"); got["sub/old.log"] != "<absent>" || got["sub/Topic.jsonl"] == "<absent>" {
				t.Fatalf("after quarantine: %v", got)
			}
		})
	}
}

// Review of #249: a session herdr lists below the top of a session folder
// (sub/Nested.jsonl) keeps its own topics: a .jsonl directly in
// sub/Nested/ is a topic of that listed transcript, wherever it lies. Its
// sibling log still moves.
func TestHerdrArtifactListedNestedSessionKeepsItsTopics(t *testing.T) {
	x := newArtifactFixture(t)
	herdr := fakeHerdr(t, x.stateStoreFixture)
	x.prevention = "  auto_quarantine: true\n"
	x.writeArtifacts(t)
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"sub/Nested/out.log": 15 * 24 * time.Hour, "sub/Nested/Topic.jsonl": 15 * 24 * time.Hour})
	writeHerdrAnswer(t, herdr, herdrAgentList(session+"/sub/Nested.jsonl"))
	item := categoryItem(t, x.categories(t, false), session)
	if item.Status != categoryArchived || item.Files != 1 || !reasonsContain(item, "whose session folder holds its topic transcripts") {
		t.Fatalf("artifacts of a listed nested session = %+v", item)
	}
	if report := x.quarantineArtifacts(t); len(report.Batches) != 1 || report.Batches[0].Moved != 1 {
		t.Fatalf("quarantine = %+v", report)
	}
	if got := contents(t, session, "sub/Nested/out.log", "sub/Nested/Topic.jsonl"); got["sub/Nested/out.log"] != "<absent>" || got["sub/Nested/Topic.jsonl"] == "<absent>" {
		t.Fatalf("after quarantine: %v", got)
	}
}

// Review of #249: herdr is asked at the quarantine's move boundary, after
// the hashing and the procfs pass. A nested topic herdr starts listing
// while the procfs pass runs stays; its sibling log moves.
func TestHerdrArtifactQuarantineAsksHerdrAfterTheProcessScan(t *testing.T) {
	x := newArtifactFixture(t)
	herdr := fakeHerdr(t, x.stateStoreFixture)
	x.prevention = "  auto_quarantine: true\n"
	x.writeArtifacts(t)
	session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"sub/old.log": 15 * 24 * time.Hour, "sub/Topic.jsonl": 15 * 24 * time.Hour})
	if item := categoryItem(t, x.categories(t, false), session); item.Status != categoryArchived || item.Files != 2 {
		t.Fatalf("batch of an unreferenced session = %+v", item)
	}
	done := x.pauseScan(t, "4242", func() error {
		return os.WriteFile(herdr, []byte(herdrAgentList(session+"/sub/Topic.jsonl")), 0o644)
	})
	report := x.quarantineArtifacts(t)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(report.Batches) != 1 || report.Batches[0].Moved != 1 || report.Batches[0].Kept != 1 {
		t.Fatalf("quarantine = %+v", report)
	}
	if got := contents(t, session, "sub/old.log", "sub/Topic.jsonl"); got["sub/old.log"] != "<absent>" || got["sub/Topic.jsonl"] == "<absent>" {
		t.Fatalf("after quarantine: %v", got)
	}
}

// Review of #249: the quarantine's herdr query blocks, so process use is
// checked again after it. A file a process already holds, or opens while
// herdr is answering, stays in place; its sibling still moves.
func TestHerdrArtifactQuarantineRechecksOpenFilesAfterHerdr(t *testing.T) {
	for name, duringHerdr := range map[string]bool{"already open": false, "opened during herdr": true} {
		t.Run(name, func(t *testing.T) {
			x := newArtifactFixture(t)
			answer := fakeHerdr(t, x.stateStoreFixture)
			x.prevention = "  auto_quarantine: true\n"
			x.writeArtifacts(t)
			session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"held.log": oldArtifact, "calm.log": oldArtifact})
			if item := categoryItem(t, x.categories(t, false), session); item.Status != categoryArchived || item.Files != 2 {
				t.Fatalf("batch = %+v", item)
			}
			held := filepath.Join(session, "held.log")
			if duringHerdr {
				// herdr itself publishes the descriptor before it answers.
				script := "#!/bin/sh\n[ \"$*\" = 'agent list --json' ] || exit 64\n/bin/ln -sfn " + held + " " + filepath.Join(x.proc, "4242", "fd", "9") + " || exit 1\nexec /bin/cat " + answer + "\n"
				if err := os.WriteFile(filepath.Join(filepath.Dir(answer), "herdr"), []byte(script), 0o755); err != nil {
					t.Fatal(err)
				}
			} else {
				x.open(t, "4242", "9", held)
			}
			report := x.quarantineArtifacts(t)
			if len(report.Batches) != 1 || report.Batches[0].Moved != 1 || report.Batches[0].Kept != 1 || !strings.Contains(strings.Join(report.Batches[0].Reasons, "\n"), "open in a process") {
				t.Fatalf("quarantine = %+v", report)
			}
			if got := contents(t, session, "held.log", "calm.log"); got["held.log"] == "<absent>" || got["calm.log"] != "<absent>" {
				t.Fatalf("after quarantine: %v", got)
			}
		})
	}
}

// Review of #249: the quarantine's second procfs pass only waits out the
// herdr query. Only one pass can inspect the seat (scanOnce), so without
// collectors.herdr the batch would move, and with it the second pass fails
// and nothing moves. A preview runs the same checks without the moves,
// whose own revalidation inspects processes too.
func TestHerdrArtifactQuarantineSecondPassOnlyWithHerdr(t *testing.T) {
	for name, withHerdr := range map[string]bool{"without herdr": false, "with herdr": true} {
		t.Run(name, func(t *testing.T) {
			x := newArtifactFixture(t)
			if withHerdr {
				fakeHerdr(t, x.stateStoreFixture)
				x.writeArtifacts(t)
			}
			session := x.liveSession(t, "-proj", sessionA, "4242", map[string]time.Duration{"a.log": oldArtifact})
			if item := categoryItem(t, x.categories(t, false), session); item.Status != categoryArchived || item.Files != 1 {
				t.Fatalf("batch = %+v", item)
			}
			swapped := x.scanOnce(t, "4242")
			out, stderr, code := x.run(t, "--format", "json", "apply", "--quarantine", "--artifacts")
			if err := <-swapped; err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Data artifactQuarantineReport `json:"data"`
			}
			if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Data.Batches) != 1 {
				t.Fatalf("quarantine preview: exit=%d stderr=%s stdout=%s", code, stderr, out)
			}
			batch := doc.Data.Batches[0]
			if !withHerdr && (code != ExitOK || batch.Moved != 1) {
				t.Fatalf("one pass without herdr: exit=%d batch=%+v stderr=%s", code, batch, stderr)
			}
			if withHerdr && (code == ExitOK || batch.Moved != 0 || !strings.Contains(strings.Join(batch.Reasons, "\n"), "live process check after herdr")) {
				t.Fatalf("second pass with herdr: exit=%d batch=%+v stderr=%s", code, batch, stderr)
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

// Review round 3 of #222: a scan whose only roots are a live session folder
// and a directory inside it protects every entry it observes, though the
// transcript beside the folder is outside every root. (The categories go:
// their roots would be inventory roots that hold the transcript.)
func TestHerdrScanInsideALiveSessionFolderStillGuards(t *testing.T) {
	x := newStateStoreFixture(t)
	file := filepath.Join(t.TempDir(), "answer.json")
	herdrScript(t, x, x.sessions, "exec /bin/cat "+file)
	session := x.session(t, "-proj", sessionA, categoryIdleAge)
	writeHerdrAnswer(t, file, herdrAgentList(session+".jsonl"))
	raw, err := os.ReadFile(x.paths(t).PolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	policy, _, _ := strings.Cut(string(raw), "workspace_archive_categories:")
	_, rest, _ := strings.Cut(policy, "protect:")
	x.writePolicy(t, "roots:\n  - path: "+session+"\n    max_depth: 2\n  - path: "+filepath.Join(session, "sub")+"\n    max_depth: 1\nprotect:"+rest)
	x.data(t, "scan")
	x.data(t, "plan", "--no-jev")
	for _, path := range []string{filepath.Join(session, "0.bash.log"), filepath.Join(session, "sub"), filepath.Join(session, "sub", "1.read.log")} {
		var verdict core.Verdict
		field(t, x.data(t, "explain", path), "safety_verdict", &verdict)
		found := false
		for _, protection := range verdict.Protections {
			found = found || protection.Kind == core.ProtectLiveAgentSession
		}
		if !found || verdict.Allows(core.ActionQuarantine) {
			t.Errorf("%s inside a live session not held by live_agent_session: %+v", path, verdict.Protections)
		}
	}
}

// Review of #223: a shallow scan whose root holds the session store (here
// the ".omp" directory, seeing "agent" at depth one) runs herdr and keeps
// that directory: protected while a session is live, unknown when herdr
// fails, so it is never planned for quarantine.
func TestHerdrShallowScanOfAStoreAncestorStillGuards(t *testing.T) {
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
			omp := filepath.Dir(filepath.Dir(x.sessions))
			raw, err := os.ReadFile(x.paths(t).PolicyFile)
			if err != nil {
				t.Fatal(err)
			}
			x.writePolicy(t, strings.Replace(string(raw), "roots:\n", "roots:\n  - path: "+omp+"\n    max_depth: 1\n", 1))
			want := core.ProtectLiveAgentSession
			if answer == herdrNotRunning {
				want = core.ProtectCollectorFailure
			}
			x.data(t, "scan")
			x.data(t, "plan", "--no-jev")
			var verdict core.Verdict
			field(t, x.data(t, "explain", filepath.Join(omp, "agent")), "safety_verdict", &verdict)
			found := false
			for _, protection := range verdict.Protections {
				found = found || protection.Kind == want
			}
			if !found || verdict.Allows(core.ActionQuarantine) {
				t.Errorf("store ancestor %s lacks %s: %+v", filepath.Join(omp, "agent"), want, verdict.Protections)
			}
		})
	}
}

// Review of #226, P1: a directory holding a session store, quarantined
// while no session was live, is held at expiry by its original footprint,
// though its original pathname is gone and no inventory observes it: a
// session herdr now names under it refuses, and herdr failing fails.
func TestHerdrExpiryOfAStoreAncestorChecksItsOriginalFootprint(t *testing.T) {
	for name, live := range map[string]bool{"live session": true, "herdr failing": false} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			root := filepath.Join(f.home, "inventory")
			build := filepath.Join(root, "build")
			sessions := filepath.Join(build, ".omp", "agent", "sessions")
			transcript := filepath.Join(sessions, "-proj", sessionA+".jsonl")
			proc := filepath.Join(f.home, "empty-proc")
			units := filepath.Join(f.home, "systemd")
			for _, dir := range []string{filepath.Join(sessions, "-proj", sessionA), proc, units} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(transcript, []byte(strings.Repeat("x", 5120)), 0o600); err != nil {
				t.Fatal(err)
			}
			answer := filepath.Join(t.TempDir(), "answer.json")
			writeHerdrAnswer(t, answer, herdrAgentList())
			binary := filepath.Join(t.TempDir(), "herdr")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\nexec /bin/cat "+answer+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			f.writePolicy(t, "roots:\n  - path: "+root+"\ncollectors:\n  git: false\n  processes: false\n  services: true\n  proc_root: "+proc+
				"\n  systemd_dirs:\n    - "+units+"\n  cron_paths: []\n  pm2_dumps: []\n  herdr:\n    binary: "+binary+"\n    session_roots: ["+sessions+"]\n"+
				"caches:\n  - name: build\n    path: "+build+"\n    action: quarantine\n    retention: none\nretention:\n  delete_enabled: true\nprevention:\n  min_free_percent: 0\n")
			if _, stderr, code := f.run(t, "scan"); code != ExitOK {
				t.Fatalf("scan: %s", stderr)
			}
			out, stderr, code := f.run(t, "--format", "json", "plan", "--no-jev")
			var doc struct {
				Data struct {
					Plan core.Plan `json:"plan"`
				} `json:"data"`
			}
			if code != ExitOK || json.Unmarshal([]byte(out), &doc) != nil {
				t.Fatalf("plan: %d %s %s", code, stderr, out)
			}
			var chosen core.Action
			for _, candidate := range doc.Data.Plan.Actions {
				if candidate.Path == build {
					chosen = candidate
				}
			}
			if chosen.Kind != core.ActionQuarantine {
				t.Fatalf("build directory not proposed for quarantine while no session is live: %+v", chosen)
			}
			if _, stderr, code := f.run(t, "plan", "--plan", doc.Data.Plan.ID, "--approve", chosen.ID, "--no-jev"); code != ExitOK {
				t.Fatalf("approve: %s", stderr)
			}
			if _, stderr, code := f.run(t, "apply", "--quarantine", "--action", chosen.ID, "--confirm", "--dry-run=false"); code != ExitOK {
				t.Fatalf("quarantine: %s", stderr)
			}
			if _, err := os.Lstat(build); !os.IsNotExist(err) {
				t.Fatalf("build not quarantined: %v", err)
			}
			if live {
				writeHerdrAnswer(t, answer, herdrAgentList(transcript))
			} else {
				writeHerdrAnswer(t, answer, herdrNotRunning)
			}
			out, stderr, code = f.run(t, "--format", "json", "apply", "--expire", "--dry-run=false", "--confirm")
			var expired struct {
				Data cleanupReport `json:"data"`
			}
			if err := json.Unmarshal([]byte(out), &expired); err != nil {
				t.Fatalf("expiry output: %v\n%s\n%s", err, out, stderr)
			}
			got := expired.Data
			switch {
			case code == ExitOK:
				t.Fatalf("expiry of a store ancestor succeeded: %+v", got)
			case live && (len(got.Errors) != 0 || len(got.Refused) != 1 || !strings.Contains(got.Refused[0], "live_agent_session")):
				t.Fatalf("expiry with a live session under the original not refused as live_agent_session: %+v", got)
			case !live && (len(got.Refused) != 0 || len(got.Errors) != 1 || !strings.Contains(got.Errors[0], "herdr")):
				t.Fatalf("expiry under a failing herdr not a failure: %+v", got)
			}
			for _, item := range got.Items {
				if item.State == core.CleanupDeleted {
					t.Fatalf("store ancestor deleted: %+v", item)
				}
			}
		})
	}
}

// Review of #226, P2: a root_scratch candidate holding a session store
// (reached through a symlinked sessions root) under a failing herdr is a
// failure of the category run, not a refusal.
func TestHerdrFailureOnAStoreAncestorCandidateIsAFailure(t *testing.T) {
	x := newCategoryFixture(t)
	candidate := filepath.Join(x.work, "scratch-build")
	store := filepath.Join(candidate, "sessions")
	if err := os.MkdirAll(filepath.Join(store, "-proj", sessionA), 0o700); err != nil {
		t.Fatal(err)
	}
	backdate(t, candidate, categoryIdleAge)
	root := filepath.Join(x.home, ".omp", "agent", "sessions")
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(store, root); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "herdr")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho '"+herdrNotRunning+"'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(x.paths(t).PolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	x.writePolicy(t, strings.Replace(string(raw), "collectors:\n", "collectors:\n  herdr:\n    binary: "+binary+"\n    session_roots: ["+root+"]\n", 1))
	out, stderr, code := x.runAgents(t, "--format", "json", "archive", "--categories", "--dry-run=false", "--confirm")
	if code == ExitOK {
		t.Fatalf("category run under a failing herdr succeeded: %s", out)
	}
	var doc struct {
		Data categoryArchiveReport `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("%v\n%s\n%s", err, out, stderr)
	}
	item := categoryItem(t, doc.Data, candidate)
	if item.Status != categoryFailed || !strings.Contains(strings.Join(item.Reasons, ";"), "herdr") {
		t.Fatalf("store ancestor candidate under a failing herdr not failed: %+v", item)
	}
}
