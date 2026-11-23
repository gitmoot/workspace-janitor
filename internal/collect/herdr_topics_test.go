//go:build unix

package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

const (
	herdrStemC = "2026-09-08T09-41-03-018Z_01a08a11-1c2d-7e3f-8a9b-0c1d2e3f4a5b"
	herdrStemD = "2026-09-09T11-12-13-140Z_01a08f22-2d3e-7f40-9bac-1d2e3f4a5b6c"
)

// topicScript prints an agent list naming session as an OMP agent's
// agent_session and topics (raw JSON) as its topic_sessions.
func topicScript(t *testing.T, session, topics string) string {
	t.Helper()
	answer := filepath.Join(t.TempDir(), "answer.json")
	mustWrite(t, answer, `{"id":"cli:agent:list","result":{"type":"agent_list","agents":[`+
		`{"agent":"omp","name":"keephair","pane_id":"w65:p72","agent_session":{"agent":"omp","kind":"path","source":"herdr:omp","value":"`+session+`"},`+
		`"topic_sessions":`+topics+`}]}}`)
	return "exec /bin/cat " + answer
}

func writeHerdrScript(t *testing.T, x herdrFixture, script string) {
	t.Helper()
	if err := os.WriteFile(x.binary, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func addHerdrSession(t *testing.T, x herdrFixture, stem string) {
	t.Helper()
	mustWrite(t, filepath.Join(x.project, stem, "0.bash.log"), "ls\n")
	mustWrite(t, filepath.Join(x.project, stem+".jsonl"), `{"type":"session"}`+"\n")
}

func jsonPaths(paths ...string) string {
	quoted := make([]string, len(paths))
	for i, path := range paths {
		quoted[i] = `"` + path + `"`
	}
	return "[" + strings.Join(quoted, ",") + "]"
}

// herdr's topic_sessions lists every topic transcript an agent keeps,
// usually beside its agent_session. Each listed topic is protected like
// the agent_session (transcript and folder, reason naming the agent and
// the topic); an unlisted session in the same directory is not.
func TestHerdrTopicSessionsProtectEveryListedTopic(t *testing.T) {
	x := newHerdrFixture(t, "")
	addHerdrSession(t, x, herdrStemC)
	addHerdrSession(t, x, herdrStemD)
	transcript := func(stem string) string { return filepath.Join(x.project, stem+".jsonl") }
	writeHerdrScript(t, x, topicScript(t, transcript(herdrStemA),
		jsonPaths(transcript(herdrStemA), transcript(herdrStemB), transcript(herdrStemC))))
	result := run(t, x.options(5*time.Second))
	if report := reportFor(t, result, CollectorHerdr); report.Status != core.CollectorRan || report.Visited != 3 || report.Recorded != 6 {
		t.Fatalf("herdr report = %+v", report)
	}
	for _, stem := range []string{herdrStemA, herdrStemB, herdrStemC} {
		for _, path := range []string{filepath.Join(x.project, stem), transcript(stem)} {
			reason := protectionReason(entryFor(t, result, path), core.ProtectLiveAgentSession)
			if !strings.Contains(reason, `"keephair" (omp, pane w65:p72)`) || !strings.Contains(reason, stem+".jsonl") {
				t.Errorf("%s: live_agent_session reason = %q", filepath.Base(path), reason)
			}
			if topic := strings.Contains(reason, "topic"); topic != (stem != herdrStemA) {
				t.Errorf("%s: reason %q names topic = %t", filepath.Base(path), reason, topic)
			}
		}
	}
	for _, path := range []string{filepath.Join(x.project, herdrStemD), transcript(herdrStemD)} {
		if entry := entryFor(t, result, path); len(entry.Protections) != 0 {
			t.Errorf("unlisted %s protected: %+v", filepath.Base(path), entry.Protections)
		}
	}
	// Topics outside every session root are ignored, as agent_session is.
	writeHerdrScript(t, x, topicScript(t, transcript(herdrStemA), jsonPaths("/elsewhere/-proj/"+herdrStemB+".jsonl")))
	result = run(t, x.options(5*time.Second))
	if report := reportFor(t, result, CollectorHerdr); report.Status != core.CollectorRan || report.Visited != 1 {
		t.Fatalf("herdr report with a foreign topic = %+v", report)
	}
}

// herdr 0.9.5 emits topic_sessions entries as objects; their string
// "path" is validated like the bare-string form and other keys are
// ignored. A topic in the session's companion folder is protected by
// name (and by the folder already protecting it).
func TestHerdrTopicSessionObjectsProtectTheirPath(t *testing.T) {
	x := newHerdrFixture(t, "")
	topic := filepath.Join(x.project, herdrStemA, "Topicscheck.jsonl")
	mustWrite(t, topic, `{"type":"session"}`+"\n")
	session := filepath.Join(x.project, herdrStemA+".jsonl")
	writeHerdrScript(t, x, topicScript(t, session,
		`[{"created_unix_ms":1795328166859,"path":"`+topic+`","title":"Topics check","topic_id":"Topicscheck","future":{"x":[1]}},"`+session+`"]`))
	result := run(t, x.options(5*time.Second))
	if report := reportFor(t, result, CollectorHerdr); report.Status != core.CollectorRan {
		t.Fatalf("herdr report = %+v", report)
	}
	var reason string
	for _, ref := range result.References {
		if ref.Path == topic && ref.Protection == core.ProtectLiveAgentSession {
			reason = ref.Detail
		}
	}
	if !strings.Contains(reason, "Topicscheck.jsonl") || !strings.Contains(reason, `"keephair" (omp, pane w65:p72) keeps topic`) {
		t.Errorf("topic live_agent_session reference = %q; references %+v", reason, result.References)
	}
	if reason := protectionReason(entryFor(t, result, filepath.Join(x.project, herdrStemA)), core.ProtectLiveAgentSession); reason == "" {
		t.Error("session folder not protected")
	}
}

// A malformed topic_sessions is no answer: herdr fails and every session
// entry is unknown. Absent and null mean no topics.
func TestHerdrMalformedTopicSessionsFailClosed(t *testing.T) {
	tooMany := make([]string, 1001) // past the 1000-per-agent cap
	for i := range tooMany {
		tooMany[i] = "/s/-proj/t.jsonl"
	}
	for name, topics := range map[string]string{
		"not an array":          `"/s/-proj/t.jsonl"`,
		"object":                `{"a":"/s/-proj/t.jsonl"}`,
		"non-string":            `[5]`,
		"null element":          `[null]`,
		"empty string":          `[""]`,
		"relative":              `["-proj/t.jsonl"]`,
		"unclean":               `["/s/alias/../t.jsonl"]`,
		"trailing /":            `["/s/-proj/t.jsonl/"]`,
		"wrong suffix":          `["/s/-proj/t.json"]`,
		"no suffix":             `["/s/-proj/t"]`,
		"past the cap":          jsonPaths(tooMany...),
		"ill-formed el":         `[{"value":"/s/-proj/t.jsonl"}]`,
		"object no path":        `[{"topic_id":"T","title":"T"}]`,
		"object path number":    `[{"path":5}]`,
		"object path null":      `[{"path":null}]`,
		"object path relative":  `[{"path":"-proj/t.jsonl"}]`,
		"object path unclean":   `[{"path":"/s/alias/../t.jsonl"}]`,
		"object path no suffix": `[{"path":"/s/-proj/t"}]`,
		"nested array":          `[["/s/-proj/t.jsonl"]]`,
	} {
		t.Run(name, func(t *testing.T) {
			x := newHerdrFixture(t, "")
			writeHerdrScript(t, x, topicScript(t, filepath.Join(x.project, herdrStemA+".jsonl"), topics))
			result := run(t, x.options(5*time.Second))
			report := reportFor(t, result, CollectorHerdr)
			if report.Status != core.CollectorFailed || !strings.Contains(report.Detail, "topic") || report.Recorded != 4 {
				t.Fatalf("herdr report for topic_sessions %s = %+v", name, report)
			}
			for _, entry := range result.Entries {
				if protectionReason(entry, core.ProtectCollectorFailure) == "" {
					t.Errorf("%s not unknown under malformed topic_sessions", entry.Path)
				}
			}
		})
	}
	for name, topics := range map[string]string{"null": `null`, "empty": `[]`} {
		t.Run(name, func(t *testing.T) {
			x := newHerdrFixture(t, "")
			writeHerdrScript(t, x, topicScript(t, filepath.Join(x.project, herdrStemA+".jsonl"), topics))
			result := run(t, x.options(5*time.Second))
			if report := reportFor(t, result, CollectorHerdr); report.Status != core.CollectorRan || report.Visited != 1 {
				t.Fatalf("herdr report for topic_sessions %s = %+v", name, report)
			}
		})
	}
}

// A topic named through a symlinked alias of the session root is the same
// identity as on the real path, exactly as an agent_session is.
func TestHerdrTopicThroughAliasedRootIsProtected(t *testing.T) {
	for name, viaRoot := range map[string]bool{"aliased session root": true, "alias of the sessions dir": false} {
		t.Run(name, func(t *testing.T) {
			x := newHerdrFixture(t, "")
			opts := x.options(5 * time.Second)
			var topic string
			if viaRoot {
				alias := filepath.Join(t.TempDir(), "alias")
				mustSymlink(t, filepath.Dir(filepath.Dir(filepath.Dir(x.sessions))), alias)
				opts.Herdr.SessionRoots = []string{filepath.Join(alias, ".omp", "agent", "sessions")}
				topic = filepath.Join(opts.Herdr.SessionRoots[0], "-proj", herdrStemB+".jsonl")
			} else {
				link := filepath.Join(t.TempDir(), "sessions")
				mustSymlink(t, x.sessions, link)
				topic = filepath.Join(link, "-proj", herdrStemB+".jsonl")
			}
			writeHerdrScript(t, x, topicScript(t, filepath.Join(x.project, herdrStemA+".jsonl"), jsonPaths(topic)))
			result := run(t, opts)
			if report := reportFor(t, result, CollectorHerdr); report.Status != core.CollectorRan || report.Visited != 2 {
				t.Fatalf("herdr report = %+v", report)
			}
			for _, path := range []string{filepath.Join(x.project, herdrStemB), filepath.Join(x.project, herdrStemB+".jsonl")} {
				if reason := protectionReason(entryFor(t, result, path), core.ProtectLiveAgentSession); !strings.Contains(reason, "topic") {
					t.Errorf("%s through an alias: live_agent_session reason = %q", filepath.Base(path), reason)
				}
			}
		})
	}
}
