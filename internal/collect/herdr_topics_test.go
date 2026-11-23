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
// ignored. Review of #237: the resumed session, the object topic and the
// string topic are three distinct sessions, so each topic is held by its
// own protection, not by the resumed session's.
func TestHerdrTopicSessionObjectsProtectTheirPath(t *testing.T) {
	x := newHerdrFixture(t, "")
	addHerdrSession(t, x, herdrStemC)
	transcript := func(stem string) string { return filepath.Join(x.project, stem+".jsonl") }
	writeHerdrScript(t, x, topicScript(t, transcript(herdrStemA),
		`[{"created_unix_ms":1795328166859,"path":"`+transcript(herdrStemB)+`","title":"Topics check","topic_id":"Topicscheck","future":{"x":[1]}},"`+transcript(herdrStemC)+`"]`))
	result := run(t, x.options(5*time.Second))
	if report := reportFor(t, result, CollectorHerdr); report.Status != core.CollectorRan || report.Visited != 3 {
		t.Fatalf("herdr report = %+v", report)
	}
	for _, stem := range []string{herdrStemB, herdrStemC} {
		for _, path := range []string{filepath.Join(x.project, stem), transcript(stem)} {
			reason := protectionReason(entryFor(t, result, path), core.ProtectLiveAgentSession)
			if !strings.Contains(reason, `"keephair" (omp, pane w65:p72) keeps topic`) || !strings.Contains(reason, stem+".jsonl") {
				t.Errorf("%s: blocking live_agent_session reason = %q", filepath.Base(path), reason)
			}
		}
	}
}

// A malformed topic_sessions is no answer: herdr fails, naming the agent,
// and every session entry is unknown. Absent and null mean no topics.
// Review of #237: an object with a second "path" member (in any spelling,
// or after a null one) is malformed, and so is a path holding a NUL or a
// character encoding/json decoded lossily to U+FFFD.
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
		"object dup path":       `[{"path":"/s/-proj/a.jsonl","path":"/s/-proj/b.jsonl"}]`,
		"object escaped dup":    `[{"path":"/s/-proj/a.jsonl","p\u0061th":"/s/-proj/b.jsonl"}]`,
		"object null then path": `[{"path":null,"path":"/s/-proj/t.jsonl"}]`,
		"NUL":                   `["/s/-proj/t\u0000.jsonl"]`,
		"object path NUL":       `[{"path":"/s/-proj/t\u0000.jsonl"}]`,
		"invalid UTF-8":         "[\"/s/-proj/t\xff.jsonl\"]",
		"object path bad UTF-8": "[{\"path\":\"/s/-proj/t\xff.jsonl\"}]",
		"lone surrogate":        `["/s/-proj/t\ud800.jsonl"]`,
		"object lone surrogate": `[{"path":"/s/-proj/t\ud800.jsonl"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			x := newHerdrFixture(t, "")
			writeHerdrScript(t, x, topicScript(t, filepath.Join(x.project, herdrStemA+".jsonl"), topics))
			result := run(t, x.options(5*time.Second))
			report := reportFor(t, result, CollectorHerdr)
			if report.Status != core.CollectorFailed || !strings.Contains(report.Detail, "topic") ||
				!strings.Contains(report.Detail, `"keephair" (omp, pane w65:p72)`) || report.Recorded != 4 {
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
