//go:build unix

package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

const (
	herdrStemA = "2026-09-06T14-13-56-147Z_01a07711-9533-70c1-9ac4-8eb12ccc9906"
	herdrStemB = "2026-09-07T15-00-22-554Z_01a07c62-759a-7452-a1c8-f3ebf00ff14f"
)

// herdrFixture is an OMP sessions store with one project holding two
// sessions (folder and transcript each) and a fake herdr whose script body
// a test chooses.
type herdrFixture struct {
	sessions, project, binary string
}

func newHerdrFixture(t *testing.T, script string) herdrFixture {
	t.Helper()
	home := t.TempDir()
	x := herdrFixture{sessions: filepath.Join(home, ".omp", "agent", "sessions")}
	x.project = filepath.Join(x.sessions, "-proj")
	for _, stem := range []string{herdrStemA, herdrStemB} {
		mustWrite(t, filepath.Join(x.project, stem, "0.bash.log"), "ls\n")
		mustWrite(t, filepath.Join(x.project, stem+".jsonl"), `{"type":"session"}`+"\n")
	}
	x.binary = filepath.Join(t.TempDir(), "herdr")
	if err := os.WriteFile(x.binary, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return x
}

func (x herdrFixture) options(timeout time.Duration) Options {
	opts := fixtureOptions(x.project)
	opts.Limits.CommandTimeout = timeout
	opts.Herdr = &config.HerdrCollector{Binary: x.binary, SessionRoots: []string{x.sessions}}
	return opts
}

// answerScript prints an agent list naming value as an OMP agent's session.
func answerScript(t *testing.T, value string) string {
	t.Helper()
	answer := filepath.Join(t.TempDir(), "answer.json")
	mustWrite(t, answer, `{"id":"cli:agent:list","result":{"type":"agent_list","agents":[`+
		`{"agent":"claude","name":"c","pane_id":"","agent_session":{"agent":"claude","kind":"id","source":"herdr:claude","value":"d396"}},`+
		`{"agent":"omp","name":"keephair","pane_id":"w65:p72","agent_session":{"agent":"omp","kind":"path","source":"herdr:omp","value":"`+value+`"}}]}}`)
	return "exec /bin/cat " + answer
}

func protectionReason(entry core.Entry, kind core.ProtectionKind) string {
	for _, p := range entry.Protections {
		if p.Kind == kind && p.Blocking {
			return p.Reason
		}
	}
	return ""
}

// Herdr names only the transcript; the session folder beside it (the unit
// omp_sessions moves) is protected too, and the other session is not. A
// path through a symlinked alias of the root maps onto the root.
func TestHerdrSessionProtectsTranscriptAndItsFolder(t *testing.T) {
	for name, alias := range map[string]bool{"configured path": false, "symlinked alias": true} {
		t.Run(name, func(t *testing.T) {
			x := newHerdrFixture(t, "")
			named := filepath.Join(x.project, herdrStemA+".jsonl")
			if alias {
				link := filepath.Join(t.TempDir(), "sessions")
				mustSymlink(t, x.sessions, link)
				named = filepath.Join(link, "-proj", herdrStemA+".jsonl")
			}
			if err := os.WriteFile(x.binary, []byte("#!/bin/sh\n[ \"$*\" = 'agent list --json' ] || exit 64\n"+answerScript(t, named)+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			result := run(t, x.options(5*time.Second))
			for _, path := range []string{filepath.Join(x.project, herdrStemA), filepath.Join(x.project, herdrStemA+".jsonl")} {
				reason := protectionReason(entryFor(t, result, path), core.ProtectLiveAgentSession)
				if !strings.Contains(reason, `"keephair" (omp, pane w65:p72)`) || !strings.Contains(reason, herdrStemA+".jsonl") {
					t.Errorf("%s: live_agent_session reason = %q", filepath.Base(path), reason)
				}
			}
			for _, path := range []string{filepath.Join(x.project, herdrStemB), filepath.Join(x.project, herdrStemB+".jsonl")} {
				if entry := entryFor(t, result, path); len(entry.Protections) != 0 {
					t.Errorf("unreferenced %s protected: %+v", filepath.Base(path), entry.Protections)
				}
			}
			if report := reportFor(t, result, CollectorHerdr); report.Status != core.CollectorRan || report.Visited != 1 || report.Recorded != 2 {
				t.Errorf("herdr report = %+v", report)
			}
			if err := HerdrGap(result.Reports); err != nil {
				t.Errorf("complete herdr evidence reported as a gap: %v", err)
			}
		})
	}
}

// Herdr configured but giving no complete answer leaves every entry under
// the session roots unknown: a collector failure, never "no live session".
func TestHerdrFailureLeavesEverySessionUnknown(t *testing.T) {
	for name, script := range map[string]string{
		"error document":   `echo '{"id":"cli:agent:list","error":{"code":"server_not_running","message":"no herdr server"}}'; exit 1`,
		"exit status":      `echo boom >&2; exit 3`,
		"not JSON":         `echo 'agents: none'`,
		"trailing data":    `echo '{"id":"x","result":{"agents":[]}} {}'`,
		"no agent list":    `echo '{"id":"x","result":{}}'`,
		"relative session": `echo '{"id":"x","result":{"agents":[{"agent":"omp","agent_session":{"kind":"path","value":"-proj/a.jsonl"}}]}}'`,
		"output bound":     `exec /usr/bin/head -c 5000000 /dev/zero`,
		"timeout":          `exec /bin/sleep 30`,
	} {
		t.Run(name, func(t *testing.T) {
			x := newHerdrFixture(t, script)
			started := time.Now()
			result := run(t, x.options(500*time.Millisecond))
			if elapsed := time.Since(started); elapsed > 10*time.Second {
				t.Fatalf("collection took %s past a 500ms command timeout", elapsed)
			}
			report := reportFor(t, result, CollectorHerdr)
			if report.Status == core.CollectorRan || report.Status == core.CollectorSkipped || report.Recorded != 4 {
				t.Fatalf("herdr report = %+v, want a failure recorded on all 4 session entries", report)
			}
			for _, entry := range result.Entries {
				if protectionReason(entry, core.ProtectCollectorFailure) == "" {
					t.Errorf("%s not unknown under a failing herdr: %+v", entry.Path, entry.Protections)
				}
			}
			if HerdrGap(result.Reports) == nil {
				t.Error("a failing herdr is not an evidence gap")
			}
		})
	}
}

// A collection that does not reach into a session root never runs herdr,
// and without collectors.herdr nothing changes.
func TestHerdrSkippedOutsideSessionRootsAndWhenUnconfigured(t *testing.T) {
	x := newHerdrFixture(t, "exit 1")
	elsewhere := t.TempDir()
	mustMkdir(t, filepath.Join(elsewhere, "work"))
	opts := x.options(5 * time.Second)
	opts.Roots = []RootSpec{{Path: elsewhere, MaxDepth: 1}}
	if report := reportFor(t, run(t, opts), CollectorHerdr); report.Status != core.CollectorSkipped {
		t.Errorf("herdr ran for a collection outside its session roots: %+v", report)
	}
	opts = x.options(5 * time.Second)
	opts.Herdr = nil
	result := run(t, opts)
	if report := reportFor(t, result, CollectorHerdr); report.Status != core.CollectorSkipped {
		t.Errorf("herdr ran while unconfigured: %+v", report)
	}
	for _, entry := range result.Entries {
		if len(entry.Protections) != 0 {
			t.Errorf("%s protected without herdr: %+v", entry.Path, entry.Protections)
		}
	}
}

// Herdr inherits only what it needs to reach its server, never the rest of
// the janitor's environment.
func TestHerdrRunsWithAMinimalEnvironment(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "sk-secret")
	t.Setenv("HERDR_SOCKET_PATH", "/run/herdr.sock")
	seen := filepath.Join(t.TempDir(), "env")
	x := newHerdrFixture(t, "/usr/bin/env > "+seen+"\n"+answerScript(t, "/nowhere/a.jsonl"))
	if report := reportFor(t, run(t, x.options(5*time.Second)), CollectorHerdr); report.Status != core.CollectorRan {
		t.Fatalf("herdr report = %+v", report)
	}
	data, err := os.ReadFile(seen)
	if err != nil {
		t.Fatal(err)
	}
	if env := string(data); strings.Contains(env, "sk-secret") || !strings.Contains(env, "HERDR_SOCKET_PATH=/run/herdr.sock") {
		t.Fatalf("herdr environment:\n%s", env)
	}
}
