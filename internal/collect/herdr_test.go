//go:build unix

package collect

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
		"trailing data":    `echo '{"id":"cli:agent:list","result":{"type":"agent_list","agents":[]}} {}'`,
		"no agent list":    `echo '{"id":"cli:agent:list","result":{"type":"agent_list"}}'`,
		"relative session": `echo '{"id":"cli:agent:list","result":{"type":"agent_list","agents":[{"agent":"omp","agent_session":{"kind":"path","value":"-proj/a.jsonl"}}]}}'`,
		// Review of #222: a wrong result type with a null record decoded
		// into a skipped zero agent and reported "ran, no sessions".
		"unexpected result":   `echo '{"result":{"type":"unexpected_result","agents":[null]}}'`,
		"wrong id":            `echo '{"id":"cli:pane:list","result":{"type":"agent_list","agents":[]}}'`,
		"wrong result type":   `echo '{"id":"cli:agent:list","result":{"type":"pane_list","agents":[]}}'`,
		"null agent":          `echo '{"id":"cli:agent:list","result":{"type":"agent_list","agents":[null]}}'`,
		"agent not an object": `echo '{"id":"cli:agent:list","result":{"type":"agent_list","agents":["omp"]}}'`,
		"ill-typed session":   `echo '{"id":"cli:agent:list","result":{"type":"agent_list","agents":[{"agent":"omp","agent_session":{"kind":"path","value":5}}]}}'`,
		"session not object":  `echo '{"id":"cli:agent:list","result":{"type":"agent_list","agents":[{"agent":"omp","agent_session":"x.jsonl"}]}}'`,
		"session no value":    `echo '{"id":"cli:agent:list","result":{"type":"agent_list","agents":[{"agent":"omp","agent_session":{"kind":"path"}}]}}'`,
		"output bound":        `exec /usr/bin/head -c 5000000 /dev/zero`,
		"timeout":             `exec /bin/sleep 30`,
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

// Review of #222: session_roots may name a symlinked alias of the store
// the inventory observes by its real path. Both spellings are one identity:
// herdr runs, the referenced session is protected on the real path whether
// herdr names it by the alias or the real path, and a failing herdr leaves
// the real-path entries unknown.
func TestHerdrAliasedSessionRootIsOneIdentity(t *testing.T) {
	aliased := func(t *testing.T, x herdrFixture) Options {
		alias := filepath.Join(t.TempDir(), "alias")
		mustSymlink(t, filepath.Dir(filepath.Dir(filepath.Dir(x.sessions))), alias)
		opts := x.options(5 * time.Second)
		opts.Herdr.SessionRoots = []string{filepath.Join(alias, ".omp", "agent", "sessions")}
		return opts
	}
	for name, viaAlias := range map[string]bool{"named by real path": false, "named by alias": true} {
		t.Run(name, func(t *testing.T) {
			x := newHerdrFixture(t, "")
			opts := aliased(t, x)
			named := filepath.Join(x.project, herdrStemA+".jsonl")
			if viaAlias {
				named = filepath.Join(opts.Herdr.SessionRoots[0], "-proj", herdrStemA+".jsonl")
			}
			if err := os.WriteFile(x.binary, []byte("#!/bin/sh\n"+answerScript(t, named)+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			result := run(t, opts)
			if report := reportFor(t, result, CollectorHerdr); report.Status != core.CollectorRan || report.Visited != 1 {
				t.Fatalf("herdr report under an aliased root = %+v", report)
			}
			for _, path := range []string{filepath.Join(x.project, herdrStemA), named} {
				if !strings.HasPrefix(path, x.sessions) {
					continue
				}
				if protectionReason(entryFor(t, result, path), core.ProtectLiveAgentSession) == "" {
					t.Errorf("%s not protected under an aliased root", path)
				}
			}
			if entry := entryFor(t, result, filepath.Join(x.project, herdrStemA)); protectionReason(entry, core.ProtectLiveAgentSession) == "" {
				t.Errorf("session folder on the real path not protected: %+v", entry.Protections)
			}
		})
	}
	t.Run("herdr failing", func(t *testing.T) {
		x := newHerdrFixture(t, "exit 1")
		result := run(t, aliased(t, x))
		for _, entry := range result.Entries {
			if protectionReason(entry, core.ProtectCollectorFailure) == "" {
				t.Errorf("%s not unknown under a failing herdr and an aliased root", entry.Path)
			}
		}
	})
}

// Review round 2 of #222: session_roots names the real store while the
// inventory reaches it through a symlinked alias, at the store or above it.
// Identity, not spelling, decides: herdr runs, the live transcript and its
// folder are protected as the alias spells them (whether herdr names the
// session by the real path or the alias), the other session is not, and a
// failing herdr leaves every alias entry unknown.
func TestHerdrInventoryAliasOfTheStoreIsOneIdentity(t *testing.T) {
	// The alias is a symlink to the home holding the store; the inventory
	// root is the store (depth 2) or its project directory (depth 1), as
	// the alias spells them.
	place := func(t *testing.T, x herdrFixture, depth int) (string, []RootSpec) {
		home := filepath.Dir(filepath.Dir(filepath.Dir(x.sessions)))
		alias := filepath.Join(t.TempDir(), "home")
		mustSymlink(t, home, alias)
		project := filepath.Join(alias, ".omp", "agent", "sessions", "-proj")
		root := project
		if depth == 2 {
			root = filepath.Dir(project)
		}
		return project, []RootSpec{{Path: root, MaxDepth: depth}}
	}
	for where, depth := range map[string]int{"root at the store": 2, "root at the project": 1} {
		for named, viaAlias := range map[string]bool{"herdr names the real path": false, "herdr names the alias": true} {
			t.Run(where+"/"+named, func(t *testing.T) {
				x := newHerdrFixture(t, "")
				project, roots := place(t, x, depth)
				value := filepath.Join(x.project, herdrStemA+".jsonl")
				if viaAlias {
					value = filepath.Join(project, herdrStemA+".jsonl")
				}
				if err := os.WriteFile(x.binary, []byte("#!/bin/sh\n"+answerScript(t, value)+"\n"), 0o755); err != nil {
					t.Fatal(err)
				}
				opts := x.options(5 * time.Second)
				opts.Roots = roots
				result := run(t, opts)
				if report := reportFor(t, result, CollectorHerdr); report.Status != core.CollectorRan || report.Visited != 1 {
					t.Fatalf("herdr report for an aliased inventory root = %+v", report)
				}
				for _, path := range []string{filepath.Join(project, herdrStemA), filepath.Join(project, herdrStemA+".jsonl")} {
					if protectionReason(entryFor(t, result, path), core.ProtectLiveAgentSession) == "" {
						t.Errorf("%s not protected through the alias", path)
					}
				}
				for _, path := range []string{filepath.Join(project, herdrStemB), filepath.Join(project, herdrStemB+".jsonl")} {
					if entry := entryFor(t, result, path); len(entry.Protections) != 0 {
						t.Errorf("unreferenced %s protected: %+v", path, entry.Protections)
					}
				}
			})
		}
		t.Run(where+"/herdr failing", func(t *testing.T) {
			x := newHerdrFixture(t, "exit 1")
			_, roots := place(t, x, depth)
			opts := x.options(5 * time.Second)
			opts.Roots = roots
			result := run(t, opts)
			if report := reportFor(t, result, CollectorHerdr); report.Status != core.CollectorFailed || report.Recorded < 4 {
				t.Fatalf("herdr report for an aliased inventory root = %+v", report)
			}
			for _, entry := range result.Entries {
				if protectionReason(entry, core.ProtectCollectorFailure) == "" {
					t.Errorf("%s not unknown under a failing herdr", entry.Path)
				}
			}
		})
	}
}

// Review round 3 of #222: a collection rooted at a live session folder, or
// at a directory inside it, never sees the transcript beside the folder,
// yet every entry it observes is part of the live unit. The same holds for
// the engine's revalidation of one file, which observes only the file's
// parent directory. An unreferenced session's folder stays unprotected.
func TestHerdrProtectsCollectionsInsideALiveSessionFolder(t *testing.T) {
	x := newHerdrFixture(t, "")
	live := filepath.Join(x.project, herdrStemA)
	mustWrite(t, filepath.Join(live, "nested", "child.log"), "child\n")
	mustWrite(t, filepath.Join(x.project, herdrStemB, "nested", "child.log"), "child\n")
	if err := os.WriteFile(x.binary, []byte("#!/bin/sh\n"+answerScript(t, live+".jsonl")+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, root := range map[string]RootSpec{
		"rooted at the session folder":         {Path: live, MaxDepth: 2},
		"rooted at a directory inside it":      {Path: filepath.Join(live, "nested"), MaxDepth: 1},
		"revalidating a file inside a session": {Path: filepath.Join(live, "nested"), MaxDepth: 1},
	} {
		t.Run(name, func(t *testing.T) {
			opts := x.options(5 * time.Second)
			opts.Roots = []RootSpec{root}
			result := run(t, opts)
			if len(result.Entries) == 0 {
				t.Fatal("nothing observed")
			}
			for _, entry := range result.Entries {
				if reason := protectionReason(entry, core.ProtectLiveAgentSession); !strings.Contains(reason, herdrStemA+".jsonl") {
					t.Errorf("%s inside the live session not protected: %+v", entry.Path, entry.Protections)
				}
			}
			// The engine's original-path check (action.originalReferences)
			// matches a Subtree reference that contains the source.
			source := filepath.Join(live, "nested", "child.log")
			held := false
			for _, ref := range result.References {
				held = held || ref.Protection == core.ProtectLiveAgentSession && (core.PathWithin(ref.Path, source) || ref.Subtree && core.PathWithin(source, ref.Path))
			}
			if !held {
				t.Errorf("no live-session reference holds %s: %+v", source, result.References)
			}
		})
	}
	t.Run("an unreferenced session folder", func(t *testing.T) {
		opts := x.options(5 * time.Second)
		opts.Roots = []RootSpec{{Path: filepath.Join(x.project, herdrStemB), MaxDepth: 2}}
		for _, entry := range run(t, opts).Entries {
			if len(entry.Protections) != 0 {
				t.Errorf("%s of an unreferenced session protected: %+v", entry.Path, entry.Protections)
			}
		}
	})
	t.Run("an ancestor reaching the store only through a symlink", func(t *testing.T) {
		// A real directory holding a symlink to the agent directory above
		// the store; the walk never descends a symlink, so the collection
		// reaches the store as a root spelled through it.
		ancestor := t.TempDir()
		mustSymlink(t, filepath.Dir(x.sessions), filepath.Join(ancestor, "agent"))
		opts := x.options(5 * time.Second)
		opts.Roots = []RootSpec{{Path: filepath.Join(ancestor, "agent", "sessions"), MaxDepth: 4}}
		result := run(t, opts)
		through := filepath.Join(ancestor, "agent", "sessions", "-proj", herdrStemA)
		for _, path := range []string{through, through + ".jsonl", filepath.Join(through, "nested", "child.log")} {
			if protectionReason(entryFor(t, result, path), core.ProtectLiveAgentSession) == "" {
				t.Errorf("%s not protected through an ancestor alias", path)
			}
		}
	})
}

// Review of #223: "sessions/alias/../<stem>.jsonl" with alias a symlink to
// "-proj/child" names "-proj/<stem>.jsonl" on the filesystem, but cleaning
// it first names "sessions/<stem>.jsonl". An unclean session path is
// malformed evidence: herdr fails, and every session entry is unknown.
func TestHerdrUncleanSessionPathFailsClosed(t *testing.T) {
	x := newHerdrFixture(t, "")
	mustMkdir(t, filepath.Join(x.project, "child"))
	mustSymlink(t, filepath.Join(x.project, "child"), filepath.Join(x.sessions, "alias"))
	value := x.sessions + "/alias/../" + herdrStemA + ".jsonl"
	if err := os.WriteFile(x.binary, []byte("#!/bin/sh\n"+answerScript(t, value)+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	result := run(t, x.options(5*time.Second))
	if report := reportFor(t, result, CollectorHerdr); report.Status != core.CollectorFailed || !strings.Contains(report.Detail, "unclean") {
		t.Fatalf("herdr report for an unclean session path = %+v", report)
	}
	for _, path := range []string{filepath.Join(x.project, herdrStemA), filepath.Join(x.project, herdrStemA+".jsonl")} {
		if protectionReason(entryFor(t, result, path), core.ProtectCollectorFailure) == "" {
			t.Errorf("%s not unknown after an unclean herdr session path", path)
		}
	}
}

// Review of #237: encoding/json decodes an escaped NUL as is, and an
// invalid UTF-8 byte or an unpaired surrogate to U+FFFD, without an error.
// An agent_session path holding one is malformed evidence: herdr fails,
// naming the agent, and every session entry is unknown.
func TestHerdrLossySessionPathFailsClosed(t *testing.T) {
	for name, inner := range map[string]string{"NUL": `\u0000`, "invalid UTF-8": "\xff", "unpaired surrogate": `\ud800`} {
		t.Run(name, func(t *testing.T) {
			x := newHerdrFixture(t, "")
			writeHerdrScript(t, x, answerScript(t, filepath.Join(x.project, herdrStemA+inner+".jsonl")))
			result := run(t, x.options(5*time.Second))
			report := reportFor(t, result, CollectorHerdr)
			if report.Status != core.CollectorFailed || !strings.Contains(report.Detail, `"keephair" (omp, pane w65:p72)`) || report.Recorded != 4 {
				t.Fatalf("herdr report for a session path holding %s = %+v", name, report)
			}
			for _, entry := range result.Entries {
				if protectionReason(entry, core.ProtectCollectorFailure) == "" {
					t.Errorf("%s not unknown after a lossy herdr session path", entry.Path)
				}
			}
		})
	}
}

// Review of #237: encoding/json keeps the last of duplicate members and
// matches struct fields case-insensitively, so a second or case-variant
// member silently replaced the one herdr meant. Every herdr object (the
// document, its result, an agent, its agent_session) with a member name
// twice, in any spelling, or a case variant of a member the guard reads is
// malformed: herdr fails, naming where, and every session entry is unknown.
func TestHerdrDuplicateOrCaseVariantMembersFailClosed(t *testing.T) {
	const (
		good  = `{"agent":"omp","name":"keephair","pane_id":"w65:p72","agent_session":{"kind":"path","value":"$S"}}`
		label = `"keephair" (omp, pane w65:p72)`
	)
	doc := func(agents string) string {
		return `{"id":"cli:agent:list","result":{"type":"agent_list","agents":[` + agents + `]}}`
	}
	agent := func(members string) string {
		return doc(`{"agent":"omp","name":"keephair","pane_id":"w65:p72",` + members + `}`)
	}
	session := func(object string) string { return agent(`"agent_session":` + object) }
	for name, c := range map[string]struct{ doc, want string }{
		"duplicate value":         {session(`{"kind":"path","value":"$S","value":"$S"}`), label},
		"Value beside value":      {session(`{"kind":"path","value":"$S","Value":"$S"}`), label},
		"escaped duplicate value": {session(`{"kind":"path","value":"$S","v\u0061lue":"$S"}`), label},
		"duplicate kind":          {session(`{"kind":"id","kind":"path","value":"$S"}`), label},
		"KIND":                    {session(`{"KIND":"path","value":"$S"}`), label},
		"two agent_session":       {agent(`"agent_session":{"kind":"path","value":"$S"},"agent_session":null`), "entry 0"},
		"AGENT_SESSION":           {agent(`"AGENT_SESSION":{"kind":"path","value":"$S"}`), "entry 0"},
		"two topic_sessions":      {agent(`"agent_session":{"kind":"path","value":"$S"},"topic_sessions":["$T"],"topic_sessions":[]`), "entry 0"},
		"Agent beside agent":      {doc(`{"agent":"omp","Agent":"claude","agent_session":{"kind":"path","value":"$S"}}`), "entry 0"},
		"PANE_ID":                 {doc(`{"agent":"omp","PANE_ID":"w1:p1","agent_session":{"kind":"path","value":"$S"}}`), "entry 0"},
		"two agents arrays":       {`{"id":"cli:agent:list","result":{"type":"agent_list","agents":[` + good + `],"agents":[]}}`, "agent list"},
		"two ids":                 {`{"id":"cli:pane:list","id":"cli:agent:list","result":{"type":"agent_list","agents":[` + good + `]}}`, "agent list"},
		"RESULT":                  {`{"id":"cli:agent:list","RESULT":{"type":"agent_list","agents":[` + good + `]}}`, "agent list"},
	} {
		t.Run(name, func(t *testing.T) {
			x := newHerdrFixture(t, "")
			answer := filepath.Join(t.TempDir(), "answer.json")
			mustWrite(t, answer, strings.NewReplacer("$S", filepath.Join(x.project, herdrStemA+".jsonl"),
				"$T", filepath.Join(x.project, herdrStemB+".jsonl")).Replace(c.doc))
			writeHerdrScript(t, x, "exec /bin/cat "+answer)
			result := run(t, x.options(5*time.Second))
			report := reportFor(t, result, CollectorHerdr)
			if report.Status != core.CollectorFailed || !strings.Contains(report.Detail, c.want) || report.Recorded != 4 {
				t.Fatalf("herdr report for %s = %+v, want a failure naming %s", name, report, c.want)
			}
			for _, entry := range result.Entries {
				if protectionReason(entry, core.ProtectCollectorFailure) == "" {
					t.Errorf("%s not unknown under %s", entry.Path, name)
				}
			}
		})
	}
}

// Review of #223: moving a real directory that holds a session store moves
// every live session in it. A shallow collection that observes such a
// directory runs herdr, protects it while a session is live, and leaves it
// unknown when herdr fails. That holds for a store reached through a
// symlink too (a sessions root pointing into a build directory), by
// identity; the directory holding only the symlink is not an ancestor.
func TestHerdrProtectsAnObservedAncestorOfAStore(t *testing.T) {
	type setup struct {
		opts     Options
		ancestor string
		other    string
	}
	shapes := map[string]func(t *testing.T, x herdrFixture) setup{
		"directory containing the store": func(t *testing.T, x herdrFixture) setup {
			omp := filepath.Dir(filepath.Dir(x.sessions))
			mustWrite(t, filepath.Join(omp, "notes.txt"), "n\n")
			opts := x.options(5 * time.Second)
			opts.Roots = []RootSpec{{Path: omp, MaxDepth: 1}}
			return setup{opts, filepath.Join(omp, "agent"), filepath.Join(omp, "notes.txt")}
		},
		"build directory the sessions root resolves into": func(t *testing.T, x herdrFixture) setup {
			top := t.TempDir()
			build := filepath.Join(top, "build")
			mustMkdir(t, build)
			if err := os.Rename(x.sessions, filepath.Join(build, "sessions")); err != nil {
				t.Fatal(err)
			}
			mustSymlink(t, filepath.Join(build, "sessions"), x.sessions)
			mustMkdir(t, filepath.Join(top, "unrelated"))
			opts := x.options(5 * time.Second)
			opts.Roots = []RootSpec{{Path: top, MaxDepth: 1}}
			return setup{opts, build, filepath.Join(top, "unrelated")}
		},
	}
	for name, shape := range shapes {
		t.Run(name+"/live session", func(t *testing.T) {
			x := newHerdrFixture(t, "")
			if err := os.WriteFile(x.binary, []byte("#!/bin/sh\n"+answerScript(t, filepath.Join(x.project, herdrStemA+".jsonl"))+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			s := shape(t, x)
			result := run(t, s.opts)
			if report := reportFor(t, result, CollectorHerdr); report.Status != core.CollectorRan {
				t.Fatalf("herdr did not run for a collection observing a store ancestor: %+v", report)
			}
			if reason := protectionReason(entryFor(t, result, s.ancestor), core.ProtectLiveAgentSession); !strings.Contains(reason, herdrStemA+".jsonl") {
				t.Errorf("ancestor %s of a live session not protected: %+v", s.ancestor, entryFor(t, result, s.ancestor).Protections)
			}
			if entry := entryFor(t, result, s.other); len(entry.Protections) != 0 {
				t.Errorf("sibling %s protected: %+v", s.other, entry.Protections)
			}
		})
		t.Run(name+"/herdr failing", func(t *testing.T) {
			x := newHerdrFixture(t, "exit 1")
			s := shape(t, x)
			result := run(t, s.opts)
			if report := reportFor(t, result, CollectorHerdr); report.Status != core.CollectorFailed {
				t.Fatalf("herdr report = %+v", report)
			}
			if protectionReason(entryFor(t, result, s.ancestor), core.ProtectCollectorFailure) == "" {
				t.Errorf("ancestor %s not unknown under a failing herdr", s.ancestor)
			}
			if entry := entryFor(t, result, s.other); len(entry.Protections) != 0 {
				t.Errorf("sibling %s protected under a failing herdr: %+v", s.other, entry.Protections)
			}
		})
	}
}

// Review round 2 of #226: proving a stagehand static prefix holds no
// symlink reads its directories in batches bounded by the remaining entry
// budget; a budget of 1 over a directory of many children stops at once
// instead of reading (and sorting) them all first.
func TestStagehandPrefixWalkReadsWithinItsBudget(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 30000; i++ {
		f, err := os.Create(filepath.Join(dir, fmt.Sprintf("child-%05d", i)))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	s := &stagehandPrefixes{ctx: context.Background(), limits: Limits{DeepSizeMaxEntries: 1, DeepSizeMaxDepth: 4}, seen: map[string]string{}}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got := s.walk(dir)
	runtime.ReadMemStats(&after)
	if !strings.Contains(got, "entry budget") {
		t.Fatalf("walk = %q, want the entry budget exhausted", got)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 256<<10 {
		t.Fatalf("walk with a budget of 1 allocated %d bytes over 30000 children", allocated)
	}
}
