package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

// maxHerdrOutput bounds what "herdr agent list" may print. A live host
// with 76 agents answers in about 80 KiB; anything past the bound is not
// read, and the answer is unknown.
const maxHerdrOutput = 4 << 20

// herdrSessionLog is the transcript suffix of an OMP session.
const herdrSessionLog = ".jsonl"

// herdrEnv are the only variables herdr inherits: what it needs to find its
// server socket. Nothing else of the janitor's environment (API keys among
// it) reaches the command.
var herdrEnv = []string{"HOME", "PATH", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "HERDR_SOCKET_PATH"}

// HerdrSessions is one complete herdr answer: every OMP session under the
// session roots that a live agent resumes, by its transcript path
// ("<root>/<project>/<stem>.jsonl") under every spelling of its root, with
// the agents that name it.
type HerdrSessions struct {
	// At is when herdr answered.
	At       time.Time
	sessions map[string]string
	// distinct holds each live session once, under its configured root.
	distinct map[string]bool
}

// ListHerdrSessions runs "<binary> agent list --json" once, without a
// shell, within timeout and maxHerdrOutput. An error means herdr gave no
// complete answer: it failed, timed out, printed too much or printed
// something that is not a well-formed agent list.
func ListHerdrSessions(ctx context.Context, cfg *config.HerdrCollector, timeout time.Duration) (*HerdrSessions, error) {
	data, err := runHerdr(ctx, cfg.Binary, timeout)
	if err != nil {
		return nil, err
	}
	agents, err := parseHerdrAgents(data)
	if err != nil {
		return nil, err
	}
	out := &HerdrSessions{At: nowFunc(), sessions: map[string]string{}, distinct: map[string]bool{}}
	forms := cfg.RootForms()
	for _, agent := range agents {
		session := agent.session
		if session == nil || session.Kind != "path" {
			// An "id" session (Claude) names no file.
			continue
		}
		if !filepath.IsAbs(session.Value) {
			return nil, fmt.Errorf("herdr agent %s names a non-absolute session path %q", agent.label(), session.Value)
		}
		paths := canonicalSession(forms, session.Value)
		for _, path := range paths {
			out.sessions[path] = appendDetail(out.sessions[path], agent.label())
		}
		if len(paths) != 0 {
			out.distinct[paths[0]] = true
		}
	}
	return out, nil
}

// Len is the number of distinct live sessions.
func (h *HerdrSessions) Len() int { return len(h.distinct) }

// Unit is why a live agent keeps the OMP session unit at path (its session
// folder "<stem>" or its transcript "<stem>.jsonl"), or "" when none does.
func (h *HerdrSessions) Unit(path string) string {
	transcript := path
	if !strings.HasSuffix(transcript, herdrSessionLog) {
		transcript += herdrSessionLog
	}
	if agents, ok := h.sessions[transcript]; ok {
		return liveSessionDetail(transcript, agents)
	}
	return ""
}

// canonicalSession maps a herdr session path onto the session roots: the
// path cleaned, and with its directory's symlinks resolved, is matched
// against every spelling of each root, and the session is named under every
// spelling of the root it matched, so an entry observed through any of them
// meets its reference. Paths outside every root (another machine's
// sessions) are dropped.
func canonicalSession(roots [][]string, value string) []string {
	candidates := []string{filepath.Clean(value)}
	if dir, err := filepath.EvalSymlinks(filepath.Dir(candidates[0])); err == nil {
		candidates = append(candidates, filepath.Join(dir, filepath.Base(candidates[0])))
	}
	var out []string
	for _, forms := range roots {
		for _, form := range forms {
			for _, candidate := range candidates {
				if !core.PathWithin(candidate, form) {
					continue
				}
				rel, err := filepath.Rel(form, candidate)
				if err != nil {
					continue
				}
				for _, spelling := range forms {
					if path := filepath.Join(spelling, rel); !slices.Contains(out, path) {
						out = append(out, path)
					}
				}
			}
		}
	}
	return out
}

// herdrReferences are the protections of every live session unit: its
// transcript and its session folder with everything in it. They bind
// collected entries only; omp_session_artifacts, which moves old single
// files out of live seats by an earlier owner decision (2026-11-09), selects
// and moves files under its own guards and never consults them.
func herdrReferences(sessions *HerdrSessions) []Reference {
	transcripts := make([]string, 0, len(sessions.sessions))
	for transcript := range sessions.sessions {
		transcripts = append(transcripts, transcript)
	}
	sort.Strings(transcripts)
	var refs []Reference
	for _, transcript := range transcripts {
		detail := liveSessionDetail(transcript, sessions.sessions[transcript])
		refs = append(refs, Reference{Path: transcript, Source: core.SourceJob, Protection: core.ProtectLiveAgentSession,
			Signal: "herdr_agent_session", Detail: detail})
		if stem, ok := strings.CutSuffix(transcript, herdrSessionLog); ok {
			refs = append(refs, Reference{Path: stem, Source: core.SourceJob, Protection: core.ProtectLiveAgentSession,
				Signal: "herdr_agent_session", Detail: detail, Subtree: true})
		}
	}
	return refs
}

func liveSessionDetail(transcript string, agents string) string {
	return fmt.Sprintf("live herdr agent %s resumes OMP session %s", agents, filepath.Base(transcript))
}

// herdrAgentListID and herdrAgentListType identify the one document
// "herdr agent list --json" answers with.
const (
	herdrAgentListID   = "cli:agent:list"
	herdrAgentListType = "agent_list"
)

// herdrSession is a well-formed agent_session: a kind and a value.
type herdrSession struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// herdrAgent is the part of one "herdr agent list" entry the guard reads.
type herdrAgent struct {
	Agent   string          `json:"agent"`
	Name    string          `json:"name"`
	PaneID  string          `json:"pane_id"`
	Session json.RawMessage `json:"agent_session"`
	session *herdrSession
}

func (a herdrAgent) label() string {
	pane := a.PaneID
	if pane == "" {
		pane = "none"
	}
	return fmt.Sprintf("%q (%s, pane %s)", a.Name, a.Agent, pane)
}

// isObject reports whether raw is a JSON object (not null, an array or a
// scalar).
func isObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) != 0 && trimmed[0] == '{'
}

// parseHerdrAgents decodes exactly one agent-list document: id
// cli:agent:list, result.type agent_list, result.agents an array of agent
// objects, each with an agent name and, when it has a session, an
// agent_session object with a kind and a value. An error document, any
// other id or result type, a null or ill-typed record, a malformed session,
// or trailing data is no answer.
func parseHerdrAgents(data []byte) ([]herdrAgent, error) {
	var doc struct {
		ID     string `json:"id"`
		Result *struct {
			Type   string             `json:"type"`
			Agents *[]json.RawMessage `json:"agents"`
		} `json:"result"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("herdr agent list is not a well-formed JSON document: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("herdr agent list has trailing data after its JSON document")
	}
	if doc.Error != nil {
		return nil, fmt.Errorf("herdr agent list failed: %s: %s", doc.Error.Code, doc.Error.Message)
	}
	switch {
	case doc.ID != herdrAgentListID:
		return nil, fmt.Errorf("herdr answered %q, not %s", doc.ID, herdrAgentListID)
	case doc.Result == nil || doc.Result.Agents == nil:
		return nil, errors.New("herdr agent list has no result.agents")
	case doc.Result.Type != herdrAgentListType:
		return nil, fmt.Errorf("herdr agent list result type is %q, not %s", doc.Result.Type, herdrAgentListType)
	}
	agents := make([]herdrAgent, 0, len(*doc.Result.Agents))
	for i, raw := range *doc.Result.Agents {
		var agent herdrAgent
		if !isObject(raw) {
			return nil, fmt.Errorf("herdr agent list entry %d is not an agent object: %s", i, bytes.TrimSpace(raw))
		}
		if err := json.Unmarshal(raw, &agent); err != nil {
			return nil, fmt.Errorf("herdr agent list entry %d is malformed: %w", i, err)
		}
		if agent.Agent == "" {
			return nil, fmt.Errorf("herdr agent list entry %d names no agent", i)
		}
		// An absent or null agent_session is an agent with no session.
		if trimmed := bytes.TrimSpace(agent.Session); len(trimmed) != 0 && !bytes.Equal(trimmed, []byte("null")) {
			var session herdrSession
			if !isObject(trimmed) {
				return nil, fmt.Errorf("herdr agent %s has a malformed agent_session: %s", agent.label(), trimmed)
			}
			if err := json.Unmarshal(trimmed, &session); err != nil {
				return nil, fmt.Errorf("herdr agent %s has a malformed agent_session: %w", agent.label(), err)
			}
			if session.Kind == "" || session.Value == "" {
				return nil, fmt.Errorf("herdr agent %s has an agent_session without kind or value", agent.label())
			}
			agent.session = &session
		}
		agents = append(agents, agent)
	}
	return agents, nil
}

// runHerdr runs the agent list under timeout, in its own process group, with
// stdout bounded by maxHerdrOutput.
func runHerdr(ctx context.Context, binary string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "agent", "list", "--json")
	cmd.Dir = "/"
	cmd.Env = []string{}
	for _, name := range herdrEnv {
		if value, ok := os.LookupEnv(name); ok {
			cmd.Env = append(cmd.Env, name+"="+value)
		}
	}
	var stdout, stderr limitedGitOutput
	stdout.limit, stderr.limit = maxHerdrOutput, 64<<10
	stdout.cancel, stderr.cancel = cancel, cancel
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	configureProcessGroup(cmd)
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	switch {
	case stdout.exceeded:
		return nil, fmt.Errorf("herdr agent list printed more than %d bytes", maxHerdrOutput)
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return nil, fmt.Errorf("herdr agent list timed out after %s", timeout)
	case err != nil:
		// herdr reports its own errors as a JSON document on stdout.
		if _, perr := parseHerdrAgents(stdout.buffer.Bytes()); perr != nil && stdout.buffer.Len() != 0 {
			return nil, fmt.Errorf("%s: %w", binary, perr)
		}
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return nil, fmt.Errorf("herdr agent list failed: %s", detail)
	}
	return stdout.buffer.Bytes(), nil
}

// gatherHerdrReferences runs herdr once for a collection whose roots or
// entries lie under a session root; otherwise it is skipped.
func gatherHerdrReferences(ctx context.Context, opts *Options, needed bool) ([]Reference, core.CollectorReport) {
	report := core.CollectorReport{Name: CollectorHerdr, Status: core.CollectorRan}
	switch {
	case opts.Herdr == nil:
		report.Status, report.Detail = core.CollectorSkipped, "herdr is not configured"
		return nil, report
	case !needed:
		report.Status, report.Detail = core.CollectorSkipped, "no observed path lies in a herdr session root"
		return nil, report
	}
	sessions, err := ListHerdrSessions(ctx, opts.Herdr, opts.Limits.CommandTimeout)
	if err != nil {
		report.Status, report.Unknowns, report.Detail = core.CollectorFailed, 1, err.Error()
		return nil, report
	}
	report.Visited = sessions.Len()
	report.Detail = fmt.Sprintf("live herdr agents resume %d OMP session(s) under %s", sessions.Len(), strings.Join(opts.Herdr.SessionRoots, ", "))
	return herdrReferences(sessions), report
}

// herdrNeeded reports whether a collection reaches into a session root:
// through one of its roots (an engine recollection of a session's project
// directory, whose session may be absent), or an observed entry. A
// collection that only passes above one (a scan of /root) does not depend
// on herdr, and a herdr failure must not hold it.
func herdrNeeded(opts *Options, entries []core.Entry) bool {
	if opts.Herdr == nil {
		return false
	}
	return slices.ContainsFunc(opts.Roots, func(root RootSpec) bool { return opts.Herdr.Covers(root.Path) }) ||
		slices.ContainsFunc(entries, func(entry core.Entry) bool { return opts.Herdr.Covers(entry.Path) })
}

// attachHerdrUnknowns fails closed: when herdr was needed but did not
// answer, every entry in a session root is unknown.
func attachHerdrUnknowns(entries []core.Entry, opts *Options, report *core.CollectorReport, now time.Time) {
	if report.Status == core.CollectorRan || report.Status == core.CollectorSkipped {
		return
	}
	for i := range entries {
		if opts.Herdr.Covers(entries[i].Path) {
			addUnknown(&entries[i], core.SourceJob, core.ProtectCollectorFailure, CollectorHerdr,
				"herdr agent sessions are unknown: "+report.Detail, now)
			report.Recorded++
		}
	}
}
