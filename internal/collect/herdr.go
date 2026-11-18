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

// listHerdrSessions runs "<binary> agent list --json" once, without a
// shell, within timeout and maxHerdrOutput, and maps every OMP session under
// the session roots a live agent resumes, by its canonical transcript path
// ("<root>/<project>/<stem>.jsonl"), to the agents that name it. An error
// means herdr gave no complete answer: it failed, timed out, printed too
// much or printed something that is not its agent list.
func listHerdrSessions(ctx context.Context, cfg *config.HerdrCollector, timeout time.Duration) (map[string]string, error) {
	data, err := runHerdr(ctx, cfg.Binary, timeout)
	if err != nil {
		return nil, err
	}
	agents, err := parseHerdrAgents(data)
	if err != nil {
		return nil, err
	}
	sessions := map[string]string{}
	for _, agent := range agents {
		session := agent.Session
		if session == nil || session.Kind != "path" {
			// An "id" session (Claude) names no file.
			continue
		}
		if !filepath.IsAbs(session.Value) {
			return nil, fmt.Errorf("herdr agent %s names a non-absolute session path %q", agent.label(), session.Value)
		}
		for _, path := range canonicalSession(cfg.SessionRoots, session.Value) {
			sessions[path] = appendDetail(sessions[path], agent.label())
		}
	}
	return sessions, nil
}

// canonicalSession maps a herdr session path onto the session roots:
// cleaned, and with its directory's symlinks resolved, under a root as
// configured or as it resolves. Paths outside every root (another machine's
// sessions) are dropped.
func canonicalSession(roots []string, value string) []string {
	candidates := []string{filepath.Clean(value)}
	if dir, err := filepath.EvalSymlinks(filepath.Dir(candidates[0])); err == nil {
		candidates = append(candidates, filepath.Join(dir, filepath.Base(candidates[0])))
	}
	var out []string
	for _, root := range roots {
		forms := []string{root}
		if real, err := filepath.EvalSymlinks(root); err == nil && real != root {
			forms = append(forms, real)
		}
		for _, form := range forms {
			for _, candidate := range candidates {
				rel, err := filepath.Rel(form, candidate)
				if err != nil || !core.PathWithin(candidate, form) {
					continue
				}
				path := filepath.Join(root, rel)
				if !slices.Contains(out, path) {
					out = append(out, path)
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
func herdrReferences(sessions map[string]string) []Reference {
	transcripts := make([]string, 0, len(sessions))
	for transcript := range sessions {
		transcripts = append(transcripts, transcript)
	}
	sort.Strings(transcripts)
	var refs []Reference
	for _, transcript := range transcripts {
		detail := liveSessionDetail(transcript, sessions[transcript])
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

// herdrAgent is the part of one "herdr agent list" entry the guard reads.
type herdrAgent struct {
	Agent   string `json:"agent"`
	Name    string `json:"name"`
	PaneID  string `json:"pane_id"`
	Session *struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	} `json:"agent_session"`
}

func (a herdrAgent) label() string {
	pane := a.PaneID
	if pane == "" {
		pane = "none"
	}
	return fmt.Sprintf("%q (%s, pane %s)", a.Name, a.Agent, pane)
}

// parseHerdrAgents decodes exactly one agent-list document. An error
// document, a missing agent list or trailing data is no answer.
func parseHerdrAgents(data []byte) ([]herdrAgent, error) {
	var doc struct {
		Result *struct {
			Agents *[]herdrAgent `json:"agents"`
		} `json:"result"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("herdr agent list is not JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("herdr agent list has trailing data after its JSON document")
	}
	if doc.Error != nil {
		return nil, fmt.Errorf("herdr agent list failed: %s: %s", doc.Error.Code, doc.Error.Message)
	}
	if doc.Result == nil || doc.Result.Agents == nil {
		return nil, errors.New("herdr agent list has no result.agents")
	}
	return *doc.Result.Agents, nil
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
	sessions, err := listHerdrSessions(ctx, opts.Herdr, opts.Limits.CommandTimeout)
	if err != nil {
		report.Status, report.Unknowns, report.Detail = core.CollectorFailed, 1, err.Error()
		return nil, report
	}
	report.Visited = len(sessions)
	report.Detail = fmt.Sprintf("live herdr agents resume %d OMP session(s) under %s", len(sessions), strings.Join(opts.Herdr.SessionRoots, ", "))
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
