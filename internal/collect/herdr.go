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
	"sort"
	"strings"
	"time"
	"unicode/utf8"

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

// HerdrSessions is one complete herdr answer: every OMP session in a
// session store that a live agent resumes (its agent_session) or keeps as
// a topic (its topic_sessions), by its resolved transcript path
// ("<store>/<project>/<stem>.jsonl", config.RealParent), with the agents
// that name it and how.
type HerdrSessions struct {
	sessions map[string]string
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
	out := &HerdrSessions{sessions: map[string]string{}}
	for _, agent := range agents {
		var resumed string
		if session := agent.session; session != nil && session.Kind == "path" {
			// An "id" session (Claude) names no file.
			if lossyHerdrPath(session.Value) {
				return nil, fmt.Errorf("herdr agent %s names a session path %q holding a NUL or an undecodable character", agent.label(), session.Value)
			}
			if !filepath.IsAbs(session.Value) {
				return nil, fmt.Errorf("herdr agent %s names a non-absolute session path %q", agent.label(), session.Value)
			}
			// Cleaning "dir/link/../x" lexically names another file than the
			// filesystem resolves; an unclean path is malformed evidence.
			if session.Value != filepath.Clean(session.Value) {
				return nil, fmt.Errorf("herdr agent %s names an unclean session path %q", agent.label(), session.Value)
			}
			resumed = session.Value
			if path, ok := storeSession(cfg, session.Value); ok {
				out.sessions[path] = appendDetail(out.sessions[path], agent.label()+" resumes")
			}
		}
		// Topic paths were validated by parseHerdrTopics.
		for _, topic := range agent.topics {
			if topic == resumed {
				continue
			}
			if path, ok := storeSession(cfg, topic); ok {
				out.sessions[path] = appendDetail(out.sessions[path], agent.label()+" keeps topic")
			}
		}
	}
	return out, nil
}

// storeSession resolves a herdr session path to its identity in a session
// store: its directory's symlinks resolved, or, spelled under a configured
// root whose directory is absent, mapped onto that root's store. Paths in
// no store (another machine's sessions) are dropped.
func storeSession(cfg *config.HerdrCollector, value string) (string, bool) {
	if real := config.RealParent(value); cfg.CoversReal(real) {
		return real, true
	}
	value = filepath.Clean(value)
	for i, root := range cfg.SessionRoots {
		if rel, err := filepath.Rel(root, value); err == nil && core.PathWithin(value, root) {
			return filepath.Join(cfg.Stores()[i], rel), true
		}
	}
	return "", false
}

// Len is the number of distinct live sessions.
func (h *HerdrSessions) Len() int { return len(h.sessions) }

// Holds is why a live agent keeps what moving path would move (path in any
// spelling, resolved, and need not exist): a live transcript at or inside
// it (a session unit, or a directory holding a store), or a live session
// folder holding it. It is "" when no live session lies there.
func (h *HerdrSessions) Holds(path string) string {
	real := config.RealParent(path)
	transcripts := make([]string, 0, len(h.sessions))
	for transcript := range h.sessions {
		transcripts = append(transcripts, transcript)
	}
	sort.Strings(transcripts)
	for _, transcript := range transcripts {
		stem := strings.TrimSuffix(transcript, herdrSessionLog)
		if core.PathWithin(transcript, real) || stem != transcript && core.PathWithin(real, stem) {
			return liveSessionDetail(transcript, h.sessions[transcript])
		}
	}
	return ""
}

// herdrView is how one collection reaches the session stores: each
// directory it observes through (its roots and the directories holding its
// entries), by its spelling, resolved; the observed entries moving which
// could move a session (config.HerdrCollector.Reaches: in a store, or a
// real directory holding one); and whether any root or entry does. It is
// computed once, before herdr runs.
type herdrView struct {
	dirs    map[string]string
	reached map[string]bool
	needed  bool
}

func newHerdrView(opts *Options, entries []core.Entry) herdrView {
	view := herdrView{dirs: map[string]string{}, reached: map[string]bool{}}
	if opts.Herdr == nil {
		return view
	}
	resolve := func(dir string) string {
		real, ok := view.dirs[dir]
		if !ok {
			real = config.RealPath(dir)
			view.dirs[dir] = real
		}
		return real
	}
	for _, root := range opts.Roots {
		view.needed = opts.Herdr.ReachesReal(resolve(root.Path), false) || view.needed
	}
	for _, entry := range entries {
		real := filepath.Join(resolve(filepath.Dir(entry.Path)), filepath.Base(entry.Path))
		// A symlink entry moves only itself; a real directory moves the
		// stores inside it.
		if opts.Herdr.ReachesReal(real, entry.Kind == core.EntryKindDirectory) {
			view.needed, view.reached[entry.Path] = true, true
		}
	}
	return view
}

// herdrReferences are the protections of every live session unit: its
// transcript and its session folder with everything in it, spelled through
// each directory the collection observes that holds them, and, for an
// observed directory that is the session folder or lies inside it, that
// whole directory. Entries and the engine's checks of an original path
// meet them in whatever spelling they use. They bind collected entries
// only; omp_session_artifacts, which moves old single files out of live
// seats by an earlier owner decision (2026-11-09), selects and moves files
// under its own guards and never consults them.
func herdrReferences(sessions *HerdrSessions, view herdrView) []Reference {
	transcripts := make([]string, 0, len(sessions.sessions))
	for transcript := range sessions.sessions {
		transcripts = append(transcripts, transcript)
	}
	sort.Strings(transcripts)
	spellings := make([]string, 0, len(view.dirs))
	for dir := range view.dirs {
		spellings = append(spellings, dir)
	}
	sort.Strings(spellings)
	seen := map[string]bool{}
	var refs []Reference
	for _, transcript := range transcripts {
		detail := liveSessionDetail(transcript, sessions.sessions[transcript])
		stem, _ := strings.CutSuffix(transcript, herdrSessionLog)
		for _, dir := range spellings {
			real := view.dirs[dir]
			switch {
			case core.PathWithin(transcript, real):
				// The directory holds the unit: reference the transcript and
				// the session folder as it spells them.
				rel, err := filepath.Rel(real, transcript)
				if err != nil {
					continue
				}
				path := filepath.Join(dir, rel)
				if seen[path] {
					continue
				}
				seen[path] = true
				refs = append(refs, Reference{Path: path, Source: core.SourceJob, Protection: core.ProtectLiveAgentSession,
					Signal: "herdr_agent_session", Detail: detail})
				if stem != transcript {
					refs = append(refs, Reference{Path: strings.TrimSuffix(path, herdrSessionLog), Source: core.SourceJob,
						Protection: core.ProtectLiveAgentSession, Signal: "herdr_agent_session", Detail: detail, Subtree: true})
				}
			case stem != transcript && core.PathWithin(real, stem):
				// The directory is the session folder or lies inside it (a
				// scan rooted there, or a revalidation of a file in it):
				// its transcript is a sibling outside it, so the folder's
				// protection is projected onto the directory itself.
				if seen[dir] {
					continue
				}
				seen[dir] = true
				refs = append(refs, Reference{Path: dir, Source: core.SourceJob, Protection: core.ProtectLiveAgentSession,
					Signal: "herdr_agent_session", Detail: detail, Subtree: true})
			}
		}
	}
	return refs
}

// liveSessionDetail names the agents holding transcript; agents are their
// clauses ("<label> resumes", "<label> keeps topic").
func liveSessionDetail(transcript string, agents string) string {
	return fmt.Sprintf("live herdr agent %s OMP session %s", agents, filepath.Base(transcript))
}

// herdrAgentListID and herdrAgentListType identify the one document
// "herdr agent list --json" answers with.
const (
	herdrAgentListID   = "cli:agent:list"
	herdrAgentListType = "agent_list"
)

// herdrSession is a well-formed agent_session: a kind and a value.
type herdrSession struct {
	Kind  string
	Value string
}

// herdrAgent is the part of one "herdr agent list" entry the guard reads.
type herdrAgent struct {
	Agent   string
	Name    string
	PaneID  string
	Session json.RawMessage
	Topics  json.RawMessage
	session *herdrSession
	topics  []string
}

// maxHerdrTopics bounds the topic sessions one agent may list; more is
// malformed evidence.
const maxHerdrTopics = 1000

// parseHerdrTopics decodes an agent's topic_sessions: absent or null is
// none; otherwise an array of at most maxHerdrTopics entries, each an
// absolute, clean ".jsonl" path, decoded losslessly (lossyHerdrPath), or
// an object (read with herdrMembers) whose "path" member is one (herdr
// 0.9.5 emits {path, topic_id, title, created_unix_ms}; other keys are
// ignored).
func parseHerdrTopics(agent herdrAgent) ([]string, error) {
	trimmed := bytes.TrimSpace(agent.Topics)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	if trimmed[0] != '[' {
		return nil, fmt.Errorf("herdr agent %s has a malformed topic_sessions: %s", agent.label(), trimmed)
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(trimmed, &raws); err != nil {
		return nil, fmt.Errorf("herdr agent %s has a malformed topic_sessions: %w", agent.label(), err)
	}
	if len(raws) > maxHerdrTopics {
		return nil, fmt.Errorf("herdr agent %s lists %d topic sessions, more than %d", agent.label(), len(raws), maxHerdrTopics)
	}
	topics := make([]string, 0, len(raws))
	for _, raw := range raws {
		topic, err := herdrTopicPath(raw)
		if err != nil {
			return nil, fmt.Errorf("herdr agent %s has a malformed topic session %s: %w", agent.label(), bytes.TrimSpace(raw), err)
		}
		switch {
		case topic == "":
			return nil, fmt.Errorf("herdr agent %s names an empty topic session path", agent.label())
		case lossyHerdrPath(topic):
			return nil, fmt.Errorf("herdr agent %s names a topic session path %q holding a NUL or an undecodable character", agent.label(), topic)
		case !filepath.IsAbs(topic):
			return nil, fmt.Errorf("herdr agent %s names a non-absolute topic session path %q", agent.label(), topic)
		case topic != filepath.Clean(topic):
			return nil, fmt.Errorf("herdr agent %s names an unclean topic session path %q", agent.label(), topic)
		case !strings.HasSuffix(topic, herdrSessionLog):
			return nil, fmt.Errorf("herdr agent %s names a topic session path %q that is not a %s transcript", agent.label(), topic, herdrSessionLog)
		}
		topics = append(topics, topic)
	}
	return topics, nil
}

// herdrTopicPath reads one topic_sessions entry: a JSON string, or an
// object (read with herdrMembers, so a second member of any name or a
// "Path" is malformed) carrying a string "path" member.
func herdrTopicPath(raw json.RawMessage) (string, error) {
	r := bytes.TrimSpace(raw)
	if len(r) == 0 {
		return "", fmt.Errorf("empty entry")
	}
	switch r[0] {
	case '"':
		var topic string
		if err := json.Unmarshal(r, &topic); err != nil {
			return "", err
		}
		return topic, nil
	case '{':
		members, err := herdrMembers(r, "path")
		if err != nil {
			return "", err
		}
		path, ok := members["path"]
		if !ok {
			return "", fmt.Errorf("object has no path")
		}
		p := bytes.TrimSpace(path)
		var topic string
		if len(p) == 0 || p[0] != '"' || json.Unmarshal(p, &topic) != nil {
			return "", fmt.Errorf("path is not a string")
		}
		return topic, nil
	}
	return "", fmt.Errorf("neither a string nor an object")
}

// lossyHerdrPath reports whether a decoded herdr path is no evidence of a
// file: it holds a NUL, which no file name does, or U+FFFD. encoding/json
// decodes every invalid UTF-8 byte and every unpaired surrogate escape
// ("\ud800") to U+FFFD without an error, so such a path may not be the one
// herdr meant; a session path holding a genuine U+FFFD is rejected with
// them.
func lossyHerdrPath(value string) bool {
	return strings.ContainsRune(value, 0) || strings.ContainsRune(value, utf8.RuneError)
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

// isNull reports whether raw is absent or JSON null.
func isNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

// herdrMembers reads the members of the well-formed JSON object raw, key
// names compared after decoding escapes, and returns those named in read.
// A member name that appears twice, in any spelling, or a case variant of a
// name in read ("Value" beside or instead of "value"), is malformed:
// encoding/json keeps the last of duplicate members and matches struct
// fields case-insensitively, so which member herdr meant is unknown. Other
// members are ignored.
func herdrMembers(raw []byte, read ...string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not an object")
	}
	seen := map[string]bool{}
	members := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := tok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		if seen[key] {
			return nil, fmt.Errorf("member %q appears twice", key)
		}
		seen[key] = true
		for _, name := range read {
			if key == name {
				members[name] = value
			} else if strings.EqualFold(key, name) {
				return nil, fmt.Errorf("member %q is a case variant of %q", key, name)
			}
		}
	}
	return members, nil
}

// herdrString decodes member name into dst: a JSON string, or "" when it
// is absent or null.
func herdrString(members map[string]json.RawMessage, name string, dst *string) error {
	if raw, ok := members[name]; ok {
		if err := json.Unmarshal(raw, dst); err != nil {
			return fmt.Errorf("member %q: %w", name, err)
		}
	}
	return nil
}

// parseHerdrAgents decodes exactly one agent-list document: id
// cli:agent:list, result.type agent_list, result.agents an array of agent
// objects, each with an agent name and, when it has a session, an
// agent_session object with a kind and a value, and optionally a
// topic_sessions array of absolute, clean ".jsonl" paths. Every object is
// read with herdrMembers. A duplicate or case-variant member, a topic path
// holding a NUL or a lossily decoded character, an error document, any
// other id or result type, a null or ill-typed record, a malformed session
// or topic list, or trailing data is no answer.
func parseHerdrAgents(data []byte) ([]herdrAgent, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var root json.RawMessage
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("herdr agent list is not a well-formed JSON document: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("herdr agent list has trailing data after its JSON document")
	}
	if !isObject(root) {
		return nil, errors.New("herdr agent list is not a JSON object")
	}
	doc, err := herdrMembers(root, "id", "result", "error")
	if err != nil {
		return nil, fmt.Errorf("herdr agent list is malformed: %w", err)
	}
	if !isNull(doc["error"]) {
		// Any error document is a failure; its fields only describe it.
		var failure struct{ Code, Message string }
		_ = json.Unmarshal(doc["error"], &failure)
		return nil, fmt.Errorf("herdr agent list failed: %s: %s", failure.Code, failure.Message)
	}
	var id string
	if err := herdrString(doc, "id", &id); err != nil {
		return nil, fmt.Errorf("herdr agent list is malformed: %w", err)
	}
	if id != herdrAgentListID {
		return nil, fmt.Errorf("herdr answered %q, not %s", id, herdrAgentListID)
	}
	if !isObject(doc["result"]) {
		return nil, errors.New("herdr agent list has no result.agents")
	}
	result, err := herdrMembers(doc["result"], "type", "agents")
	if err != nil {
		return nil, fmt.Errorf("herdr agent list result is malformed: %w", err)
	}
	if isNull(result["agents"]) {
		return nil, errors.New("herdr agent list has no result.agents")
	}
	var resultType string
	if err := herdrString(result, "type", &resultType); err != nil {
		return nil, fmt.Errorf("herdr agent list result is malformed: %w", err)
	}
	if resultType != herdrAgentListType {
		return nil, fmt.Errorf("herdr agent list result type is %q, not %s", resultType, herdrAgentListType)
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(result["agents"], &raws); err != nil {
		return nil, fmt.Errorf("herdr agent list result.agents is malformed: %w", err)
	}
	agents := make([]herdrAgent, 0, len(raws))
	for i, raw := range raws {
		if !isObject(raw) {
			return nil, fmt.Errorf("herdr agent list entry %d is not an agent object: %s", i, bytes.TrimSpace(raw))
		}
		members, err := herdrMembers(raw, "agent", "name", "pane_id", "agent_session", "topic_sessions")
		if err != nil {
			return nil, fmt.Errorf("herdr agent list entry %d is malformed: %w", i, err)
		}
		var agent herdrAgent
		for name, dst := range map[string]*string{"agent": &agent.Agent, "name": &agent.Name, "pane_id": &agent.PaneID} {
			if err := herdrString(members, name, dst); err != nil {
				return nil, fmt.Errorf("herdr agent list entry %d is malformed: %w", i, err)
			}
		}
		agent.Session, agent.Topics = members["agent_session"], members["topic_sessions"]
		if agent.Agent == "" {
			return nil, fmt.Errorf("herdr agent list entry %d names no agent", i)
		}
		// An absent or null agent_session is an agent with no session.
		if !isNull(agent.Session) {
			trimmed := bytes.TrimSpace(agent.Session)
			if !isObject(trimmed) {
				return nil, fmt.Errorf("herdr agent %s has a malformed agent_session: %s", agent.label(), trimmed)
			}
			members, err := herdrMembers(trimmed, "kind", "value")
			if err != nil {
				return nil, fmt.Errorf("herdr agent %s has a malformed agent_session: %w", agent.label(), err)
			}
			var session herdrSession
			for name, dst := range map[string]*string{"kind": &session.Kind, "value": &session.Value} {
				if err := herdrString(members, name, dst); err != nil {
					return nil, fmt.Errorf("herdr agent %s has a malformed agent_session: %w", agent.label(), err)
				}
			}
			if session.Kind == "" || session.Value == "" {
				return nil, fmt.Errorf("herdr agent %s has an agent_session without kind or value", agent.label())
			}
			agent.session = &session
		}
		topics, err := parseHerdrTopics(agent)
		if err != nil {
			return nil, err
		}
		agent.topics = topics
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

// gatherHerdrReferences runs herdr once for a collection that reaches into
// a session store (view.needed); otherwise it is skipped.
func gatherHerdrReferences(ctx context.Context, opts *Options, view herdrView) ([]Reference, core.CollectorReport) {
	report := core.CollectorReport{Name: CollectorHerdr, Status: core.CollectorRan}
	switch {
	case opts.Herdr == nil:
		report.Status, report.Detail = core.CollectorSkipped, "herdr is not configured"
		return nil, report
	case !view.needed:
		report.Status, report.Detail = core.CollectorSkipped, "no observed path lies in or holds a herdr session store"
		return nil, report
	}
	sessions, err := ListHerdrSessions(ctx, opts.Herdr, opts.Limits.CommandTimeout)
	if err != nil {
		report.Status, report.Unknowns, report.Detail = core.CollectorFailed, 1, err.Error()
		return nil, report
	}
	report.Visited = sessions.Len()
	report.Detail = fmt.Sprintf("live herdr agents hold %d OMP session(s) under %s", sessions.Len(), strings.Join(opts.Herdr.SessionRoots, ", "))
	return herdrReferences(sessions, view), report
}

// attachHerdrUnknowns fails closed: when herdr was needed but did not
// answer, every entry in a session store, in any spelling, and every
// observed real directory holding one is unknown.
func attachHerdrUnknowns(entries []core.Entry, opts *Options, view herdrView, report *core.CollectorReport, now time.Time) {
	if report.Status == core.CollectorRan || report.Status == core.CollectorSkipped {
		return
	}
	for i := range entries {
		if view.reached[entries[i].Path] {
			addUnknown(&entries[i], core.SourceJob, core.ProtectCollectorFailure, CollectorHerdr,
				"herdr agent sessions are unknown: "+report.Detail, now)
			report.Recorded++
		}
	}
}
