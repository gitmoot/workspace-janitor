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
	"strconv"
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

// KeepsFile is why a live agent keeps the single file at path (any
// spelling, resolved): herdr lists it (an agent_session or a topic
// transcript), or it is a ".jsonl" directly inside the session folder of a
// listed transcript, where OMP keeps that session's topic transcripts. It
// is "" otherwise. omp_session_artifacts never moves such a file.
func (h *HerdrSessions) KeepsFile(path string) string {
	real := config.RealParent(path)
	if agents, ok := h.sessions[real]; ok {
		return liveSessionDetail(real, agents)
	}
	if !strings.HasSuffix(real, herdrSessionLog) {
		return ""
	}
	transcript := filepath.Dir(real) + herdrSessionLog
	if agents, ok := h.sessions[transcript]; ok {
		return liveSessionDetail(transcript, agents) + ", whose session folder holds its topic transcripts"
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
// under its own guards and asks only HerdrSessions.KeepsFile.
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
// absolute, clean ".jsonl" path (herdrPath), or an object (herdrObject)
// whose "path" member is one (herdr 0.9.5 emits {path, topic_id, title,
// created_unix_ms}; other members are ignored).
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

// herdrTopicPath reads one topic_sessions entry: a path string, or an
// object whose "path" member is one.
func herdrTopicPath(raw json.RawMessage) (string, error) {
	r := bytes.TrimSpace(raw)
	if isObject(r) {
		var path json.RawMessage
		if err := herdrObject(r, herdrFields{"path": &path}); err != nil {
			return "", err
		}
		if path == nil {
			return "", errors.New("object has no path")
		}
		r = path
	}
	return herdrPath(r)
}

// herdrPath decodes raw, a JSON string naming a path, only when decoding
// is lossless. encoding/json replaces each invalid UTF-8 byte and each
// unpaired surrogate escape ("\ud800" without a low surrogate after it, or
// a lone "\udc00") with U+FFFD without an error, so such a path may not be
// the one herdr meant: the raw token is checked before decoding. A U+FFFD
// herdr sent, as UTF-8 or as "\ufffd", is a character of a valid file name
// and kept. A NUL, which no file name holds, is refused.
func herdrPath(raw []byte) (string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return "", errors.New("path is not a string")
	}
	if !utf8.Valid(raw) {
		return "", errors.New("path is not valid UTF-8")
	}
	if err := pairedSurrogateEscapes(raw); err != nil {
		return "", err
	}
	var path string
	if err := json.Unmarshal(raw, &path); err != nil {
		return "", fmt.Errorf("path is not a string: %w", err)
	}
	if strings.IndexByte(path, 0) >= 0 {
		return "", errors.New("path holds a NUL")
	}
	return path, nil
}

// pairedSurrogateEscapes checks that every surrogate "\uXXXX" escape in the
// JSON string token raw is a high surrogate immediately followed by a low
// one, the only surrogates encoding/json decodes without loss. Malformed
// escapes are left to the decoder, which refuses them.
func pairedSurrogateEscapes(raw []byte) error {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		// Step onto the escaped character, so an escaped backslash is
		// never read as the start of an escape.
		i++
		if i == len(raw) || raw[i] != 'u' {
			continue
		}
		r, ok := hexRune(raw, i+1)
		if !ok {
			continue
		}
		i += 4
		switch {
		case 0xd800 <= r && r < 0xdc00:
			if i+2 < len(raw) && raw[i+1] == '\\' && raw[i+2] == 'u' {
				if low, ok := hexRune(raw, i+3); ok && 0xdc00 <= low && low < 0xe000 {
					i += 6
					continue
				}
			}
			return fmt.Errorf("path has an unpaired surrogate escape \\u%04x", r)
		case 0xdc00 <= r && r < 0xe000:
			return fmt.Errorf("path has an unpaired surrogate escape \\u%04x", r)
		}
	}
	return nil
}

// hexRune reads the four hex digits of a "\u" escape at raw[at:].
func hexRune(raw []byte, at int) (rune, bool) {
	if at+4 > len(raw) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(raw[at:at+4]), 16, 16)
	return rune(n), err == nil
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

// herdrFields declares, once for matching and decoding, each member a herdr
// object is read for: its exact wire name and where it decodes, a *string
// (null leaves "") or a *json.RawMessage (absent leaves it nil).
type herdrFields map[string]any

// herdrObject decodes raw, exactly one JSON object and nothing after it
// but space, into fields, key names compared after decoding escapes. A
// member name that appears twice, in any spelling, or a case variant of a
// name in fields ("Value" beside or instead of "value") is malformed:
// encoding/json keeps the last of duplicate members and matches struct
// fields case-insensitively, so which member herdr meant is unknown. Other
// members are ignored.
func herdrObject(raw []byte, fields herdrFields) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('{') {
		return errors.New("not an object")
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := tok.(string)
		if seen[key] {
			return fmt.Errorf("member %q appears twice", key)
		}
		seen[key] = true
		dst, read := fields[key]
		if !read {
			for name := range fields {
				if strings.EqualFold(key, name) {
					return fmt.Errorf("member %q is a case variant of %q", key, name)
				}
			}
			dst = new(json.RawMessage)
		}
		if err := dec.Decode(dst); err != nil {
			return fmt.Errorf("member %q: %w", key, err)
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return errors.New("object is not closed")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the object")
	}
	return nil
}

// herdrFailure is the failure an error document reports. Any error
// document is a failure; a malformed one (not an object, a duplicate or
// case-variant member, an ill-typed code or message) is reported as
// malformed, never by a shadowed or partial value.
func herdrFailure(raw json.RawMessage) error {
	var code, message string
	if err := herdrObject(raw, herdrFields{"code": &code, "message": &message}); err != nil {
		return fmt.Errorf("herdr agent list failed with a malformed error: %w", err)
	}
	return fmt.Errorf("herdr agent list failed: %s: %s", code, message)
}

// parseHerdrAgents decodes exactly one agent-list document: id
// cli:agent:list, result.type agent_list, result.agents an array of agent
// objects, each with an agent name and, when it has a session, an
// agent_session object with a kind and a value (for kind path, a lossless
// herdrPath), and optionally a topic_sessions array of absolute, clean
// ".jsonl" paths. Every object is read with herdrObject. A duplicate or
// case-variant member, a lossy or NUL-holding path, an error document, any
// other id or result type, a null or ill-typed record, a malformed session
// or topic list, or trailing data is no answer.
func parseHerdrAgents(data []byte) ([]herdrAgent, error) {
	var id string
	var result, failure json.RawMessage
	if err := herdrObject(data, herdrFields{"id": &id, "result": &result, "error": &failure}); err != nil {
		return nil, fmt.Errorf("herdr agent list is not a well-formed document: %w", err)
	}
	if !isNull(failure) {
		return nil, herdrFailure(failure)
	}
	if id != herdrAgentListID {
		return nil, fmt.Errorf("herdr answered %q, not %s", id, herdrAgentListID)
	}
	if !isObject(result) {
		return nil, errors.New("herdr agent list has no result.agents")
	}
	var resultType string
	var list json.RawMessage
	if err := herdrObject(result, herdrFields{"type": &resultType, "agents": &list}); err != nil {
		return nil, fmt.Errorf("herdr agent list result is malformed: %w", err)
	}
	if isNull(list) {
		return nil, errors.New("herdr agent list has no result.agents")
	}
	if resultType != herdrAgentListType {
		return nil, fmt.Errorf("herdr agent list result type is %q, not %s", resultType, herdrAgentListType)
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(list, &raws); err != nil {
		return nil, fmt.Errorf("herdr agent list result.agents is malformed: %w", err)
	}
	agents := make([]herdrAgent, 0, len(raws))
	for i, raw := range raws {
		if !isObject(raw) {
			return nil, fmt.Errorf("herdr agent list entry %d is not an agent object: %s", i, bytes.TrimSpace(raw))
		}
		var agent herdrAgent
		if err := herdrObject(raw, herdrFields{"agent": &agent.Agent, "name": &agent.Name, "pane_id": &agent.PaneID,
			"agent_session": &agent.Session, "topic_sessions": &agent.Topics}); err != nil {
			return nil, fmt.Errorf("herdr agent list entry %d is malformed: %w", i, err)
		}
		if agent.Agent == "" {
			return nil, fmt.Errorf("herdr agent list entry %d names no agent", i)
		}
		// An absent or null agent_session is an agent with no session.
		if !isNull(agent.Session) {
			session, err := parseHerdrSession(agent)
			if err != nil {
				return nil, err
			}
			agent.session = session
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

// parseHerdrSession decodes an agent's non-null agent_session: an object
// with a string kind and value; a "path" value is a lossless herdrPath.
func parseHerdrSession(agent herdrAgent) (*herdrSession, error) {
	trimmed := bytes.TrimSpace(agent.Session)
	if !isObject(trimmed) {
		return nil, fmt.Errorf("herdr agent %s has a malformed agent_session: %s", agent.label(), trimmed)
	}
	var session herdrSession
	var value json.RawMessage
	if err := herdrObject(trimmed, herdrFields{"kind": &session.Kind, "value": &value}); err != nil {
		return nil, fmt.Errorf("herdr agent %s has a malformed agent_session: %w", agent.label(), err)
	}
	if !isNull(value) {
		var err error
		if session.Kind == "path" {
			session.Value, err = herdrPath(value)
		} else {
			err = json.Unmarshal(value, &session.Value)
		}
		if err != nil {
			return nil, fmt.Errorf("herdr agent %s has a malformed agent_session value: %w", agent.label(), err)
		}
	}
	if session.Kind == "" || session.Value == "" {
		return nil, fmt.Errorf("herdr agent %s has an agent_session without kind or value", agent.label())
	}
	return &session, nil
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
