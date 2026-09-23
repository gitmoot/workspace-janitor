// Package jev is the optional Jev advisor, accessed through OpenRouter,
// for entries the deterministic rules could not classify.
//
// It is an advisor, never an authority. It sees only entries the planner
// marked ambiguous, only after every rule has run, and only as a sanitized
// projection. Its answers pass through the safety engine and are accepted
// only when they make a decision safer. When it is absent, unconfigured,
// offline, slow, or wrong, the rules' decision stands.
package jev

import (
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// SchemaVersion versions everything that is sent and asked: the projection
// below, the questions, and how answers are mapped. Changing any of them
// must bump it, which invalidates every cached decision.
const SchemaVersion = 1

// redactedSegment replaces a path segment that must not leave the machine.
const redactedSegment = "[redacted]"

// Projection is the complete set of facts about one entry that may be sent.
//
// It is an allowlist. Nothing reaches a request unless a field here names
// it, so a new field on core.Entry cannot leak by default. Deliberately
// absent: file contents, evidence details (they quote paths, process names,
// and service definitions), Git remotes (URLs routinely embed credentials),
// symlink targets, owner ids, and absolute paths.
type Projection struct {
	Ref          string         `json:"ref"`
	Path         string         `json:"path"`
	Name         string         `json:"name"`
	Kind         string         `json:"kind"`
	Depth        int            `json:"depth"`
	Size         string         `json:"size"`
	SizeMeasured bool           `json:"size_measured"`
	AgeDays      int            `json:"modified_days_ago"`
	Git          *GitProjection `json:"git,omitempty"`
	Signals      []string       `json:"signals"`
	Protections  []string       `json:"protections"`
}

// GitProjection carries Git facts as counts and booleans only: no branch
// names, commit ids, or remotes, which can identify private work.
type GitProjection struct {
	LinkedWorktree     bool `json:"linked_worktree"`
	HasUpstream        bool `json:"has_upstream"`
	DirtyFiles         int  `json:"dirty_files"`
	Stashes            int  `json:"stashes"`
	UnpublishedCommits int  `json:"unpublished_commits"`
	Degraded           bool `json:"degraded"`
}

// signalPattern admits only the fixed vocabulary our collectors emit. A
// signal is a name like "git_state" or "unknown:lstat_failed"; anything
// else is dropped rather than trusted.
var signalPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(:[a-z][a-z0-9_]*)?$`)

// Redactor decides which path segments may be sent verbatim.
type Redactor struct {
	// Segments are policy-configured patterns that are always redacted.
	Segments []string
	// SensitiveNames are the protected-name patterns, which by definition
	// look like credential material.
	SensitiveNames []string
}

// Segment returns a path segment, or the redaction marker when it must not
// be sent.
func (r Redactor) Segment(segment string) string {
	if segment == "" {
		return segment
	}
	for _, patterns := range [][]string{r.Segments, r.SensitiveNames} {
		for _, pattern := range patterns {
			if matched, err := filepath.Match(pattern, segment); err == nil && matched {
				return redactedSegment
			}
			if pattern == segment {
				return redactedSegment
			}
		}
	}
	if looksSecret(segment) {
		return redactedSegment
	}
	return segment
}

// looksSecret flags segments shaped like tokens or keys: long, dense runs
// of letters and digits with no word structure. A directory named after an
// API key is rare, but sending one to a third party is not recoverable.
func looksSecret(segment string) bool {
	if len(segment) < 24 {
		return false
	}
	letters, digits, other := 0, 0, 0
	for _, r := range segment {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			letters++
		case r >= '0' && r <= '9':
			digits++
		case r == '-' || r == '_':
			other++
		default:
			return false
		}
	}
	return digits >= 4 && letters >= 4 && other <= 3
}

// Project builds the sanitized view of one entry.
//
// The path is rewritten relative to its discovery root, which is replaced
// by the placeholder "<root>": the root is usually a home directory, and a
// home directory names a person.
func Project(entry core.Entry, ref string, redactor Redactor, now time.Time) Projection {
	segments := relativeSegments(entry)
	sent := make([]string, 0, len(segments)+1)
	sent = append(sent, "<root>")
	for _, segment := range segments {
		sent = append(sent, redactor.Segment(segment))
	}

	name := redactedSegment
	if len(segments) > 0 {
		name = redactor.Segment(segments[len(segments)-1])
	}

	projection := Projection{
		Ref:          ref,
		Path:         strings.Join(sent, "/"),
		Name:         name,
		Kind:         string(entry.Kind),
		Depth:        len(segments),
		Size:         sizeBucket(entry.SizeBytes),
		SizeMeasured: entry.SizeIsDeep || entry.Kind == core.EntryKindFile,
		AgeDays:      ageDays(entry.ModifiedAt, now),
		Signals:      signalNames(entry),
		Protections:  protectionKinds(entry),
	}
	if entry.Git != nil {
		projection.Git = &GitProjection{
			LinkedWorktree:     entry.Git.WorktreeOf != "",
			HasUpstream:        entry.Git.UpstreamKnown,
			DirtyFiles:         entry.Git.DirtyFiles,
			Stashes:            entry.Git.Stashes,
			UnpublishedCommits: entry.Git.UnpublishedCommits,
			Degraded:           entry.Git.Degraded,
		}
	}
	return projection
}

// relativeSegments splits the entry's path below its root. An entry with no
// usable root sends only its final segment, never an absolute path.
func relativeSegments(entry core.Entry) []string {
	if entry.Root != "" && core.PathWithin(entry.Path, entry.Root) && entry.Path != entry.Root {
		rel, err := filepath.Rel(entry.Root, entry.Path)
		if err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			return strings.Split(filepath.ToSlash(rel), "/")
		}
	}
	return []string{filepath.Base(entry.Path)}
}

// sizeBucket reports size coarsely. Exact byte counts add nothing to a
// classification and can fingerprint specific files.
func sizeBucket(bytes int64) string {
	const (
		mib = int64(1) << 20
		gib = int64(1) << 30
	)
	switch {
	case bytes <= 0:
		return "empty"
	case bytes < mib:
		return "under_1MiB"
	case bytes < 100*mib:
		return "under_100MiB"
	case bytes < gib:
		return "under_1GiB"
	default:
		return "1GiB_or_more"
	}
}

func ageDays(modified, now time.Time) int {
	if modified.IsZero() || now.IsZero() || now.Before(modified) {
		return 0
	}
	return int(now.Sub(modified).Hours() / 24)
}

func signalNames(entry core.Entry) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, evidence := range entry.Evidence {
		if !signalPattern.MatchString(evidence.Signal) {
			continue
		}
		if _, dup := seen[evidence.Signal]; dup {
			continue
		}
		seen[evidence.Signal] = struct{}{}
		out = append(out, evidence.Signal)
	}
	return out
}

func protectionKinds(entry core.Entry) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, protection := range entry.Protections {
		if !protection.Kind.Valid() {
			continue
		}
		kind := string(protection.Kind)
		if _, dup := seen[kind]; dup {
			continue
		}
		seen[kind] = struct{}{}
		out = append(out, kind)
	}
	return out
}
