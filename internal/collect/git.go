package collect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// maxGitFileBytes bounds how much of a ".git" pointer file is read. A real
// gitfile is one short line.
const maxGitFileBytes = 4096

// gitReadOnlyVerbs is the complete set of Git subcommands this collector may
// run. Every one is local and read-only.
//
// The allowlist exists to make the "never fetch during a scan" rule
// enforceable rather than aspirational: adding a network verb requires
// editing this list, and runGit refuses anything absent from it.
var gitReadOnlyVerbs = map[string]struct{}{
	"rev-parse": {},
	"status":    {},
	"stash":     {},
	"config":    {},
	"worktree":  {},
}

// errGitVerbNotAllowed reports an attempt to run a non-allowlisted command.
var errGitVerbNotAllowed = errors.New("collect: git subcommand is not in the read-only allowlist")

// gitRunner executes bounded, read-only git commands.
type gitRunner struct {
	binary  string
	timeout time.Duration
}

func newGitRunner(opts *Options) gitRunner {
	binary := opts.GitBinary
	if binary == "" {
		binary = "git"
	}
	return gitRunner{binary: binary, timeout: opts.Limits.GitTimeout}
}

// run executes one git command in dir under the configured timeout.
func (g gitRunner) run(ctx context.Context, dir string, args ...string) (string, error) {
	if len(args) == 0 {
		return "", errGitVerbNotAllowed
	}
	if _, ok := gitReadOnlyVerbs[args[0]]; !ok {
		return "", fmt.Errorf("%w: %q", errGitVerbNotAllowed, args[0])
	}
	ctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	// Git's -c options override repository config even on versions that do
	// not support GIT_CONFIG_COUNT. Status must never run an fsmonitor hook.
	commandArgs := make([]string, 0, len(args)+4)
	commandArgs = append(commandArgs, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null")
	commandArgs = append(commandArgs, args...)
	cmd := exec.CommandContext(ctx, g.binary, commandArgs...)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + dir,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_ASKPASS=true",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"LC_ALL=C",
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	configureProcessGroup(cmd)
	// Backstop for a grandchild that survives the group kill: Wait returns
	// shortly after the deadline instead of blocking on an inherited pipe.
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if ctxErr := ctx.Err(); errors.Is(ctxErr, context.DeadlineExceeded) {
		return "", fmt.Errorf("git %s timed out after %s", args[0], g.timeout)
	}
	if err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return "", fmt.Errorf("git %s failed: %s", strings.Join(args, " "), detail)
	}
	return strings.TrimRight(stdout.String(), "\n"), nil
}

// collectGit enriches directory entries that are Git working trees.
//
// Any command failure or timeout degrades the state and protects the path:
// an unobserved repository must never be presented as clean.
func collectGit(ctx context.Context, opts *Options, entries []core.Entry, now time.Time) core.CollectorReport {
	report := core.CollectorReport{Name: CollectorGit, Status: core.CollectorRan}
	runner := newGitRunner(opts)

	for i := range entries {
		entry := &entries[i]
		if entry.Kind != core.EntryKindDirectory {
			continue
		}
		marker, kind, err := gitMarker(entry.Path)
		switch {
		case err != nil:
			report.Visited++
			report.Unknowns++
			report.Status = core.CollectorPartial
			entry.Git = &core.GitState{Degraded: true, DegradedReason: err.Error()}
			addUnknown(entry, core.SourceGit, core.ProtectBrokenGitMetadata,
				"git_marker_unreadable", err.Error(), now)
			continue
		case kind == gitMarkerNone:
			continue
		}
		report.Visited++
		if collectRepository(ctx, runner, entry, marker, kind, now) {
			report.Unknowns++
			report.Status = core.CollectorPartial
		}
		report.Recorded++
	}

	if report.Detail == "" {
		report.Detail = fmt.Sprintf("inspected %d repositor(ies) with a %s timeout, read-only verbs only",
			report.Recorded, opts.Limits.GitTimeout)
	}
	return report
}

type gitMarkerKind int

const (
	gitMarkerNone gitMarkerKind = iota
	gitMarkerDirectory
	gitMarkerFile
)

// gitMarker inspects "<dir>/.git" without following it.
func gitMarker(dir string) (string, gitMarkerKind, error) {
	path := filepath.Join(dir, ".git")
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", gitMarkerNone, nil
		}
		return "", gitMarkerNone, fmt.Errorf("lstat %s: %v", path, err)
	}
	switch {
	case info.IsDir():
		return path, gitMarkerDirectory, nil
	case info.Mode().IsRegular():
		if info.Size() > maxGitFileBytes {
			return "", gitMarkerFile, fmt.Errorf("gitfile %s is %d bytes, larger than the %d byte bound", path, info.Size(), maxGitFileBytes)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", gitMarkerFile, fmt.Errorf("read %s: %v", path, err)
		}
		target := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(data)), "gitdir:"))
		if target == "" || target == strings.TrimSpace(string(data)) {
			return "", gitMarkerFile, fmt.Errorf("gitfile %s does not contain a gitdir pointer", path)
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(dir, target)
		}
		if _, err := os.Stat(target); err != nil {
			return "", gitMarkerFile, fmt.Errorf("gitfile %s points at %s which is unreadable: %v", path, target, err)
		}
		return filepath.Clean(target), gitMarkerFile, nil
	default:
		return "", gitMarkerFile, fmt.Errorf("%s is neither a directory nor a gitfile", path)
	}
}

// collectRepository fills entry.Git. It returns true when anything was left
// unknown.
func collectRepository(ctx context.Context, runner gitRunner, entry *core.Entry, marker string, kind gitMarkerKind, now time.Time) bool {
	state := &core.GitState{RepoRoot: entry.Path}
	entry.Git = state
	if kind == gitMarkerFile {
		state.WorktreeOf = worktreeParent(marker)
		addEvidence(entry, core.Evidence{
			Source:     core.SourceGit,
			Signal:     "linked_worktree",
			Detail:     "git directory " + marker,
			ObservedAt: now,
		})
	}

	degrade := func(reason string, kind core.ProtectionKind, signal string) bool {
		state.Degraded = true
		state.DegradedReason = reason
		addUnknown(entry, core.SourceGit, kind, signal, reason, now)
		return true
	}

	commonDir, err := runner.run(ctx, entry.Path, "rev-parse", "--git-common-dir")
	if err != nil {
		return degrade(err.Error(), degradeKind(err), "git_rev_parse_failed")
	}
	if !filepath.IsAbs(commonDir) {
		commonDir = filepath.Join(entry.Path, commonDir)
	}
	commonDir = filepath.Clean(commonDir)

	if bare, err := runner.run(ctx, entry.Path, "rev-parse", "--is-bare-repository"); err != nil {
		return degrade(err.Error(), degradeKind(err), "git_rev_parse_failed")
	} else {
		state.Bare = bare == "true"
	}

	if remote, err := runner.run(ctx, entry.Path, "config", "--get", "remote.origin.url"); err == nil {
		state.Remote = remote
	}

	status, err := runner.run(ctx, entry.Path, "status", "--porcelain=v2", "--branch", "--untracked-files=all", "--no-renames")
	if err != nil {
		return degrade(err.Error(), degradeKind(err), "git_status_failed")
	}
	parseStatus(status, state)

	if stashes, err := runner.run(ctx, entry.Path, "stash", "list"); err != nil {
		return degrade(err.Error(), degradeKind(err), "git_stash_failed")
	} else {
		state.Stashes = countLines(stashes)
	}

	state.Locked = gitLocked(commonDir, marker, kind)
	if state.Locked {
		addProtection(entry, core.Protection{
			Kind:     core.ProtectLockHeld,
			Reason:   "a Git lock file is present",
			Source:   core.SourceGit,
			Blocking: true,
		})
	}

	addEvidence(entry, core.Evidence{
		Source: core.SourceGit,
		Signal: "git_state",
		Detail: fmt.Sprintf("branch %q head %q dirty %d stashes %d unpublished %d upstream %t",
			state.Branch, shortHead(state.Head), state.DirtyFiles, state.Stashes, state.UnpublishedCommits, state.UpstreamKnown),
		ObservedAt: now,
	})

	if state.DirtyFiles > 0 {
		addProtection(entry, core.Protection{
			Kind:     core.ProtectDirtyRepository,
			Reason:   fmt.Sprintf("%d uncommitted change(s)", state.DirtyFiles),
			Source:   core.SourceGit,
			Blocking: true,
		})
	}
	if state.Stashes > 0 {
		addProtection(entry, core.Protection{
			Kind:     core.ProtectStashedWork,
			Reason:   fmt.Sprintf("%d stash entr(ies)", state.Stashes),
			Source:   core.SourceGit,
			Blocking: true,
		})
	}
	switch {
	case !state.UpstreamKnown && !state.Bare:
		// No upstream means publication cannot be shown, and a scan may not
		// fetch to find out. Unknown publication fails closed.
		addUnknown(entry, core.SourceGit, core.ProtectUnpublishedCommits,
			"upstream_unknown", "no upstream is configured, so local commits cannot be shown as published", now)
		return true
	case state.UnpublishedCommits > 0:
		addProtection(entry, core.Protection{
			Kind:     core.ProtectUnpublishedCommits,
			Reason:   fmt.Sprintf("%d commit(s) ahead of upstream", state.UnpublishedCommits),
			Source:   core.SourceGit,
			Blocking: true,
		})
	}
	return false
}

// degradeKind maps a Git failure onto the protection that describes it.
func degradeKind(err error) core.ProtectionKind {
	if strings.Contains(err.Error(), "timed out") {
		return core.ProtectCollectorFailure
	}
	return core.ProtectBrokenGitMetadata
}

// parseStatus reads `git status --porcelain=v2 --branch` output.
func parseStatus(output string, state *core.GitState) {
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "# ") {
			// Any non-header porcelain line is a change: tracked
			// modification (1/2), unmerged (u), untracked (?), or ignored
			// (!), and ignored entries are not requested.
			state.DirtyFiles++
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		switch fields[1] {
		case "branch.oid":
			if fields[2] != "(initial)" {
				state.Head = fields[2]
			}
		case "branch.head":
			if fields[2] != "(detached)" {
				state.Branch = fields[2]
			}
		case "branch.upstream":
			state.UpstreamKnown = true
		case "branch.ab":
			if len(fields) >= 4 {
				state.UnpublishedCommits = parseAhead(fields[2])
			}
		}
	}
}

func parseAhead(field string) int {
	value, err := strconv.Atoi(strings.TrimPrefix(field, "+"))
	if err != nil || value < 0 {
		return 0
	}
	return value
}

// gitLocked reports whether a lock file is present in the repository or in
// the linked worktree's administrative directory.
func gitLocked(commonDir, marker string, kind gitMarkerKind) bool {
	candidates := []string{filepath.Join(commonDir, "index.lock")}
	if kind == gitMarkerFile {
		candidates = append(candidates,
			filepath.Join(marker, "index.lock"),
			filepath.Join(marker, "locked"),
		)
	}
	for _, candidate := range candidates {
		if _, err := os.Lstat(candidate); err == nil {
			return true
		}
	}
	return false
}

// worktreeParent maps ".../<repo>/.git/worktrees/<name>" to the repository
// working tree that owns the linked worktree.
func worktreeParent(gitDir string) string {
	parent := filepath.Dir(gitDir)
	if filepath.Base(parent) != "worktrees" {
		return ""
	}
	common := filepath.Dir(parent)
	if filepath.Base(common) == ".git" {
		return filepath.Dir(common)
	}
	return common
}

func countLines(output string) int {
	output = strings.TrimSpace(output)
	if output == "" {
		return 0
	}
	return len(strings.Split(output, "\n"))
}

func shortHead(head string) string {
	if len(head) > 12 {
		return head[:12]
	}
	return head
}
