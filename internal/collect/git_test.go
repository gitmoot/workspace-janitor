package collect

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// gitEnv is the environment fixture repositories are created with. It keeps
// the operator's real Git configuration and identity out of every test.
func gitEnv(home string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + filepath.Join(home, ".gitconfig"),
		"GIT_AUTHOR_NAME=Fixture",
		"GIT_AUTHOR_EMAIL=fixture@example.invalid",
		"GIT_COMMITTER_NAME=Fixture",
		"GIT_COMMITTER_EMAIL=fixture@example.invalid",
		"LC_ALL=C",
	}
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git is not installed: %v", err)
	}
}

func git(t *testing.T, home, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv(home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

// newRepo creates a fixture repository with one commit.
func newRepo(t *testing.T, home, dir string) string {
	t.Helper()
	mustMkdir(t, dir)
	git(t, home, dir, "init", "--initial-branch=main")
	mustWrite(t, filepath.Join(dir, "README.md"), "fixture\n")
	git(t, home, dir, "add", "README.md")
	git(t, home, dir, "commit", "-m", "initial")
	return dir
}

func gitOptions(root string) Options {
	opts := fixtureOptions(root)
	opts.Git = true
	return opts
}

func TestGitCollectorReadsRepositoryState(t *testing.T) {
	requireGit(t)
	home := t.TempDir()
	root := t.TempDir()
	repo := newRepo(t, home, filepath.Join(root, "app"))
	mustWrite(t, filepath.Join(repo, "dirty.txt"), "uncommitted\n")

	result := run(t, gitOptions(root))
	entry := entryFor(t, result, repo)

	if entry.Git == nil {
		t.Fatal("no Git state was collected")
	}
	if entry.Git.Degraded {
		t.Fatalf("state is degraded: %s", entry.Git.DegradedReason)
	}
	if entry.Git.Branch != "main" {
		t.Errorf("branch = %q, want main", entry.Git.Branch)
	}
	if entry.Git.Head == "" {
		t.Error("head was not recorded")
	}
	if entry.Git.DirtyFiles < 1 {
		t.Errorf("dirty files = %d, want the untracked file counted", entry.Git.DirtyFiles)
	}
	if entry.Git.Clean() {
		t.Error("a dirty tree must never report clean")
	}
	if !hasProtection(entry, core.ProtectDirtyRepository) {
		t.Errorf("dirty tree is not protected: %+v", entry.Protections)
	}
	// No upstream exists, so publication cannot be shown without fetching.
	if !hasProtection(entry, core.ProtectUnpublishedCommits) {
		t.Errorf("unknown publication state is not protected: %+v", entry.Protections)
	}
	if report := reportFor(t, result, CollectorGit); report.Recorded != 1 {
		t.Errorf("git report = %+v, want one repository recorded", report)
	}
}

func TestGitCollectorRecordsStashes(t *testing.T) {
	requireGit(t)
	home := t.TempDir()
	root := t.TempDir()
	repo := newRepo(t, home, filepath.Join(root, "app"))
	mustWrite(t, filepath.Join(repo, "README.md"), "changed\n")
	git(t, home, repo, "stash", "push", "-m", "work in progress")

	entry := entryFor(t, run(t, gitOptions(root)), repo)
	if entry.Git.Stashes != 1 {
		t.Errorf("stashes = %d, want 1", entry.Git.Stashes)
	}
	if !hasProtection(entry, core.ProtectStashedWork) {
		t.Errorf("stashed work is not protected: %+v", entry.Protections)
	}
}

func TestGitCollectorIdentifiesLinkedWorktree(t *testing.T) {
	requireGit(t)
	home := t.TempDir()
	root := t.TempDir()
	repo := newRepo(t, home, filepath.Join(root, "app"))
	worktree := filepath.Join(root, "app-feature")
	git(t, home, repo, "worktree", "add", worktree, "-b", "feature")

	entry := entryFor(t, run(t, gitOptions(root)), worktree)
	if entry.Git == nil || entry.Git.Degraded {
		t.Fatalf("worktree state = %+v", entry.Git)
	}
	if entry.Git.WorktreeOf != repo {
		t.Errorf("worktree owner = %q, want %q", entry.Git.WorktreeOf, repo)
	}
	if !hasSignal(entry, "linked_worktree") {
		t.Errorf("linked worktree is not recorded: %+v", entry.Evidence)
	}
	if entry.Git.Branch != "feature" {
		t.Errorf("branch = %q, want feature", entry.Git.Branch)
	}
}

func TestBrokenGitfileIsProtected(t *testing.T) {
	requireGit(t)
	root := t.TempDir()
	broken := mustMkdir(t, filepath.Join(root, "broken"))
	mustWrite(t, filepath.Join(broken, ".git"), "gitdir: /nonexistent/elsewhere/.git\n")
	garbage := mustMkdir(t, filepath.Join(root, "garbage"))
	mustWrite(t, filepath.Join(garbage, ".git"), "not a gitfile at all\n")

	result := run(t, gitOptions(root))
	for _, path := range []string{broken, garbage} {
		entry := entryFor(t, result, path)
		if entry.Git == nil || !entry.Git.Degraded {
			t.Errorf("%s: state = %+v, want degraded", path, entry.Git)
		}
		if entry.Git != nil && entry.Git.Clean() {
			t.Errorf("%s: broken metadata must never report clean", path)
		}
		if !hasProtection(entry, core.ProtectBrokenGitMetadata) {
			t.Errorf("%s: broken git metadata is not protected: %+v", path, entry.Protections)
		}
	}
	if report := reportFor(t, result, CollectorGit); report.Status != core.CollectorPartial {
		t.Errorf("git status = %q, want partial", report.Status)
	}
}

// A Git command that times out leaves the repository unobserved. The path
// must end up protected, never clean.
func TestGitTimeoutProtectsPathInsteadOfMarkingItClean(t *testing.T) {
	root := t.TempDir()
	repo := mustMkdir(t, filepath.Join(root, "slow"))
	mustMkdir(t, filepath.Join(repo, ".git"))

	slowGit := filepath.Join(t.TempDir(), "git")
	mustWrite(t, slowGit, "#!/bin/sh\nsleep 30\n")
	if err := os.Chmod(slowGit, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	opts := gitOptions(root)
	opts.GitBinary = slowGit
	opts.Limits.GitTimeout = 100 * time.Millisecond

	start := time.Now()
	result := run(t, opts)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("collection took %s: the git timeout did not bound the command", elapsed)
	}

	entry := entryFor(t, result, repo)
	if entry.Git == nil || !entry.Git.Degraded {
		t.Fatalf("state = %+v, want degraded after a timeout", entry.Git)
	}
	if !strings.Contains(entry.Git.DegradedReason, "timed out") {
		t.Errorf("degraded reason = %q, want it to name the timeout", entry.Git.DegradedReason)
	}
	if entry.Git.Clean() {
		t.Error("a timed-out repository must never report clean")
	}
	if !hasProtection(entry, core.ProtectCollectorFailure) {
		t.Errorf("timed-out repository is not protected: %+v", entry.Protections)
	}
	if report := reportFor(t, result, CollectorGit); report.Status != core.CollectorPartial || report.Unknowns != 1 {
		t.Errorf("git report = %+v, want partial with one unknown", report)
	}
}

// A scan may never reach the network. The allowlist is the enforcement
// point, so it is tested directly as well as through the runner.
func TestGitRunnerRefusesCommandsOutsideTheReadOnlyAllowlist(t *testing.T) {
	runner := gitRunner{binary: "git", timeout: time.Second}
	for _, verb := range []string{"fetch", "pull", "clone", "ls-remote", "push", "remote"} {
		if _, err := runner.run(context.Background(), t.TempDir(), verb, "origin"); !errors.Is(err, errGitVerbNotAllowed) {
			t.Errorf("git %s was not refused: %v", verb, err)
		}
	}
	if _, err := runner.run(context.Background(), t.TempDir()); !errors.Is(err, errGitVerbNotAllowed) {
		t.Errorf("an empty command was not refused: %v", err)
	}
	for verb := range gitReadOnlyVerbs {
		switch verb {
		case "fetch", "pull", "clone", "push", "ls-remote", "submodule":
			t.Errorf("allowlist contains network-capable verb %q", verb)
		}
	}
}

func TestGitCollectorSkipsNonRepositories(t *testing.T) {
	requireGit(t)
	root := t.TempDir()
	plain := mustMkdir(t, filepath.Join(root, "plain"))

	result := run(t, gitOptions(root))
	entry := entryFor(t, result, plain)
	if entry.Git != nil {
		t.Errorf("non-repository has Git state: %+v", entry.Git)
	}
	if report := reportFor(t, result, CollectorGit); report.Recorded != 0 {
		t.Errorf("git report = %+v, want nothing recorded", report)
	}
}

func TestGitCollectorSkippedWhenDisabled(t *testing.T) {
	requireGit(t)
	home := t.TempDir()
	root := t.TempDir()
	repo := newRepo(t, home, filepath.Join(root, "app"))

	opts := fixtureOptions(root)
	opts.Git = false
	result := run(t, opts)

	if entry := entryFor(t, result, repo); entry.Git != nil {
		t.Errorf("git state collected while disabled: %+v", entry.Git)
	}
	report := reportFor(t, result, CollectorGit)
	if report.Status != core.CollectorSkipped || report.Detail == "" {
		t.Errorf("git report = %+v, want a skipped report with a reason", report)
	}
}

func TestGitLockIsProtected(t *testing.T) {
	requireGit(t)
	home := t.TempDir()
	root := t.TempDir()
	repo := newRepo(t, home, filepath.Join(root, "app"))
	mustWrite(t, filepath.Join(repo, ".git", "index.lock"), "")

	entry := entryFor(t, run(t, gitOptions(root)), repo)
	if entry.Git == nil || !entry.Git.Locked {
		t.Fatalf("state = %+v, want the lock detected", entry.Git)
	}
	if !hasProtection(entry, core.ProtectLockHeld) {
		t.Errorf("held lock is not protected: %+v", entry.Protections)
	}
}
