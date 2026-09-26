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

// Old Git ignores GIT_CONFIG_COUNT. Simulate that behavior while exercising
// the real runner: argv-level overrides must still prevent repository hooks.
func TestGitRunnerDisablesFsmonitorWithoutEnvironmentConfig(t *testing.T) {
	requireGit(t)
	home := t.TempDir()
	repo := newRepo(t, home, filepath.Join(home, "repo"))
	hook := filepath.Join(home, "fsmonitor.sh")
	marker := filepath.Join(home, "hook-ran")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nprintf ran > \"${0%/*}/hook-ran\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	git(t, home, repo, "config", "core.fsmonitor", hook)
	mustWrite(t, filepath.Join(repo, "dirty"), "uncommitted\n")
	wrapper := filepath.Join(home, "old-git")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nunset GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 GIT_CONFIG_KEY_1 GIT_CONFIG_VALUE_1\nexec git \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	runner := gitRunner{binary: wrapper, timeout: time.Second}
	if _, err := runner.run(context.Background(), repo, "status", "--porcelain=v2", "--branch"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatalf("repository fsmonitor ran despite command-line override: %v", err)
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

// pushedRepo creates a repository whose main branch is on a bare remote's
// tracking ref, pushed without configuring an upstream.
func pushedRepo(t *testing.T, home, root, name string) string {
	t.Helper()
	remote := filepath.Join(t.TempDir(), name+".git")
	git(t, home, root, "init", "--bare", "--initial-branch=main", remote)
	repo := newRepo(t, home, filepath.Join(root, name))
	git(t, home, repo, "remote", "add", "origin", remote)
	git(t, home, repo, "push", "origin", "main")
	return repo
}

// Publication is judged against every remote-tracking branch, not only a
// configured upstream: a clone pushed without -u is published, and a clean
// current branch does not hide unpushed commits on another local branch.
func TestGitPublicationCoversEveryRemoteTrackingBranch(t *testing.T) {
	requireGit(t)
	home := t.TempDir()
	root := t.TempDir()

	published := pushedRepo(t, home, root, "published")
	sideBranch := pushedRepo(t, home, root, "side-branch")
	git(t, home, sideBranch, "switch", "-c", "local-only")
	mustWrite(t, filepath.Join(sideBranch, "work.txt"), "unpushed\n")
	git(t, home, sideBranch, "add", "work.txt")
	git(t, home, sideBranch, "commit", "-m", "unpushed work")
	git(t, home, sideBranch, "switch", "main")

	result := run(t, gitOptions(root))

	entry := entryFor(t, result, published)
	if entry.Git.UpstreamKnown {
		t.Fatal("fixture must have no configured upstream")
	}
	if !entry.Git.PublicationKnown || entry.Git.UnpublishedCommits != 0 || !entry.Git.Clean() {
		t.Errorf("pushed clone state = %+v, want published and clean", entry.Git)
	}
	if hasProtection(entry, core.ProtectUnpublishedCommits) || hasSignal(entry, "unknown:upstream_unknown") {
		t.Errorf("pushed clone is protected as unpublished: %+v", entry.Protections)
	}

	entry = entryFor(t, result, sideBranch)
	if entry.Git.UnpublishedCommits != 1 || !hasProtection(entry, core.ProtectUnpublishedCommits) {
		t.Errorf("an unpushed commit on another branch is not protected: state %+v protections %+v", entry.Git, entry.Protections)
	}
}

// Removing a linked worktree keeps its repository's branches, so only the
// worktree's own HEAD decides publication.
func TestLinkedWorktreePublicationIsJudgedByItsHead(t *testing.T) {
	requireGit(t)
	home := t.TempDir()
	root := t.TempDir()
	repo := pushedRepo(t, home, root, "app")

	pushed := filepath.Join(root, "app-wt-pushed")
	git(t, home, repo, "worktree", "add", pushed, "main~0", "--detach")

	unpushed := filepath.Join(root, "app-wt-unpushed")
	git(t, home, repo, "worktree", "add", unpushed, "-b", "feature")
	mustWrite(t, filepath.Join(unpushed, "feature.txt"), "feature\n")
	git(t, home, unpushed, "add", "feature.txt")
	git(t, home, unpushed, "commit", "-m", "feature work")
	// An unpushed branch elsewhere in the shared repository must not block
	// a worktree whose own HEAD is published.
	git(t, home, repo, "switch", "-c", "local-in-main")
	git(t, home, repo, "commit", "--allow-empty", "-m", "main-repo local commit")

	result := run(t, gitOptions(root))
	entry := entryFor(t, result, pushed)
	if !entry.Git.PublicationKnown || entry.Git.UnpublishedCommits != 0 || hasProtection(entry, core.ProtectUnpublishedCommits) {
		t.Errorf("published worktree state = %+v protections %+v, want publication known with nothing unpublished", entry.Git, entry.Protections)
	}
	entry = entryFor(t, result, unpushed)
	if entry.Git.UnpublishedCommits != 1 || !hasProtection(entry, core.ProtectUnpublishedCommits) {
		t.Errorf("worktree with an unpushed HEAD commit: state %+v protections %+v, want protected", entry.Git, entry.Protections)
	}
}

// A worktree's last activity is its newest checkout, staging, or commit,
// read from the linked Git directory rather than the checkout alone.
func TestLinkedWorktreeRecordsLastGitActivity(t *testing.T) {
	requireGit(t)
	home := t.TempDir()
	root := t.TempDir()
	repo := pushedRepo(t, home, root, "app")
	wt := filepath.Join(root, "app-wt")
	git(t, home, repo, "worktree", "add", wt, "--detach")
	old := time.Now().Add(-30 * 24 * time.Hour)
	gitDir := filepath.Join(repo, ".git", "worktrees", "app-wt")
	for _, p := range []string{wt, filepath.Join(gitDir, "HEAD"), filepath.Join(gitDir, "index"), filepath.Join(gitDir, "logs", "HEAD")} {
		if err := os.Chtimes(p, old, old); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	entry := entryFor(t, run(t, gitOptions(root)), wt)
	if got := entry.Git.LastActivity; got.IsZero() || got.After(old.Add(time.Minute)) {
		t.Fatalf("idle worktree last activity = %v, want about %v", got, old)
	}
	recent := time.Now()
	if err := os.Chtimes(filepath.Join(gitDir, "index"), recent, recent); err != nil {
		t.Fatal(err)
	}
	entry = entryFor(t, run(t, gitOptions(root)), wt)
	if entry.Git.LastActivity.Before(recent.Add(-time.Minute)) {
		t.Fatalf("staging in the worktree did not count as activity: %v", entry.Git.LastActivity)
	}
}
