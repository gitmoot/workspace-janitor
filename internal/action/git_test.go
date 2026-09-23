package action

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureGit(t *testing.T, home, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=Fixture",
		"GIT_AUTHOR_EMAIL=fixture@example.invalid",
		"GIT_COMMITTER_NAME=Fixture",
		"GIT_COMMITTER_EMAIL=fixture@example.invalid",
		"LC_ALL=C",
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

func linkedFixture(t *testing.T) (owner, linked, destination, home string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git unavailable: %v", err)
	}
	root := t.TempDir()
	home = t.TempDir()
	owner = filepath.Join(root, "owner")
	linked = filepath.Join(root, "linked")
	destination = filepath.Join(root, "moved")
	if err := os.Mkdir(owner, 0700); err != nil {
		t.Fatal(err)
	}
	fixtureGit(t, home, owner, "init", "--initial-branch=main")
	if err := os.WriteFile(filepath.Join(owner, "README"), []byte("fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fixtureGit(t, home, owner, "add", "README")
	fixtureGit(t, home, owner, "commit", "-m", "initial")
	fixtureGit(t, home, owner, "worktree", "add", "-b", "feature", linked)
	return owner, linked, destination, home
}

func TestMoveLinkedWorktreeMaintainsGitLinks(t *testing.T) {
	owner, linked, destination, home := linkedFixture(t)
	ctx := context.Background()
	// Git should move the directory and gitfile without replacing either;
	// root and gitfile metadata are part of the quarantined artifact.
	mtime := time.Unix(1_600_000_000, 123_456_789)
	for _, path := range []string{linked, filepath.Join(linked, ".git")} {
		if err := os.Chmod(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	rootBefore, err := os.Lstat(linked)
	if err != nil {
		t.Fatal(err)
	}
	gitfileBefore, err := os.Lstat(filepath.Join(linked, ".git"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyLinkedWorktree(ctx, owner, linked); err != nil {
		t.Fatalf("verify initial linked worktree: %v", err)
	}
	if err := MoveLinkedWorktree(ctx, owner, linked, destination); err != nil {
		t.Fatalf("move linked worktree: %v", err)
	}
	if _, err := os.Lstat(linked); !os.IsNotExist(err) {
		t.Fatalf("original path remains: %v", err)
	}
	if err := VerifyLinkedWorktree(ctx, owner, destination); err != nil {
		t.Fatalf("verify moved linked worktree: %v", err)
	}
	for _, check := range []struct {
		path   string
		before os.FileInfo
	}{
		{destination, rootBefore},
		{filepath.Join(destination, ".git"), gitfileBefore},
	} {
		after, err := os.Lstat(check.path)
		if err != nil {
			t.Fatal(err)
		}
		if after.Mode() != check.before.Mode() || !after.ModTime().Equal(check.before.ModTime()) {
			t.Errorf("%s metadata changed: mode %v -> %v, mtime %v -> %v",
				check.path, check.before.Mode(), after.Mode(), check.before.ModTime(), after.ModTime())
		}
	}
	if root := fixtureGit(t, home, destination, "rev-parse", "--show-toplevel"); root != destination {
		t.Fatalf("moved repository root = %q, want %q", root, destination)
	}
	if status := fixtureGit(t, home, destination, "status", "--porcelain"); status != "" {
		t.Fatalf("moved repository is dirty: %q", status)
	}
	if err := MoveLinkedWorktree(ctx, owner, destination, linked); err != nil {
		t.Fatalf("restore linked worktree: %v", err)
	}
	if err := VerifyLinkedWorktree(ctx, owner, linked); err != nil {
		t.Fatalf("verify restored worktree: %v", err)
	}
}

func TestMoveLinkedWorktreeWithBareOwner(t *testing.T) {
	owner, linked, destination, home := linkedFixture(t)
	bare := filepath.Join(filepath.Dir(owner), "bare.git")
	fixtureGit(t, home, filepath.Dir(owner), "clone", "--bare", owner, bare)
	bareLinked := filepath.Join(filepath.Dir(owner), "bare-linked")
	fixtureGit(t, home, bare, "worktree", "add", "-b", "bare-feature", bareLinked, "main")
	if err := VerifyLinkedWorktree(context.Background(), bare, bareLinked); err != nil {
		t.Fatalf("verify worktree with bare owner: %v", err)
	}
	if err := MoveLinkedWorktree(context.Background(), bare, bareLinked, destination); err != nil {
		t.Fatalf("move worktree with bare owner: %v", err)
	}
	if err := VerifyLinkedWorktree(context.Background(), bare, destination); err != nil {
		t.Fatalf("verify moved worktree with bare owner: %v", err)
	}
	if err := VerifyLinkedWorktree(context.Background(), owner, destination); err == nil {
		t.Fatal("unrelated owner accepted another repository's linked worktree")
	}
	if err := VerifyLinkedWorktree(context.Background(), owner, linked); err != nil {
		t.Fatalf("original owner's worktree changed: %v", err)
	}
}

func TestMoveLinkedWorktreeRefusesLockedAndOccupiedDestination(t *testing.T) {
	owner, linked, destination, home := linkedFixture(t)
	ctx := context.Background()
	fixtureGit(t, home, owner, "worktree", "lock", linked)
	if err := VerifyLinkedWorktree(ctx, owner, linked); err == nil {
		t.Fatal("locked worktree was accepted")
	}
	if err := MoveLinkedWorktree(ctx, owner, linked, destination); err == nil {
		t.Fatal("locked worktree was moved")
	}
	fixtureGit(t, home, owner, "worktree", "unlock", linked)
	if err := os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	if err := MoveLinkedWorktree(ctx, owner, linked, destination); err == nil {
		t.Fatal("occupied destination was accepted")
	}
	if err := VerifyLinkedWorktree(ctx, owner, linked); err != nil {
		t.Fatalf("source registration changed after refusals: %v", err)
	}
}

func TestMoveLinkedWorktreeRefusesUnregisteredAndBrokenMetadata(t *testing.T) {
	owner, linked, destination, _ := linkedFixture(t)
	ctx := context.Background()
	unregistered := filepath.Join(filepath.Dir(linked), "unregistered")
	if err := os.Mkdir(unregistered, 0700); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLinkedWorktree(ctx, owner, unregistered); err == nil {
		t.Fatal("unregistered worktree was accepted")
	}
	if err := MoveLinkedWorktree(ctx, owner, unregistered, destination); err == nil {
		t.Fatal("unregistered worktree was moved")
	}
	gitfile := filepath.Join(linked, ".git")
	if err := os.WriteFile(gitfile, []byte("gitdir: /nonexistent/gitdir\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLinkedWorktree(ctx, owner, linked); err == nil {
		t.Fatal("broken gitfile was accepted")
	}
	if err := MoveLinkedWorktree(ctx, owner, linked, destination); err == nil {
		t.Fatal("broken gitfile was moved")
	}
}
