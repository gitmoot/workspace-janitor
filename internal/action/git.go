package action

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	gitCommandTimeout = 10 * time.Second
	maxGitOutput      = 64 << 10
	maxGitPointer     = 4096
)

// MoveLinkedWorktree moves a registered linked worktree using Git, so Git's
// administrative records and both sides of the .git link move together.
// The caller must independently recheck the filesystem identity and policy.
func MoveLinkedWorktree(ctx context.Context, owner, from, to string) error {
	if err := validGitPath(to); err != nil {
		return fmt.Errorf("destination: %w", err)
	}
	if from == to {
		return errors.New("source and destination are the same")
	}
	rootMetadata, err := captureGitMetadata(from)
	if err != nil {
		return fmt.Errorf("capture worktree metadata: %w", err)
	}
	gitfileMetadata, err := captureGitMetadata(filepath.Join(from, ".git"))
	if err != nil {
		return fmt.Errorf("capture worktree gitfile metadata: %w", err)
	}
	if _, err := inspectLinkedWorktree(ctx, owner, from); err != nil {
		return err
	}
	if _, err := os.Lstat(to); err == nil {
		return fmt.Errorf("destination %q already exists", to)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect destination %q: %w", to, err)
	}
	if err := gitDirectory(filepath.Dir(to)); err != nil {
		return fmt.Errorf("destination parent: %w", err)
	}
	if _, err := runLocalGit(ctx, owner, "worktree", "move", "--", from, to); err != nil {
		return fmt.Errorf("move linked worktree: %w", err)
	}
	if _, err := inspectLinkedWorktree(ctx, owner, to); err != nil {
		return fmt.Errorf("verify moved linked worktree: %w", err)
	}
	if err := restoreGitMetadata(filepath.Join(to, ".git"), gitfileMetadata); err != nil {
		return fmt.Errorf("preserve moved worktree gitfile metadata: %w", err)
	}
	if err := restoreGitMetadata(to, rootMetadata); err != nil {
		return fmt.Errorf("preserve moved worktree directory metadata: %w", err)
	}
	return nil
}

// VerifyLinkedWorktree checks that path is a live, unlocked linked worktree
// registered to owner, with matching forward and reverse Git metadata links.
func VerifyLinkedWorktree(ctx context.Context, owner, path string) error {
	_, err := inspectLinkedWorktree(ctx, owner, path)
	return err
}

func inspectLinkedWorktree(ctx context.Context, owner, path string) (string, error) {
	if err := validGitPath(owner); err != nil {
		return "", fmt.Errorf("owner: %w", err)
	}
	if err := validGitPath(path); err != nil {
		return "", fmt.Errorf("worktree: %w", err)
	}
	if owner == path {
		return "", errors.New("owner is not a linked worktree")
	}
	if err := gitDirectory(owner); err != nil {
		return "", fmt.Errorf("owner: %w", err)
	}
	if err := gitDirectory(path); err != nil {
		return "", fmt.Errorf("worktree: %w", err)
	}

	bare, err := runLocalGit(ctx, owner, "rev-parse", "--is-bare-repository")
	if err != nil {
		return "", fmt.Errorf("inspect owner: %w", err)
	}
	common, err := runLocalGit(ctx, owner, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil {
		return "", fmt.Errorf("inspect owner common directory: %w", err)
	}
	common = strings.TrimSpace(common)
	if !filepath.IsAbs(common) || filepath.Clean(common) != common {
		return "", errors.New("owner has invalid Git common directory")
	}
	switch bare {
	case "true":
		if common != owner {
			return "", errors.New("owner is not the bare repository")
		}
	case "false":
		root, err := runLocalGit(ctx, owner, "rev-parse", "--show-toplevel")
		if err != nil {
			return "", fmt.Errorf("inspect owner root: %w", err)
		}
		if strings.TrimSpace(root) != owner || common != filepath.Join(owner, ".git") {
			return "", errors.New("owner is not the primary repository")
		}
	default:
		return "", errors.New("owner has invalid bare status")
	}
	if err := gitDirectory(common); err != nil {
		return "", fmt.Errorf("owner common directory: %w", err)
	}

	listing, err := runLocalGit(ctx, owner, "worktree", "list", "--porcelain", "-z")
	if err != nil {
		return "", fmt.Errorf("list registered worktrees: %w", err)
	}
	registered, err := registeredWorktree(listing, path)
	if err != nil {
		return "", err
	}
	if !registered {
		return "", fmt.Errorf("worktree %q is not registered to %q", path, owner)
	}

	pointer, err := readGitPointer(filepath.Join(path, ".git"), "gitdir: ")
	if err != nil {
		return "", err
	}
	if filepath.Dir(pointer) != filepath.Join(common, "worktrees") || filepath.Base(pointer) == "." {
		return "", errors.New("worktree gitfile does not point into owner's worktree records")
	}
	if err := gitDirectory(pointer); err != nil {
		return "", fmt.Errorf("worktree administrative directory: %w", err)
	}
	back, err := readGitPointer(filepath.Join(pointer, "gitdir"), "")
	if err != nil {
		return "", err
	}
	if back != filepath.Join(path, ".git") {
		return "", errors.New("worktree administrative gitdir does not point back to worktree")
	}
	for _, lock := range []string{filepath.Join(pointer, "locked"), filepath.Join(pointer, "index.lock"), filepath.Join(common, "index.lock")} {
		if _, err := os.Lstat(lock); err == nil {
			return "", fmt.Errorf("Git lock present: %s", lock)
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect Git lock %q: %w", lock, err)
		}
	}

	root, err := runLocalGit(ctx, path, "rev-parse", "--show-toplevel")
	if err != nil || strings.TrimSpace(root) != path {
		return "", fmt.Errorf("worktree cannot resolve its own root %q: %w", path, err)
	}
	gitDir, err := runLocalGit(ctx, path, "rev-parse", "--absolute-git-dir")
	if err != nil || strings.TrimSpace(gitDir) != pointer {
		return "", fmt.Errorf("worktree Git directory does not match gitfile: %w", err)
	}
	worktreeCommon, err := runLocalGit(ctx, path, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if err != nil || strings.TrimSpace(worktreeCommon) != common {
		return "", fmt.Errorf("worktree Git common directory does not match owner: %w", err)
	}
	return pointer, nil
}

func validGitPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("path %q must be absolute and normalized", path)
	}
	return nil
}

func gitDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if resolved != path {
		return fmt.Errorf("%q traverses a symlink", path)
	}
	return nil
}

func readGitPointer(path, prefix string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("inspect Git pointer %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxGitPointer {
		return "", fmt.Errorf("Git pointer %q is not a small regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxGitPointer+1))
	if err != nil || len(data) > maxGitPointer {
		return "", fmt.Errorf("read Git pointer %q: %v", path, err)
	}
	value := strings.TrimSuffix(string(data), "\n")
	if !strings.HasPrefix(value, prefix) || strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("malformed Git pointer %q", path)
	}
	value = strings.TrimPrefix(value, prefix)
	if !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return "", fmt.Errorf("Git pointer %q is not an absolute normalized path", path)
	}
	return value, nil
}

// Git's -z porcelain format delimits every field with NUL and every record
// with an empty field. Do not parse quoted, human-oriented worktree output.
func registeredWorktree(listing, path string) (bool, error) {
	if !strings.HasSuffix(listing, "\x00\x00") {
		return false, errors.New("malformed Git worktree listing")
	}
	found := false
	current := ""
	locked := false
	prunable := false
	for _, field := range strings.Split(strings.TrimSuffix(listing, "\x00"), "\x00") {
		if field == "" {
			if current == "" {
				return false, errors.New("malformed Git worktree record")
			}
			if current == path {
				if found {
					return false, errors.New("duplicate worktree registration")
				}
				found = true
				if locked || prunable {
					return false, fmt.Errorf("worktree %q is locked or prunable", path)
				}
			}
			current, locked, prunable = "", false, false
			continue
		}
		if current == "" {
			if !strings.HasPrefix(field, "worktree ") {
				return false, errors.New("malformed Git worktree record")
			}
			current = strings.TrimPrefix(field, "worktree ")
			if !filepath.IsAbs(current) || filepath.Clean(current) != current {
				return false, errors.New("malformed Git worktree path")
			}
		} else if field == "locked" || strings.HasPrefix(field, "locked ") {
			locked = true
		} else if field == "prunable" || strings.HasPrefix(field, "prunable ") {
			prunable = true
		}
	}
	return found, nil
}

type boundedGitOutput struct{ bytes.Buffer }

func (b *boundedGitOutput) Write(p []byte) (int, error) {
	if b.Len() >= maxGitOutput {
		return len(p), nil
	}
	remaining := maxGitOutput - b.Len()
	if len(p) > remaining {
		_, _ = b.Buffer.Write(p[:remaining])
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// runLocalGit passes only fixed local subcommands from this package. Its
// environment discards inherited GIT_* settings, hooks, credential helpers,
// and user/system config; no invocation can contact a remote.
func runLocalGit(ctx context.Context, dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, gitCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir, "--no-optional-locks"}, args...)...)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=/nonexistent",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=true",
		"LC_ALL=C",
	}
	cmd.WaitDelay = time.Second
	var stdout, stderr boundedGitOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), ctx.Err())
	}
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	if stdout.Len() == maxGitOutput || stderr.Len() == maxGitOutput {
		return "", fmt.Errorf("git %s output exceeded limit", strings.Join(args, " "))
	}
	return strings.TrimSuffix(stdout.String(), "\n"), nil
}
