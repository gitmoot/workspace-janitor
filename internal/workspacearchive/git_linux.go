//go:build linux

package workspacearchive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const maxGitOutput = 64 << 10

type boundedBuffer struct{ bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if remaining := maxGitOutput - b.Len(); remaining < len(p) {
		if remaining > 0 {
			_, _ = b.Buffer.Write(p[:remaining])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// runGit runs one fixed local subcommand. Inherited GIT_* settings, hooks,
// credential helpers and user/system config are discarded; nothing contacts a
// remote. extra, when set, is visible to Git as /proc/self/fd/3.
func runGit(ctx context.Context, dir string, stdout io.Writer, extra *os.File, args ...string) (string, error) {
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
	var out, stderr boundedBuffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if stdout != nil {
		cmd.Stdout = stdout
	}
	if extra != nil {
		cmd.ExtraFiles = []*os.File{extra}
	}
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), ctx.Err())
	}
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	if stdout == nil && out.Len() >= maxGitOutput {
		return "", fmt.Errorf("git %s output exceeded limit", strings.Join(args, " "))
	}
	return strings.TrimSpace(out.String()), nil
}

const extraFilePath = "/proc/self/fd/3"

// createBundle writes a bundle of HEAD into stage exclusively, verifies it
// against the source repository and confirms it lists HEAD.
func createBundle(ctx context.Context, source, admin string, root, stage *os.File) (*Bundle, *os.File, error) {
	info, err := os.Stat(admin)
	if err != nil || !info.IsDir() {
		return nil, nil, fmt.Errorf("linked worktree admin entry %s is unavailable; history cannot be bundled", admin)
	}
	head, err := runGit(ctx, source, nil, nil, "rev-parse", "--verify", "HEAD")
	if err != nil {
		return nil, nil, err
	}
	file, err := createChild(stage, "history.bundle")
	if err != nil {
		return nil, nil, err
	}
	hash, count := sha256.New(), &countingWriter{}
	if _, err = runGit(ctx, source, io.MultiWriter(spaceWriter{root, 0, file}, hash, count), nil, "bundle", "create", "-", "HEAD"); err != nil {
		file.Close()
		return nil, nil, err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return nil, nil, err
	}
	b := &Bundle{Bytes: count.n, SHA256: hex.EncodeToString(hash.Sum(nil)), Head: head, WorktreeAdmin: admin}
	if _, err = runGit(ctx, source, nil, file, "bundle", "verify", extraFilePath); err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("worktree history bundle failed verification: %w", err)
	}
	if err = verifyBundle(ctx, file, b); err != nil {
		file.Close()
		return nil, nil, err
	}
	if _, err := os.Lstat(filepath.Join(admin, "locked")); err == nil {
		b.AdminLocked = true
	}
	return b, file, nil
}

// verifyBundle re-reads the bundle bytes and confirms Git lists the recorded
// HEAD. Listing heads needs no repository.
func verifyBundle(ctx context.Context, file *os.File, b *Bundle) error {
	st, err := fstate(file)
	if err != nil || st.size != b.Bytes || st.kind() != unix.S_IFREG {
		return errors.New("history bundle size changed")
	}
	digest, n, err := hashFile(ctx, file, b.Bytes)
	if err != nil || n != b.Bytes || digest != b.SHA256 {
		return errors.New("history bundle checksum mismatch")
	}
	heads, err := runGit(ctx, "/", nil, file, "bundle", "list-heads", extraFilePath)
	if err != nil {
		return fmt.Errorf("history bundle cannot be listed: %w", err)
	}
	for _, line := range strings.Split(heads, "\n") {
		if sha, ref, _ := strings.Cut(strings.TrimSpace(line), " "); sha == b.Head && ref == "HEAD" {
			return nil
		}
	}
	return errors.New("history bundle does not contain the recorded HEAD")
}

func hashFile(ctx context.Context, file *os.File, limit int64) (string, int64, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	n, err := io.Copy(hash, contextReader{ctx, io.LimitReader(file, limit+1)})
	return hex.EncodeToString(hash.Sum(nil)), n, err
}
