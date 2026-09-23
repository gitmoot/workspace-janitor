//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

func executeOfficialPrune(ctx context.Context, argv []string, limit time.Duration) error {
	if len(argv) < 2 || limit <= 0 {
		return errors.New("invalid official command or timeout")
	}
	bounded, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	cmd := exec.CommandContext(bounded, argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, io.Discard, io.Discard
	// A provider cache command never needs the caller's credentials or network.
	// Explicit root and offline settings make the invocation reproducible.
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.TempDir(), "TMPDIR=" + os.TempDir(), "CI=1",
		"UV_OFFLINE=1", "npm_config_offline=true",
		"npm_config_userconfig=/dev/null", "npm_config_globalconfig=/dev/null",
	}
	if err := cmd.Run(); err != nil {
		if bounded.Err() != nil {
			return fmt.Errorf("official prune exceeded %s: %w", limit, bounded.Err())
		}
		return fmt.Errorf("official prune failed: %w", err)
	}
	if bounded.Err() != nil {
		return fmt.Errorf("official prune exceeded %s: %w", limit, bounded.Err())
	}
	return nil
}

func recordOfficialPrune(stateDir string, report pruneReport) error {
	path := filepath.Join(stateDir, "official-prunes.jsonl")
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_APPEND|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("official prune journal busy: %w", err)
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	info, err := file.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Nlink != 1 || st.Uid != uint32(os.Getuid()) || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("official prune journal has unsafe ownership or permissions")
	}
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	dir, err := os.Open(stateDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func lockOfficialPrune(stateDir string) (func(), error) {
	path := filepath.Join(stateDir, "official-prunes.lock")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return func() { syscall.Flock(fd, syscall.LOCK_UN); syscall.Close(fd) }, nil
}
