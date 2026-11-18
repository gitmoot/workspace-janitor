//go:build linux

package cli

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

// notifyWaitDelay bounds how long a notify command's output pipes are
// drained after it exits or is killed: a descendant holding them open
// cannot hold the notifier.
const notifyWaitDelay = 2 * time.Second

// runNotifyCommand runs argv in its own process group, as
// executeOfficialPrune does, killing the whole group at limit and once the
// command has finished, so no descendant outlives the run. It returns the
// combined output and the run's error.
func runNotifyCommand(ctx context.Context, argv []string, limit time.Duration) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	cmd := exec.CommandContext(bounded, argv[0], argv[1:]...)
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = notifyWaitDelay
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	err := cmd.Wait()
	// The leader is reaped; the group lives on only in descendants.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if bounded.Err() == context.DeadlineExceeded {
		return out.Bytes(), fmt.Errorf("notify command exceeded %s: %w", limit, bounded.Err())
	}
	return out.Bytes(), err
}
