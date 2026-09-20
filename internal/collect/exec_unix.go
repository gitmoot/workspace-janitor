//go:build unix

package collect

import (
	"os/exec"
	"syscall"
)

// configureProcessGroup puts the command in its own process group and kills
// the whole group on cancellation.
//
// Killing only the direct child is not enough: a child that spawned its own
// children leaves them holding the inherited output pipe, and Wait then
// blocks until they exit — which is exactly the hang the timeout exists to
// prevent.
func configureProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
