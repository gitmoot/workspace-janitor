//go:build !unix

package collect

import "os/exec"

// configureProcessGroup is a no-op on platforms without process groups. The
// command still stops at its deadline through the context and WaitDelay.
func configureProcessGroup(*exec.Cmd) {}
