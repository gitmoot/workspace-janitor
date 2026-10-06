//go:build linux

package collect

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The external Git boundary must not turn a partial/oversized listing into a
// successful proof or let an unbounded producer hold collection indefinitely.
func TestWorktreeContentsGitListingFailsClosed(t *testing.T) {
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Skip(err)
	}
	for _, scenario := range []string{"overflow", "incomplete", "timeout"} {
		t.Run(scenario, func(t *testing.T) {
			home, root := t.TempDir(), t.TempDir()
			repo := newRepo(t, home, filepath.Join(root, "app"))
			command := "printf '100644 invalid 0\\tREADME.md'"
			if scenario == "overflow" {
				command = "dd if=/dev/zero bs=1048576 count=17 2>/dev/null"
			}
			if scenario == "timeout" {
				command = "sleep 10"
			}
			wrapper := filepath.Join(home, "git-wrapper")
			script := "#!/bin/sh\ncase \" $* \" in *\" ls-files \"*) " + command + "; exit 0;; esac\nexec " + realGit + " \"$@\"\n"
			if err := os.WriteFile(wrapper, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			opts := gitOptions(root)
			opts.GitBinary = wrapper
			opts.Limits.GitTimeout = time.Second
			entry := entryFor(t, run(t, opts), repo)
			if entry.Git == nil || !entry.Git.Degraded {
				t.Fatal("incomplete bounded Git evidence was accepted as safe")
			}
		})
	}
}
