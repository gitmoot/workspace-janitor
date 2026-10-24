package collect

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// Only descriptor link targets in explicitly owned export scopes are retained.
// Arguments, environments and file contents remain unread. Our own archive
// verification descriptors are not external consumers.
func exportProcessReferences(ctx context.Context, opts *Options, pid, procDir string) ([]Reference, bool) {
	if opts.WorktreePolicy == nil || len(opts.WorktreePolicy.EvidenceExports) == 0 || pid == strconv.Itoa(os.Getpid()) {
		return nil, false
	}
	var refs []Reference
	seen := uint64(0)
	add := func(target, signal string) {
		target = strings.TrimSuffix(target, " (deleted)")
		if !filepath.IsAbs(target) {
			return
		}
		original := target
		if source, ok := opts.WorktreeOrigins[target]; ok {
			original = source
		}
		for i, rule := range opts.WorktreePolicy.EvidenceExports {
			if !core.PathWithin(original, rule.SourceContainer) {
				continue
			}
			path := rule.Path
			if seen&(uint64(1)<<i) != 0 {
				continue
			}
			seen |= uint64(1) << i
			for actual, source := range opts.WorktreeOrigins {
				if source == rule.Path {
					path = actual
					break
				}
			}
			refs = append(refs, Reference{Path: path, Source: core.SourceProcess, Protection: core.ProtectActiveProcess, Signal: signal, Detail: fmt.Sprintf("pid %s uses the owner-defined export container", pid)})
		}
	}
	if cwd, err := os.Readlink(filepath.Join(procDir, "cwd")); err == nil {
		add(cwd, "export_process_cwd")
	}
	descriptors, err := readDirNamesBounded(filepath.Join(procDir, "fd"), opts.Limits.MaxDirEntries)
	if err != nil {
		if os.IsNotExist(err) {
			if _, gone := os.Stat(procDir); os.IsNotExist(gone) {
				return refs, false
			}
		}
		return refs, true
	}
	unknown := descriptors.bounded
	for _, fd := range descriptors.names {
		if ctx.Err() != nil {
			return refs, true
		}
		target, err := os.Readlink(filepath.Join(procDir, "fd", fd))
		if err != nil {
			if !os.IsNotExist(err) {
				unknown = true
			}
			continue
		}
		add(target, "export_open_descriptor")
	}
	return refs, unknown
}
