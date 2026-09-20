package collect

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// maxCommBytes bounds the process name read from procfs.
const maxCommBytes = 256

// gatherProcessReferences reads the working directory and executable of
// every visible process from procfs.
//
// Only the "cwd", "exe", and "comm" entries are read. The command line and
// the environment are deliberately not read: both routinely carry
// credentials, and neither is needed to know that a path is in use.
//
// A process this run may not inspect is counted as an unknown, which makes
// the report partial. A partial process collector can never be read as
// "nothing is using these paths".
func gatherProcessReferences(ctx context.Context, opts *Options) ([]Reference, core.CollectorReport) {
	report := core.CollectorReport{Name: CollectorProcesses, Status: core.CollectorRan}
	if !opts.Processes {
		report.Status = core.CollectorSkipped
		report.Detail = "process collection disabled"
		return nil, report
	}
	if _, err := os.Stat(opts.ProcRoot); err != nil {
		report.Status = core.CollectorSkipped
		report.Detail = fmt.Sprintf("%s is unavailable: %v", opts.ProcRoot, err)
		return nil, report
	}

	names, err := readDirNamesBounded(opts.ProcRoot, opts.Limits.MaxDirEntries)
	if err != nil {
		report.Status = core.CollectorFailed
		report.Detail = fmt.Sprintf("list %s: %v", opts.ProcRoot, err)
		return nil, report
	}
	if names.bounded {
		report.Status = core.CollectorPartial
	}

	var refs []Reference
	for _, name := range names.names {
		if err := ctx.Err(); err != nil {
			report.Status = core.CollectorPartial
			report.Detail = err.Error()
			return refs, report
		}
		if _, err := strconv.Atoi(name); err != nil {
			continue
		}
		report.Visited++
		procDir := filepath.Join(opts.ProcRoot, name)
		comm := processName(procDir)

		for _, link := range []struct {
			file   string
			signal string
			label  string
		}{
			{"cwd", "process_cwd", "working directory"},
			{"exe", "process_exe", "executable"},
		} {
			target, err := os.Readlink(filepath.Join(procDir, link.file))
			if err != nil {
				if os.IsNotExist(err) {
					// The process exited between listing and reading. That
					// is not an unknown: it holds nothing now.
					continue
				}
				report.Unknowns++
				report.Status = core.CollectorPartial
				continue
			}
			if !filepath.IsAbs(target) {
				continue
			}
			refs = append(refs, Reference{
				Path:       filepath.Clean(target),
				Source:     core.SourceProcess,
				Protection: core.ProtectActiveProcess,
				Signal:     link.signal,
				Detail:     fmt.Sprintf("pid %s (%s) %s", name, comm, link.label),
			})
		}
	}

	if report.Detail == "" {
		report.Detail = fmt.Sprintf("inspected %d process(es) under %s; %d unreadable",
			report.Visited, opts.ProcRoot, report.Unknowns)
	}
	return refs, report
}

// processName reads the short process name, which carries no arguments and
// therefore no secrets.
func processName(procDir string) string {
	f, err := os.Open(filepath.Join(procDir, "comm"))
	if err != nil {
		return "unknown"
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxCommBytes))
	if err != nil {
		return "unknown"
	}
	name := strings.TrimSpace(string(data))
	if name == "" {
		return "unknown"
	}
	return name
}

// gatherAgentReferences asks every registered-agent adapter which
// directories its agents occupy.
func gatherAgentReferences(ctx context.Context, opts *Options) ([]Reference, core.CollectorReport) {
	report := core.CollectorReport{Name: CollectorAgents, Status: core.CollectorRan}
	if len(opts.AgentSources) == 0 {
		report.Status = core.CollectorSkipped
		report.Detail = "no registered-agent source is configured"
		return nil, report
	}

	var (
		refs    []Reference
		details []string
	)
	for _, source := range opts.AgentSources {
		report.Visited++
		dirs, err := askAgentSource(ctx, source, opts.Limits.CommandTimeout)
		if err != nil {
			report.Unknowns++
			report.Status = core.CollectorPartial
			details = append(details, fmt.Sprintf("%s: %v", source.Name(), err))
			continue
		}
		for _, dir := range dirs {
			if !filepath.IsAbs(dir.Path) {
				report.Unknowns++
				report.Status = core.CollectorPartial
				details = append(details, fmt.Sprintf("%s: non-absolute path %q", source.Name(), dir.Path))
				continue
			}
			detail := fmt.Sprintf("agent %s registered by %s", dir.Agent, source.Name())
			if dir.Detail != "" {
				detail += ": " + dir.Detail
			}
			refs = append(refs, Reference{
				Path:       filepath.Clean(dir.Path),
				Source:     core.SourceJob,
				Protection: core.ProtectRegisteredAgent,
				Signal:     "agent_directory",
				Detail:     detail,
			})
		}
	}

	if len(details) > 0 {
		report.Detail = strings.Join(details, "; ")
	} else {
		report.Detail = fmt.Sprintf("%d source(s) reported %d directory reference(s)", report.Visited, len(refs))
	}
	return refs, report
}

// askAgentSource queries one adapter under a deadline.
//
// The adapter is third-party code. Passing it a cancellable context is not
// enough — an adapter that ignores cancellation would still block the scan —
// so the call runs on its own goroutine and the deadline is enforced here.
// A late answer is discarded rather than awaited.
func askAgentSource(ctx context.Context, source AgentSource, timeout time.Duration) ([]AgentRef, error) {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type answer struct {
		dirs []AgentRef
		err  error
	}
	// Buffered so an adapter that answers after the deadline does not leak a
	// blocked goroutine.
	done := make(chan answer, 1)
	go func() {
		dirs, err := source.ActiveDirectories(callCtx)
		done <- answer{dirs: dirs, err: err}
	}()

	select {
	case result := <-done:
		return result.dirs, result.err
	case <-callCtx.Done():
		return nil, fmt.Errorf("did not answer within the %s command timeout", timeout)
	}
}
