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

// maxCmdlineBytes bounds the command line read from an OMP process.
const maxCmdlineBytes = 64 << 10

// ProcessWorkdir is a live process whose working directory lies within one
// of the paths ProcessWorkdirs was asked about.
type ProcessWorkdir struct {
	PID string
	Cwd string
	// Name is the process's short name (comm).
	Name string
	// OMPSession is the session directory name of an OMP process resumed
	// from a session file, else "".
	OMPSession string
}

// ProcessWorkdirs lists the live processes whose working directory is one of
// within or inside one, under the process collector's bounds: at most
// limits.max_dir_entries processes, within limits.command_timeout and ctx.
// A report other than ran means some processes were not observed.
//
// Like the process collector it reads cwd, exe and comm. The command line of
// a process inside within is read, bounded and without blocking on a
// non-regular file, and decoded only once its executable or argv[0] names
// OMP; only the session directory name is kept.
func ProcessWorkdirs(ctx context.Context, opts Options, within []string) ([]ProcessWorkdir, core.CollectorReport) {
	return runBoundedFor(ctx, &opts, CollectorProcesses, opts.Limits.CommandTimeout, "command timeout",
		func(ctx context.Context, opts *Options) ([]ProcessWorkdir, core.CollectorReport) {
			return gatherProcessWorkdirs(ctx, opts, within)
		})
}

func gatherProcessWorkdirs(ctx context.Context, opts *Options, within []string) ([]ProcessWorkdir, core.CollectorReport) {
	report := core.CollectorReport{Name: CollectorProcesses, Status: core.CollectorRan}
	names, err := readDirNamesBounded(opts.ProcRoot, opts.Limits.MaxDirEntries)
	if err != nil {
		report.Status = core.CollectorFailed
		report.Detail = fmt.Sprintf("list %s: %v", opts.ProcRoot, err)
		return nil, report
	}
	if names.bounded {
		report.Status = core.CollectorPartial
	}
	var found []ProcessWorkdir
	for _, name := range names.names {
		if err := ctx.Err(); err != nil {
			report.Status = core.CollectorPartial
			report.Detail = err.Error()
			return found, report
		}
		if _, err := strconv.Atoi(name); err != nil {
			continue
		}
		procDir := filepath.Join(opts.ProcRoot, name)
		cwd, err := os.Readlink(filepath.Join(procDir, "cwd"))
		if os.IsNotExist(err) {
			continue // exited: it holds nothing now
		}
		report.Visited++
		if err != nil {
			report.Unknowns++
			report.Status = core.CollectorPartial
			continue
		}
		if !filepath.IsAbs(cwd) {
			continue
		}
		cwd = filepath.Clean(cwd)
		inside := false
		for _, path := range within {
			inside = inside || core.PathWithin(cwd, path)
		}
		if !inside {
			continue
		}
		process := ProcessWorkdir{PID: name, Cwd: cwd, Name: processName(procDir)}
		process.OMPSession = ompSession(procDir)
		found = append(found, process)
	}
	if report.Detail == "" {
		report.Detail = fmt.Sprintf("inspected %d process(es) under %s; %d unreadable", report.Visited, opts.ProcRoot, report.Unknowns)
		if names.bounded {
			report.Detail += fmt.Sprintf("; listing truncated at %d", opts.Limits.MaxDirEntries)
		}
	}
	return found, report
}

// ompSession is the session directory name of an OMP process started with
// --resume=<session.jsonl>, or "" when the process is not OMP or resumes no
// session file. Another program's --resume argument means nothing here.
func ompSession(procDir string) string {
	exe, _ := os.Readlink(filepath.Join(procDir, "exe"))
	cmdline, err := readFileBounded(filepath.Join(procDir, "cmdline"), maxCmdlineBytes)
	if err != nil {
		return ""
	}
	argv := strings.Split(strings.TrimRight(cmdline, "\x00"), "\x00")
	if filepath.Base(exe) != "omp" && filepath.Base(argv[0]) != "omp" {
		return ""
	}
	for i, arg := range argv[1:] {
		session, ok := strings.CutPrefix(arg, "--resume=")
		if !ok && arg == "--resume" && i+2 < len(argv) {
			session, ok = argv[i+2], true
		}
		if ok && filepath.IsAbs(session) && strings.HasSuffix(session, ".jsonl") {
			return filepath.Base(filepath.Dir(session))
		}
	}
	return ""
}
