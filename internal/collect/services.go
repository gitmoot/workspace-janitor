package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// Bounds for the small definition files the reference collectors parse.
const (
	maxUnitFileBytes = 256 << 10
	maxCronFileBytes = 256 << 10
	maxPM2DumpBytes  = 4 << 20
)

// gatherServiceReferences collects paths referenced by systemd units, cron
// tables, and PM2 process dumps.
//
// These collectors read configuration files, so they are deliberately
// narrow: only directives that name a path are interpreted. Environment
// directives and assignments are skipped without being read into evidence,
// because their values routinely hold credentials and are never needed to
// establish that a path is referenced.
func gatherServiceReferences(ctx context.Context, opts *Options) ([]Reference, core.CollectorReport) {
	report := core.CollectorReport{Name: CollectorServices, Status: core.CollectorRan}
	if !opts.Services {
		report.Status = core.CollectorSkipped
		report.Detail = "service collection disabled"
		return nil, report
	}
	sources := opts.ServiceSources
	if len(sources.SystemdDirs) == 0 && len(sources.CronPaths) == 0 && len(sources.PM2Dumps) == 0 {
		report.Status = core.CollectorSkipped
		report.Detail = "no service definition locations are configured"
		return nil, report
	}

	var refs []Reference
	for _, gather := range []func(context.Context, *Options, *core.CollectorReport) []Reference{
		gatherSystemd,
		gatherCron,
		gatherPM2,
	} {
		if err := ctx.Err(); err != nil {
			report.Status = core.CollectorPartial
			report.Detail = err.Error()
			return refs, report
		}
		refs = append(refs, gather(ctx, opts, &report)...)
	}

	report.Detail = appendDetail(
		fmt.Sprintf("inspected %d definition(s); %d unreadable", report.Visited, report.Unknowns),
		report.Detail)
	return refs, report
}

func gatherSystemd(ctx context.Context, opts *Options, report *core.CollectorReport) []Reference {
	var refs []Reference
	for _, dir := range opts.ServiceSources.SystemdDirs {
		if ctx.Err() != nil {
			return refs
		}
		names, err := readDirNamesBounded(dir, opts.Limits.MaxDirEntries)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			noteUnreadable(report, fmt.Sprintf("could not list %s: %v", dir, err))
			continue
		}
		if names.bounded {
			// Units past the bound were not read, so their references are
			// unknown; a truncated listing must not read as "no more units".
			noteUnreadable(report, fmt.Sprintf("listing of %s was truncated at %d entries", dir, opts.Limits.MaxDirEntries))
		}
		for _, name := range names.names {
			if ctx.Err() != nil {
				return refs
			}
			if !strings.HasSuffix(name, ".service") {
				continue
			}
			path := filepath.Join(dir, name)
			content, err := readFileBounded(path, maxUnitFileBytes)
			if err != nil {
				noteUnreadable(report, fmt.Sprintf("could not read %s: %v", path, err))
				continue
			}
			report.Visited++
			refs = append(refs, systemdUnitReferences(name, content)...)
		}
	}
	return refs
}

// systemdUnitReferences extracts path-valued directives from a unit file.
func systemdUnitReferences(unit, content string) []Reference {
	var refs []Reference
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "WorkingDirectory":
			if path := firstAbsolutePath(value); path != "" {
				refs = append(refs, Reference{
					Path:       path,
					Source:     core.SourceService,
					Protection: core.ProtectServiceReference,
					Signal:     "systemd_working_directory",
					Detail:     fmt.Sprintf("systemd unit %s WorkingDirectory", unit),
				})
			}
		case "ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload":
			if path := firstAbsolutePath(value); path != "" {
				refs = append(refs, Reference{
					Path:       path,
					Source:     core.SourceService,
					Protection: core.ProtectServiceReference,
					Signal:     "systemd_exec",
					Detail:     fmt.Sprintf("systemd unit %s %s", unit, key),
				})
			}
		default:
			// Environment and EnvironmentFile intentionally fall here: their
			// values are never read.
		}
	}
	return refs
}

func gatherCron(ctx context.Context, opts *Options, report *core.CollectorReport) []Reference {
	var refs []Reference
	for _, target := range opts.ServiceSources.CronPaths {
		if ctx.Err() != nil {
			return refs
		}
		info, err := os.Stat(target)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			noteUnreadable(report, fmt.Sprintf("could not stat %s: %v", target, err))
			continue
		}
		files := []string{target}
		if info.IsDir() {
			names, err := readDirNamesBounded(target, opts.Limits.MaxDirEntries)
			if err != nil {
				noteUnreadable(report, fmt.Sprintf("could not list %s: %v", target, err))
				continue
			}
			if names.bounded {
				noteUnreadable(report, fmt.Sprintf("listing of %s was truncated at %d entries", target, opts.Limits.MaxDirEntries))
			}
			files = files[:0]
			for _, name := range names.names {
				files = append(files, filepath.Join(target, name))
			}
		}
		for _, file := range files {
			if ctx.Err() != nil {
				return refs
			}
			content, err := readFileBounded(file, maxCronFileBytes)
			if err != nil {
				noteUnreadable(report, fmt.Sprintf("could not read %s: %v", file, err))
				continue
			}
			report.Visited++
			refs = append(refs, cronReferences(file, content)...)
		}
	}
	return refs
}

// cronReferences extracts absolute paths from crontab command fields.
func cronReferences(file, content string) []Reference {
	var refs []Reference
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// A crontab assignment such as "SECRET=value" is an environment
		// value: skip the whole line rather than parsing it.
		if name, _, found := strings.Cut(line, "="); found && isEnvName(strings.TrimSpace(name)) {
			continue
		}
		for _, field := range strings.Fields(line) {
			if !strings.HasPrefix(field, "/") {
				continue
			}
			refs = append(refs, Reference{
				Path:       filepath.Clean(field),
				Source:     core.SourceScheduler,
				Protection: core.ProtectServiceReference,
				Signal:     "cron_command_path",
				Detail:     "cron entry in " + file,
			})
		}
	}
	return refs
}

// isEnvName reports whether token looks like a shell variable name, which
// makes the line an assignment rather than a schedule.
func isEnvName(token string) bool {
	if token == "" || strings.ContainsAny(token, " \t/") {
		return false
	}
	for i, r := range token {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r == '_':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// pm2Dump is the subset of a PM2 dump this collector reads.
type pm2Dump []struct {
	Name   string `json:"name"`
	PM2Env struct {
		WorkingDir string `json:"pm_cwd"`
		ExecPath   string `json:"pm_exec_path"`
	} `json:"pm2_env"`
}

func gatherPM2(ctx context.Context, opts *Options, report *core.CollectorReport) []Reference {
	var refs []Reference
	for _, dump := range opts.ServiceSources.PM2Dumps {
		if ctx.Err() != nil {
			return refs
		}
		content, err := readFileBounded(dump, maxPM2DumpBytes)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			noteUnreadable(report, fmt.Sprintf("could not read %s: %v", dump, err))
			continue
		}
		report.Visited++
		var parsed pm2Dump
		if err := json.Unmarshal([]byte(content), &parsed); err != nil {
			noteUnreadable(report, fmt.Sprintf("could not parse %s: %v", dump, err))
			continue
		}
		for _, process := range parsed {
			for _, candidate := range []struct {
				path   string
				signal string
				label  string
			}{
				{process.PM2Env.WorkingDir, "pm2_cwd", "working directory"},
				{process.PM2Env.ExecPath, "pm2_exec", "executable"},
			} {
				if !filepath.IsAbs(candidate.path) {
					continue
				}
				refs = append(refs, Reference{
					Path:       filepath.Clean(candidate.path),
					Source:     core.SourceService,
					Protection: core.ProtectServiceReference,
					Signal:     candidate.signal,
					Detail:     fmt.Sprintf("pm2 process %q %s (%s)", process.Name, candidate.label, dump),
				})
			}
		}
	}
	return refs
}

// firstAbsolutePath returns the first absolute path in a directive value,
// skipping systemd's "-", "@", "+", "!" execution prefixes.
func firstAbsolutePath(value string) string {
	for _, field := range strings.Fields(value) {
		trimmed := strings.TrimLeft(field, "-@+!:")
		if strings.HasPrefix(trimmed, "/") {
			return filepath.Clean(trimmed)
		}
	}
	return ""
}

// readFileBounded reads at most limit bytes and fails when the file exceeds
// that bound, rather than truncating silently.
func readFileBounded(path string, limit int64) (string, error) {
	// A FIFO, device, or socket would block an ordinary Open indefinitely.
	// Service definitions are regular files, so anything else is refused
	// rather than read.
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file (%s)", path, info.Mode().Type())
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > limit {
		return "", fmt.Errorf("%s exceeds the %d byte bound", path, limit)
	}
	return string(data), nil
}

// noteUnreadable records something the service collectors could not read.
// Every such gap makes the report partial: a definition that was not read
// may reference a workspace path that would otherwise look unreferenced.
func noteUnreadable(report *core.CollectorReport, detail string) {
	report.Unknowns++
	report.Status = core.CollectorPartial
	report.Detail = appendDetail(report.Detail, detail)
}
