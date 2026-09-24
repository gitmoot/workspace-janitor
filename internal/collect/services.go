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

// A unit alias has no independent directives. Scan regular definitions first,
// then accept an alias only when a bounded, unchanged chain leads to a unit
// actually read from one of these opened definition roots (or to the exact
// systemd /dev/null mask). Never follow an alias to read arbitrary content.
func gatherSystemd(ctx context.Context, opts *Options, report *core.CollectorReport) []Reference {
	type alias struct {
		unit unitLocation
		info os.FileInfo
	}
	var sources []systemdDirectory
	defer func() {
		for _, source := range sources {
			_ = source.root.Close()
		}
	}()
	for _, dir := range opts.ServiceSources.SystemdDirs {
		if ctx.Err() != nil {
			return nil
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			if !os.IsNotExist(err) {
				noteUnreadable(report, fmt.Sprintf("could not open unit directory %s: %v", dir, err))
			}
			continue
		}
		listing, err := root.Open(".")
		if err != nil {
			_ = root.Close()
			noteUnreadable(report, fmt.Sprintf("could not list unit directory %s: %v", dir, err))
			continue
		}
		names, err := readDirNamesFromFile(listing, opts.Limits.MaxDirEntries)
		_ = listing.Close()
		if err != nil {
			_ = root.Close()
			noteUnreadable(report, fmt.Sprintf("could not list unit directory %s: %v", dir, err))
			continue
		}
		if names.bounded {
			noteUnreadable(report, fmt.Sprintf("listing of %s was truncated at %d entries", dir, opts.Limits.MaxDirEntries))
		}
		sources = append(sources, systemdDirectory{path: filepath.Clean(dir), root: root, names: names.names})
	}

	var refs []Reference
	scanned := make(map[unitLocation]os.FileInfo)
	aliases := make([]alias, 0)
	aliasInfos := make(map[unitLocation]os.FileInfo)
	for i, source := range sources {
		for _, name := range source.names {
			if ctx.Err() != nil {
				return refs
			}
			if !strings.HasSuffix(name, ".service") {
				continue
			}
			unit := unitLocation{directory: i, name: name}
			info, err := source.root.Lstat(name)
			if err != nil {
				noteUnreadable(report, fmt.Sprintf("could not inspect %s: %v", filepath.Join(source.path, name), err))
				continue
			}
			if info.Mode()&os.ModeSymlink != 0 {
				aliases = append(aliases, alias{unit: unit, info: info})
				aliasInfos[unit] = info
				continue
			}
			content, err := readSystemdUnit(source.root, name, info)
			if err != nil {
				noteUnreadable(report, fmt.Sprintf("could not read %s: %v", filepath.Join(source.path, name), err))
				continue
			}
			scanned[unit] = info
			report.Visited++
			refs = append(refs, systemdUnitReferences(name, content)...)
		}
	}
	for _, link := range aliases {
		if ctx.Err() != nil {
			return refs
		}
		if err := proveSystemdAlias(link.unit, link.info, sources, scanned, aliasInfos); err != nil {
			noteUnreadable(report, fmt.Sprintf("unproven unit alias %s: %v",
				filepath.Join(sources[link.unit.directory].path, link.unit.name), err))
			continue
		}
		report.Visited++ // known alias/mask, never a second copy of its target's refs
	}
	return refs
}

type systemdDirectory struct {
	path  string
	root  *os.Root
	names []string
}

type unitLocation struct {
	directory int
	name      string
}

// The opened file, both observations of its directory entry, and its content
// must describe the same bounded regular inode. A swapped-in special file
// cannot block the reader or become a clean empty definition.
func readSystemdUnit(root *os.Root, name string, before os.FileInfo) (string, error) {
	if !before.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file (%s)", before.Mode().Type())
	}
	file, err := openSystemdUnit(root, name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !sameUnitFile(before, opened) {
		return "", fmt.Errorf("unit changed before read")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxUnitFileBytes+1))
	if err != nil || int64(len(data)) > maxUnitFileBytes {
		return "", fmt.Errorf("unit read failed or exceeded %d bytes: %v", maxUnitFileBytes, err)
	}
	after, err := file.Stat()
	if err != nil || !sameUnitFile(opened, after) {
		return "", fmt.Errorf("unit changed during read")
	}
	entry, err := root.Lstat(name)
	if err != nil || !sameUnitFile(opened, entry) {
		return "", fmt.Errorf("unit changed after read")
	}
	return string(data), nil
}

const maxSystemdAliasHops = 8

func proveSystemdAlias(start unitLocation, initial os.FileInfo, sources []systemdDirectory,
	scanned, aliasInfos map[unitLocation]os.FileInfo) error {
	type step struct {
		unit   unitLocation
		info   os.FileInfo
		target string
	}
	steps := make([]step, 0, 2)
	seen := make(map[unitLocation]bool)
	current := start
	proven := false
	for range maxSystemdAliasHops {
		if seen[current] {
			return fmt.Errorf("alias loop")
		}
		seen[current] = true
		source := sources[current.directory]
		info, err := source.root.Lstat(current.name)
		if err != nil {
			return fmt.Errorf("alias target unavailable: %w", err)
		}
		if info.Mode().IsRegular() {
			known, ok := scanned[current]
			if !ok || !sameUnitFile(known, info) {
				return fmt.Errorf("target was not scanned or changed")
			}
			proven = true
			break
		}
		known, ok := aliasInfos[current]
		if !ok || info.Mode()&os.ModeSymlink == 0 || !sameUnitFile(known, info) ||
			current == start && !sameUnitFile(initial, info) {
			return fmt.Errorf("alias was not listed or changed")
		}
		target, err := source.root.Readlink(current.name)
		if err != nil {
			return fmt.Errorf("alias target unreadable: %w", err)
		}
		steps = append(steps, step{unit: current, info: info, target: target})
		if target == "/dev/null" {
			if !provenSystemdMask() {
				return fmt.Errorf("mask device is not proven")
			}
			proven = true
			break
		}
		next, ok := systemdAliasTarget(current, target, sources)
		if !ok {
			return fmt.Errorf("target escapes or is not a configured service definition")
		}
		current = next
	}
	if !proven {
		return fmt.Errorf("alias chain exceeds %d hops", maxSystemdAliasHops)
	}
	for _, link := range steps {
		source := sources[link.unit.directory]
		info, err := source.root.Lstat(link.unit.name)
		if err != nil || !sameUnitFile(link.info, info) {
			return fmt.Errorf("alias changed during proof")
		}
		target, err := source.root.Readlink(link.unit.name)
		if err != nil || target != link.target {
			return fmt.Errorf("alias changed during proof")
		}
	}
	if target, ok := scanned[current]; ok {
		info, err := sources[current.directory].root.Lstat(current.name)
		if err != nil || !sameUnitFile(target, info) {
			return fmt.Errorf("target changed during proof")
		}
	}
	return nil
}

func systemdAliasTarget(from unitLocation, target string, sources []systemdDirectory) (unitLocation, bool) {
	if target == "" || target != filepath.Clean(target) {
		return unitLocation{}, false
	}
	if !filepath.IsAbs(target) {
		if filepath.Base(target) != target || !strings.HasSuffix(target, ".service") {
			return unitLocation{}, false
		}
		return unitLocation{directory: from.directory, name: target}, true
	}
	if !strings.HasSuffix(target, ".service") {
		return unitLocation{}, false
	}
	for i, source := range sources {
		if filepath.Dir(target) == source.path {
			return unitLocation{directory: i, name: filepath.Base(target)}, true
		}
	}
	return unitLocation{}, false
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
