package collect

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"gopkg.in/yaml.v3"
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
	if len(sources.SystemdDirs) == 0 && len(sources.CronPaths) == 0 && len(sources.PM2Dumps) == 0 && len(sources.ConfigFiles) == 0 && sources.GitmootPipelines == "" && len(sources.StagehandDirs) == 0 {
		report.Status = core.CollectorSkipped
		report.Detail = "no service definition locations are configured"
		return nil, report
	}

	var refs []Reference
	for _, gather := range []func(context.Context, *Options, *core.CollectorReport) []Reference{
		gatherSystemd,
		gatherCron,
		gatherPM2,
		gatherConfigFiles,
		gatherGitmootPipelines,
		gatherStagehand,
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
	aliases := make([]unitLocation, 0)
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
				aliases = append(aliases, unit)
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
		if err := proveSystemdAlias(link, sources, scanned, aliasInfos); err != nil {
			noteUnreadable(report, fmt.Sprintf("unproven unit alias %s: %v",
				filepath.Join(sources[link.directory].path, link.name), err))
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

func proveSystemdAlias(start unitLocation, sources []systemdDirectory,
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
		if !ok || info.Mode()&os.ModeSymlink == 0 || !sameUnitFile(known, info) {
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

// gatherConfigFiles reports every absolute path held in any string value of
// a configured configuration file. Files are decoded with a real parser
// (TOML, YAML or JSON by extension), so quoting, escapes and comments follow
// the format exactly; an unknown format or a file that does not parse is
// reported unreadable, which leaves this source unknown rather than empty.
// Only the path and the file become evidence, never other values.
func gatherConfigFiles(ctx context.Context, opts *Options, report *core.CollectorReport) []Reference {
	var refs []Reference
	for _, file := range opts.ServiceSources.ConfigFiles {
		if ctx.Err() != nil {
			return refs
		}
		content, err := readFileBounded(file, maxPM2DumpBytes)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			noteUnreadable(report, fmt.Sprintf("could not read %s: %v", file, err))
			continue
		}
		var doc any
		switch strings.ToLower(filepath.Ext(file)) {
		case ".toml":
			var table map[string]any
			_, err = toml.Decode(content, &table)
			doc = table
		case ".yaml", ".yml":
			// Every document of the stream; a bad later document fails
			// the whole file rather than being silently skipped.
			var docs []any
			decoder := yaml.NewDecoder(strings.NewReader(content))
			for {
				var one any
				if err = decoder.Decode(&one); err != nil {
					break
				}
				docs = append(docs, one)
			}
			if errors.Is(err, io.EOF) {
				err = nil
			}
			doc = docs
		case ".json":
			err = json.Unmarshal([]byte(content), &doc)
		default:
			err = errors.New("unsupported format; use .toml, .yaml, .yml or .json")
		}
		if err != nil {
			noteUnreadable(report, fmt.Sprintf("could not parse %s: %v", file, err))
			continue
		}
		report.Visited++
		walkConfigStrings(doc, func(value string) {
			if !filepath.IsAbs(value) {
				return
			}
			path := filepath.Clean(value)
			if path == "/" {
				return
			}
			refs = append(refs, Reference{
				Path:       path,
				Source:     core.SourceService,
				Protection: core.ProtectServiceReference,
				Signal:     "config_file_path",
				Detail:     "named in " + file,
			})
		})
	}
	return refs
}

// gatherGitmootPipelines reports every absolute path in the spec of an
// enabled Gitmoot pipeline (its commands, working directories and any other
// value). A scheduled pipeline runs from those paths whether or not anything
// else references them (live 2026-11-06: keephair-geo ran
// /root/keephair-pipelines/current/geo-collect.sh hourly and failed after
// that folder was archived as idle scratch). A missing database is skipped;
// one that cannot be read, or a spec that does not parse, leaves this source
// unknown, which refuses removals.
func gatherGitmootPipelines(ctx context.Context, opts *Options, report *core.CollectorReport) []Reference {
	path := opts.ServiceSources.GitmootPipelines
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		noteUnreadable(report, fmt.Sprintf("could not stat %s: %v", path, err))
		return nil
	}
	uri := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&_pragma=query_only(1)"}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		noteUnreadable(report, fmt.Sprintf("could not open %s: %v", path, err))
		return nil
	}
	defer db.Close()
	// A Gitmoot schema without a pipelines table has no pipelines. Any
	// other read failure still leaves this source unknown.
	var tables int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'pipelines'`).Scan(&tables); err != nil {
		noteUnreadable(report, fmt.Sprintf("could not read Gitmoot schema: %v", err))
		return nil
	}
	if tables == 0 {
		return nil
	}
	rows, err := db.QueryContext(ctx, `SELECT name, spec_yaml FROM pipelines WHERE enabled != 0`)
	if err != nil {
		noteUnreadable(report, fmt.Sprintf("could not read Gitmoot pipelines: %v", err))
		return nil
	}
	defer rows.Close()
	var refs []Reference
	for rows.Next() {
		var name, spec string
		if err := rows.Scan(&name, &spec); err != nil {
			noteUnreadable(report, fmt.Sprintf("could not read a Gitmoot pipeline: %v", err))
			return refs
		}
		report.Visited++
		found, unresolved, err := specPathReferences(spec, "gitmoot_pipeline_path", "used by enabled Gitmoot pipeline "+name, nil)
		if err != nil {
			noteUnreadable(report, fmt.Sprintf("could not parse Gitmoot pipeline %s: %v", name, err))
			continue
		}
		if len(unresolved) > 0 {
			noteUnreadable(report, fmt.Sprintf("Gitmoot pipeline %s uses paths that cannot be resolved: %s", name, strings.Join(unresolved, " ")))
		}
		refs = append(refs, found...)
	}
	if err := rows.Err(); err != nil {
		noteUnreadable(report, fmt.Sprintf("could not read Gitmoot pipelines: %v", err))
	}
	return refs
}

// stagehandRunPlaceholder stands for a stagehand run id while expanding
// $STAGEHAND_WORK. Like the integer it replaces, it holds no "/" or "..".
const stagehandRunPlaceholder = "STAGEHAND-RUN-ID"

// gatherStagehand reports every absolute path in each stagehand pipeline
// spec (*.yaml, *.yml) in the configured directories: commands, working
// directories, env and prompt files, and any other value. Disabled specs
// count too. A missing directory is skipped; one that cannot be listed, or
// a spec that cannot be read or parsed, leaves this source unknown, which
// refuses removals.
func gatherStagehand(ctx context.Context, opts *Options, report *core.CollectorReport) []Reference {
	var refs []Reference
	// Stagehand sets $STAGEHAND_WORK to <state>/runs/<run id>/work and
	// $STAGEHAND_RUN_ID to that run id, an integer it assigns. A placeholder
	// stands for it;
	// references through it are folded into <state>/runs, unless the spec
	// itself climbs out of that directory with a literal "..".
	var runtime map[string]string
	var runsDir string
	if state := opts.ServiceSources.StagehandStateDir; filepath.IsAbs(state) {
		runsDir = filepath.Join(state, "runs")
		runtime = map[string]string{
			"STAGEHAND_WORK":   runsDir + "/" + stagehandRunPlaceholder + "/work",
			"STAGEHAND_RUN_ID": stagehandRunPlaceholder,
		}
	}
	for _, dir := range opts.ServiceSources.StagehandDirs {
		if ctx.Err() != nil {
			return refs
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			noteUnreadable(report, fmt.Sprintf("could not list %s: %v", dir, err))
			continue
		}
		for _, entry := range entries {
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if entry.IsDir() || (ext != ".yaml" && ext != ".yml") {
				continue
			}
			file := filepath.Join(dir, entry.Name())
			content, err := readFileBounded(file, maxPM2DumpBytes)
			if err != nil {
				noteUnreadable(report, fmt.Sprintf("could not read %s: %v", file, err))
				continue
			}
			report.Visited++
			found, unresolved, err := specPathReferences(content, "stagehand_path", "used by stagehand pipeline "+file, runtime)
			if err != nil {
				noteUnreadable(report, fmt.Sprintf("could not parse %s: %v", file, err))
				continue
			}
			if len(unresolved) > 0 {
				noteUnreadable(report, fmt.Sprintf("stagehand pipeline %s uses paths that cannot be resolved: %s", file, strings.Join(unresolved, " ")))
			}
			for _, ref := range found {
				if !strings.Contains(ref.Path, stagehandRunPlaceholder) {
					refs = append(refs, ref)
					continue
				}
				// filepath.Clean has already applied any literal "..": a path
				// that left <state>/runs is reported, not folded.
				if !core.PathWithin(ref.Path, runsDir) {
					noteUnreadable(report, fmt.Sprintf("stagehand pipeline %s builds a path outside its run directory: %s", file, ref.Path))
					continue
				}
				ref.Path, ref.Subtree = runsDir, true
				refs = append(refs, ref)
			}
		}
	}
	return refs
}

// specPathReferences parses a pipeline spec (YAML, every document) and
// returns a blocking service reference for each path it names.
//
//   - A string value that is itself an absolute path counts whole, spaces
//     included.
//   - Otherwise the value is split into shell words (quotes and backslashes
//     honoured; whitespace and ; & | < > ( ) separate words). A quoted word
//     that is itself a command (sh -c '...') is split again.
//   - Variables are expanded from what the spec states: NAME=value words
//     anywhere in it, string entries of YAML maps (env: blocks), and
//     ${NAME:-default} fallbacks. HOME is the janitor's own HOME: pipelines
//     on this host run as the same user. runtime adds variables the runner
//     itself sets.
//   - Each expanded word counts, as does the value after every = and each
//     :-separated part of it.
//   - A word still holding an unresolved expansion ($x, $(...), `...`) and a
//     / is a path whose location is unknown: the value may hold anything,
//     "..", included. It is returned as unresolved, and the caller must
//     treat the whole source as unknown.
func specPathReferences(spec, signal, detail string, runtime map[string]string) ([]Reference, []string, error) {
	var docs []any
	decoder := yaml.NewDecoder(strings.NewReader(spec))
	var err error
	for {
		var one any
		if err = decoder.Decode(&one); err != nil {
			break
		}
		docs = append(docs, one)
	}
	if !errors.Is(err, io.EOF) {
		return nil, nil, err
	}
	vars := map[string][]string{}
	// A variable with more values than this is not expanded at all: words
	// using it are then unresolved and protected conservatively, never
	// expanded from a silently truncated list.
	const maxValues = 8
	setVar := func(name, value string) {
		if !shellName.MatchString(name) || slices.Contains(vars[name], value) {
			return
		}
		if values, seen := vars[name]; seen && values == nil {
			return // already too many
		}
		if len(vars[name]) >= maxValues {
			vars[name] = nil
			return
		}
		vars[name] = append(vars[name], value)
	}
	if home := os.Getenv("HOME"); filepath.IsAbs(home) {
		setVar("HOME", home)
	}
	for name, value := range runtime {
		setVar(name, value)
	}
	walkConfigMaps(docs, func(key, value string) { setVar(key, value) })
	walkConfigStrings(docs, func(value string) {
		forEachWord(value, 0, func(word string) {
			if name, val, ok := strings.Cut(word, "="); ok {
				setVar(name, val)
			}
		})
	})
	var refs []Reference
	var unresolved []string
	addOne := func(path string) {
		if p := filepath.Clean(path); filepath.IsAbs(p) && p != "/" {
			refs = append(refs, Reference{Path: p, Source: core.SourceService, Protection: core.ProtectServiceReference, Signal: signal, Detail: detail})
		}
	}
	// add applies the shell's pathname expansions to one candidate: braces,
	// a leading ~, then globs against the filesystem as it is now. A pattern
	// that cannot be expanded safely is unresolved.
	add := func(candidate string) {
		paths, ok := expandPathname(candidate)
		if !ok {
			unresolved = append(unresolved, candidate)
			return
		}
		for _, path := range paths {
			addOne(path)
		}
	}
	consider := func(word string) {
		for _, expanded := range expandWord(word, vars) {
			// An expansion still present may hold any value, including "..",
			// so no part of the word bounds where it points: unresolved.
			if unresolvedExpansion.MatchString(expanded) {
				if strings.Contains(expanded, "/") {
					unresolved = append(unresolved, word)
				}
				continue
			}
			add(expanded)
			rest := expanded
			for {
				_, after, ok := strings.Cut(rest, "=")
				if !ok {
					break
				}
				add(after)
				for _, part := range strings.Split(after, ":") {
					add(part)
				}
				rest = after
			}
		}
	}
	// A path field's whole value is one path and may contain spaces
	// (cwd: /a b). A command field is shell text: only its words count, or a
	// whole command line would be read as one long path.
	walkConfigKeyedStrings(docs, "", func(key, value string) {
		if whole := strings.TrimSpace(value); !commandKeys[strings.ToLower(key)] && strings.HasPrefix(whole, "/") && !strings.Contains(whole, "\n") {
			consider(whole)
		}
		forEachWord(value, 0, consider)
	})
	return refs, unresolved, nil
}

var (
	shellName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// shellParam matches ${NAME}, ${NAME:-default}, ${NAME-default},
	// ${NAME:=default} and $NAME.
	shellParam = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?[-=]([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)
	// unresolvedExpansion is anything a shell would still expand.
	unresolvedExpansion = regexp.MustCompile("\\$|`")
)

// forEachWord calls visit with every shell word of text, splitting quoted
// words that are themselves commands again, a few levels deep.
func forEachWord(text string, depth int, visit func(string)) {
	for _, word := range shellWords(text) {
		visit(word)
		if depth < 3 && strings.ContainsAny(word, " \t\n;&|<>()") {
			forEachWord(word, depth+1, visit)
		}
	}
}

// expandPathname performs, for one word, the pathname expansions a shell
// applies after parameter expansion: brace expansion ({a,b}), tilde
// expansion (~, ~/..., ~user/...). Quoting is gone by this point, so the
// literal word is always kept as well: a quoted '/a/{b,c}' names itself. It
// reports false when a form cannot be expanded faithfully: nested or
// oversized braces, ~+ and ~-, an unknown user, or any glob character
// (* ? [) left after brace and tilde expansion. The caller treats that word
// as unresolved.
func expandPathname(word string) ([]string, bool) {
	const maxPaths = 64
	// Only a word that can become an absolute path is a candidate: one that
	// starts with /, ~, or a brace group holding a /. Other words (options,
	// JSON-like text, relative names) are left alone.
	if !strings.HasPrefix(word, "/") && !strings.HasPrefix(word, "~") &&
		!(strings.HasPrefix(word, "{") && strings.Contains(word, "/")) {
		return nil, true
	}
	var out []string
	if filepath.IsAbs(word) {
		out = append(out, word)
	}
	words, ok := expandBraces(word, maxPaths)
	if !ok {
		return nil, false
	}
	for _, w := range words {
		if strings.HasPrefix(w, "~") {
			name, rest, _ := strings.Cut(w[1:], "/")
			var home string
			switch name {
			case "":
				home = os.Getenv("HOME")
			case "+", "-":
				return nil, false
			default:
				account, err := user.Lookup(name)
				if err != nil {
					return nil, false
				}
				home = account.HomeDir
			}
			if !filepath.IsAbs(home) {
				return nil, false
			}
			w = filepath.Join(home, rest)
		}
		if !filepath.IsAbs(w) {
			continue
		}
		// Shell globbing depends on locale, quoting and options that the
		// spec does not record, and Go's matcher differs from it in ways
		// that are easy to miss. A glob is therefore never resolved: the
		// word is unresolved, which blocks removals.
		if strings.ContainsAny(w, "*?[") {
			return nil, false
		}
		if w != word {
			out = append(out, w)
		}
	}
	return out, true
}

// expandBraces expands one level of {a,b,...} groups, innermost-free: a
// nested group, an unbalanced brace, or more than limit results reports
// false. A {..} range or a group without a comma is left literal, as in
// sh; bash range expansion ({1..3}) is reported false.
func expandBraces(word string, limit int) ([]string, bool) {
	results := []string{word}
	for round := 0; round < 8; round++ {
		changed := false
		var next []string
		for _, w := range results {
			open := strings.IndexByte(w, '{')
			if open < 0 {
				next = append(next, w)
				continue
			}
			end := strings.IndexByte(w[open:], '}')
			if end < 0 {
				return nil, false
			}
			end += open
			body := w[open+1 : end]
			if strings.ContainsRune(body, '{') {
				return nil, false
			}
			if strings.Contains(body, "..") {
				return nil, false
			}
			if !strings.Contains(body, ",") {
				// Not a brace group; keep it literal and look past it.
				rest, ok := expandBraces(w[end+1:], limit)
				if !ok {
					return nil, false
				}
				for _, r := range rest {
					next = append(next, w[:end+1]+r)
				}
				continue
			}
			changed = true
			for _, alt := range strings.Split(body, ",") {
				next = append(next, w[:open]+alt+w[end+1:])
			}
			if len(next) > limit {
				return nil, false
			}
		}
		results = next
		if !changed {
			return results, true
		}
	}
	return nil, false
}

// expandWord returns word with every expansion of a known variable replaced
// by each of its values. A ${NAME:-default} fallback is always one of the
// candidates, set or not. An unknown expansion, a variable recorded with too
// many values (nil in vars), or a word whose expansions would exceed 16 is
// returned unexpanded, for the caller to treat as unresolved: candidates are
// never silently dropped.
func expandWord(word string, vars map[string][]string) []string {
	const maxResults = 16
	results := []string{word}
	for round := 0; round < 4; round++ {
		changed := false
		var next []string
		for _, current := range results {
			loc := shellParam.FindStringSubmatchIndex(current)
			if loc == nil {
				next = append(next, current)
				continue
			}
			name := ""
			if loc[2] >= 0 {
				name = current[loc[2]:loc[3]]
			} else {
				name = current[loc[6]:loc[7]]
			}
			known, recorded := vars[name]
			if recorded && known == nil {
				return []string{word}
			}
			// A written fallback is always a candidate as well: POSIX uses it
			// when NAME is unset and, for :- and :=, when NAME is empty, and
			// the spec cannot tell us which applies at run time.
			values := slices.Clone(known)
			if loc[4] >= 0 {
				if fallback := current[loc[4]:loc[5]]; !slices.Contains(values, fallback) {
					values = append(values, fallback)
				}
			}
			if len(values) == 0 {
				next = append(next, current)
				continue
			}
			if len(next)+len(values) > maxResults {
				return []string{word}
			}
			changed = true
			for _, value := range values {
				next = append(next, current[:loc[0]]+value+current[loc[1]:])
			}
		}
		results = next
		if !changed {
			break
		}
	}
	return results
}

// commandKeys name spec fields whose values are shell commands.
var commandKeys = map[string]bool{
	"cmd": true, "command": true, "commands": true, "run": true, "script": true,
	"shell": true, "sh": true, "bash": true, "exec": true, "entrypoint": true, "args": true,
}

// walkConfigKeyedStrings calls visit with every string value (and map key)
// in a decoded configuration document and the map key it sits under; list
// items inherit their list's key.
func walkConfigKeyedStrings(node any, key string, visit func(key, value string)) {
	switch value := node.(type) {
	case string:
		visit(key, value)
	case map[string]any:
		for name, child := range value {
			visit("", name)
			walkConfigKeyedStrings(child, name, visit)
		}
	case map[any]any:
		for name, child := range value {
			text, _ := name.(string)
			walkConfigKeyedStrings(name, "", visit)
			walkConfigKeyedStrings(child, text, visit)
		}
	case []any:
		for _, child := range value {
			walkConfigKeyedStrings(child, key, visit)
		}
	}
}

// walkConfigMaps calls visit with every string-valued entry of every map in
// a decoded configuration document.
func walkConfigMaps(node any, visit func(key, value string)) {
	switch value := node.(type) {
	case map[string]any:
		for key, child := range value {
			if text, ok := child.(string); ok {
				visit(key, text)
			}
			walkConfigMaps(child, visit)
		}
	case map[any]any:
		for key, child := range value {
			if name, ok := key.(string); ok {
				if text, ok := child.(string); ok {
					visit(name, text)
				}
			}
			walkConfigMaps(child, visit)
		}
	case []any:
		for _, child := range value {
			walkConfigMaps(child, visit)
		}
	}
}

// shellWords splits s into words the way a POSIX shell would before
// expansion: single quotes are literal, double quotes allow backslash
// escapes, a backslash outside quotes escapes the next character, and
// whitespace and the operators ; & | < > ( ) end a word. An unterminated
// quote ends at the end of s.
func shellWords(s string) []string {
	var words []string
	var word strings.Builder
	inWord := false
	flush := func() {
		if inWord {
			words = append(words, word.String())
			word.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			i++
			word.WriteByte(s[i])
			inWord = true
		case c == '\'':
			inWord = true
			for i++; i < len(s) && s[i] != '\''; i++ {
				word.WriteByte(s[i])
			}
		case c == '"':
			inWord = true
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("\"\\$`", s[i+1]) >= 0 {
					i++
				}
				word.WriteByte(s[i])
			}
		case strings.IndexByte(" \t\n\r;&|<>()", c) >= 0:
			flush()
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	flush()
	return words
}

// walkConfigStrings calls visit with every string value (and map key) in a
// decoded configuration document.
func walkConfigStrings(node any, visit func(string)) {
	switch value := node.(type) {
	case string:
		visit(value)
	case map[string]any:
		for key, child := range value {
			visit(key)
			walkConfigStrings(child, visit)
		}
	case map[any]any:
		for key, child := range value {
			walkConfigStrings(key, visit)
			walkConfigStrings(child, visit)
		}
	case []any:
		for _, child := range value {
			walkConfigStrings(child, visit)
		}
	case []map[string]any:
		for _, child := range value {
			walkConfigStrings(child, visit)
		}
	}
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
