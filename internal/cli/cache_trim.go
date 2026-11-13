package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

// cacheTrimLoop re-runs the standing cache trims every cache_trim_interval
// between daily cycles, so a busy shared cache cannot regrow to the disk
// floor. Each run trims only a cache over its bound with no live user. A
// failed trim command is reported and retried next interval. A report that
// cannot be written is returned: a trim that deleted bytes must not lose its
// only record while the watcher looks healthy.
func cacheTrimLoop(ctx context.Context, e *env, paths config.Paths, policy config.Policy) error {
	interval := policy.Prevention.CacheTrimInterval.Duration()
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
		reports, err := runCacheTrims(ctx, policy, paths.StateDir)
		// Report before honouring cancellation: an earlier trim in this run
		// may already have deleted bytes.
		report := watchReport{Reason: "cache_trim", CacheTrims: reports}
		if err != nil && ctx.Err() == nil {
			report.Error = err.Error()
		}
		if acted(reports) || report.Error != "" {
			if writeErr := writeWatchReport(e, report); writeErr != nil {
				return fmt.Errorf("cache trim report: %w", writeErr)
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		timer.Reset(interval)
	}
}

// acted reports whether any trim did or attempted something worth logging;
// routine under-bound checks stay quiet.
func acted(reports []cacheTrimReport) bool {
	for _, r := range reports {
		if r.Status != cacheUnderBound && r.Status != cacheTrimNotFound {
			return true
		}
	}
	return false
}

// cacheTrimTimeout bounds one official trim command.
const cacheTrimTimeout = 10 * time.Minute

// Cache trim outcomes.
const (
	cacheTrimmed      = "trimmed"
	cacheUnderBound   = "under_bound"
	cacheInUse        = "skipped_in_use"
	cacheTrimFailed   = "failed"
	cacheTrimNotFound = "absent"
	cacheTrimBusy     = "skipped_trim_running"
)

// cacheTrimReport is one trim's outcome. For docker-images the sizes are the
// reclaimable image bytes Docker reports, not a directory's allocated size,
// and Images lists every candidate image with what happened to it.
type cacheTrimReport struct {
	Kind        string   `json:"kind"`
	Path        string   `json:"path,omitempty"`
	MaxBytes    int64    `json:"max_bytes"`
	Status      string   `json:"status"`
	SizeBefore  *int64   `json:"size_before_bytes,omitempty"`
	SizeAfter   *int64   `json:"size_after_bytes,omitempty"`
	Reclaimed   *int64   `json:"reclaimed_bytes,omitempty"`
	FreeBefore  *uint64  `json:"free_before_bytes,omitempty"`
	FreeAfter   *uint64  `json:"free_after_bytes,omitempty"`
	Command     []string `json:"command,omitempty"`
	ActiveUsers []string `json:"active_users,omitempty"`
	Output      string   `json:"output,omitempty"`
	Error       string   `json:"error,omitempty"`
	// EventsCoveredSince is how far back the daemon's event history
	// reached (docker-images only).
	EventsCoveredSince string               `json:"events_covered_since,omitempty"`
	Images             []dockerImageOutcome `json:"images,omitempty"`
}

// runCacheTrims applies every configured standing cache trim once. A cache in
// live use is skipped, not an error; the next cycle retries it. Only a trim
// command that fails is returned as an error.
func runCacheTrims(ctx context.Context, policy config.Policy, stateDir string) ([]cacheTrimReport, error) {
	if len(policy.Prevention.CacheTrims) == 0 {
		return nil, nil
	}
	release, held, err := tryLockTrim(stateDir)
	if err != nil {
		return nil, err
	}
	if !held {
		var reports []cacheTrimReport
		for _, trim := range policy.Prevention.CacheTrims {
			reports = append(reports, cacheTrimReport{Kind: trim.Kind, Path: trim.Path, MaxBytes: trim.MaxBytes, Status: cacheTrimBusy})
		}
		return reports, nil
	}
	defer release()
	var reports []cacheTrimReport
	var errs []error
	for _, trim := range policy.Prevention.CacheTrims {
		// Validation refuses a lexical overlap; this also resolves symlinks,
		// and the provider then runs on the resolved path it checked.
		written := trim.Path
		if trim.Path != "" {
			if resolved, err := filepath.EvalSymlinks(trim.Path); err == nil {
				trim.Path = resolved
			}
		}
		if refusal := archiveOnlyTrimRefusal(ctx, &policy, trim); refusal != "" {
			reports = append(reports, cacheTrimReport{Kind: trim.Kind, Path: written, MaxBytes: trim.MaxBytes,
				Status: cacheTrimFailed, Error: refusal})
			errs = append(errs, fmt.Errorf("cache trim %s %s: %s", trim.Kind, written, refusal))
			continue
		}
		report := trimCache(ctx, policy.Collectors.ProcRoot, trim)
		report.Path = written
		if report.Status == cacheTrimFailed {
			errs = append(errs, fmt.Errorf("cache trim %s %s: %s", trim.Kind, trim.Path, report.Error))
		}
		reports = append(reports, report)
	}
	return reports, errors.Join(errs...)
}

func trimCache(ctx context.Context, procRoot string, trim config.CacheTrim) cacheTrimReport {
	report := cacheTrimReport{Kind: trim.Kind, Path: trim.Path, MaxBytes: trim.MaxBytes}
	fail := func(err error) cacheTrimReport {
		report.Status, report.Error = cacheTrimFailed, err.Error()
		return report
	}
	var args, env []string
	switch trim.Kind {
	case config.CacheTrimGoBuild, config.CacheTrimGoMod, config.CacheTrimPnpmStore:
		info, err := os.Lstat(trim.Path)
		if errors.Is(err, fs.ErrNotExist) {
			report.Status = cacheTrimNotFound
			return report
		}
		if err != nil {
			return fail(err)
		}
		if !info.IsDir() {
			return fail(fmt.Errorf("%s is not a directory", trim.Path))
		}
		size, err := allocatedBytes(ctx, trim.Path)
		if err != nil {
			return fail(fmt.Errorf("measure: %w", err))
		}
		report.SizeBefore = &size
		if size <= trim.MaxBytes {
			report.Status = cacheUnderBound
			return report
		}
		switch trim.Kind {
		case config.CacheTrimGoBuild:
			args = []string{"clean", "-cache"}
			env = []string{"GOCACHE=" + trim.Path, "GOTOOLCHAIN=local", "GOENV=off", "GOFLAGS=", "GOPROXY=off",
				"HOME=" + os.Getenv("HOME"), "PATH=/usr/bin:/bin"}
		case config.CacheTrimGoMod:
			if err := binaryOutside(trim); err != nil {
				return fail(err)
			}
			// go clean -modcache makes Go's read-only module files writable
			// before removing them.
			args = []string{"clean", "-modcache"}
			env = []string{"GOMODCACHE=" + trim.Path, "GOTOOLCHAIN=local", "GOENV=off", "GOFLAGS=", "GOPROXY=off",
				"HOME=" + os.Getenv("HOME"), "PATH=/usr/bin:/bin"}
		case config.CacheTrimPnpmStore:
			if err := binaryOutside(trim); err != nil {
				return fail(err)
			}
			env = pnpmEnv(trim.Binary)
			if err := pnpmStoreIs(ctx, trim.Binary, env, trim.Path); err != nil {
				return fail(err)
			}
			// pnpm removes only packages no project links to.
			args = []string{"store", "prune", "--store-dir", trim.Path}
		}
	case config.CacheTrimDockerBuilder:
		// Docker enforces the bound itself and removes only unused build
		// cache: never images, containers or volumes.
		args = []string{"builder", "prune", "--force", "--max-used-space", strconv.FormatInt(trim.MaxBytes, 10)}
		env = dockerEnv()
	case config.CacheTrimDockerImages:
		return trimDockerImages(ctx, procRoot, trim, report)
	default:
		return fail(fmt.Errorf("unsupported cache trim kind %q", trim.Kind))
	}
	report.Command = append([]string{trim.Binary}, args...)
	// Check for live users at the last moment before running the command.
	if users := cacheUsers(procRoot, trim); len(users) != 0 {
		report.Status, report.ActiveUsers = cacheInUse, users
		return report
	}
	report.FreeBefore = freeBytes(trimFilesystem(trim))
	runCtx, cancel := context.WithTimeout(ctx, cacheTrimTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, trim.Binary, args...)
	cmd.Env = env
	cmd.Dir = "/"
	out, err := cmd.CombinedOutput()
	report.Output = boundedOutput(out)
	report.FreeAfter = freeBytes(trimFilesystem(trim))
	switch trim.Kind {
	case config.CacheTrimGoBuild, config.CacheTrimGoMod, config.CacheTrimPnpmStore:
		if size, sizeErr := allocatedBytes(ctx, trim.Path); sizeErr == nil {
			report.SizeAfter = &size
		}
	}
	if report.SizeBefore != nil && report.SizeAfter != nil {
		reclaimed := max(*report.SizeBefore-*report.SizeAfter, 0)
		report.Reclaimed = &reclaimed
	}
	if err != nil {
		return fail(err)
	}
	report.Status = cacheTrimmed
	return report
}

func trimFilesystem(trim config.CacheTrim) string {
	return trim.TrimTarget()
}

// cacheUsers lists processes that may be using the cache right now: Go
// toolchain commands for go-build (plus any handle open under the cache); Go
// commands and gopls for go-mod (plus any handle or executable under the
// cache); pnpm for pnpm-store (plus any handle under the store); image builds
// for docker-builder, and image builds or pulls for docker-images. It fails
// closed: a process that cannot be inspected counts as a possible user. A
// false positive only postpones the trim to the next cycle.
func cacheUsers(procRoot string, trim config.CacheTrim) []string {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return []string{fmt.Sprintf("process list unavailable: %v", err)}
	}
	var users []string
	for _, entry := range entries {
		pid := entry.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(procRoot, pid, "cmdline"))
		if processGone(err) {
			continue
		}
		if err != nil {
			users = append(users, fmt.Sprintf("%s (cannot inspect: %v)", pid, err))
			continue
		}
		if len(raw) == 0 {
			continue // kernel thread or exiting process
		}
		argv := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		var busy bool
		procDir := filepath.Join(procRoot, pid)
		switch trim.Kind {
		case config.CacheTrimGoBuild, config.CacheTrimGoMod:
			candidate, uses := goToolchainBusy, goProcessUsesCache
			if trim.Kind == config.CacheTrimGoMod {
				candidate, uses = goModuleUser, goProcessUsesModCache
			}
			busy = candidate(argv)
			if busy {
				// A Go process whose cache is elsewhere does not use this
				// one; only one that resolves here (or cannot be resolved)
				// blocks the trim.
				here, err := uses(procDir, trim.Path)
				if processGone(err) {
					continue
				}
				if err != nil {
					users = append(users, fmt.Sprintf("%s (cannot inspect environment: %v)", pid, err))
					continue
				}
				busy = here
			}
			if !busy && trim.Kind == config.CacheTrimGoMod {
				// A toolchain that Go downloaded runs from the module cache.
				runs, err := executableUnder(procDir, trim.Path)
				if err != nil {
					users = append(users, fmt.Sprintf("%s (cannot inspect executable: %v)", pid, err))
					continue
				}
				busy = runs
			}
			if !busy {
				holds, err := holdsHandleUnder(filepath.Join(procDir, "fd"), trim.Path)
				if err != nil {
					users = append(users, fmt.Sprintf("%s (cannot inspect handles: %v)", pid, err))
					continue
				}
				busy = holds
			}
		case config.CacheTrimPnpmStore:
			busy = pnpmBusy(argv)
			if !busy {
				holds, err := holdsHandleUnder(filepath.Join(procDir, "fd"), trim.Path)
				if err != nil {
					users = append(users, fmt.Sprintf("%s (cannot inspect handles: %v)", pid, err))
					continue
				}
				busy = holds
			}
		case config.CacheTrimDockerBuilder:
			busy = dockerBuildBusy(argv)
		case config.CacheTrimDockerImages:
			busy = dockerImageBusy(argv)
		}
		if busy {
			users = append(users, pid+" "+truncate(strings.Join(argv, " "), 160))
		}
	}
	sort.Strings(users)
	return users
}

// goProcessUsesCache reports whether the Go process at procDir
// (/proc/<pid>) builds into cache. It follows Go's own precedence for
// GOCACHE (see goProcEnv), then the default $XDG_CACHE_HOME/go-build or
// $HOME/.cache/go-build. GOCACHE=off uses no cache. It fails closed: a value
// that cannot be established, a relative GOENV, or an existing file that
// cannot be read counts the process as a user.
func goProcessUsesCache(procDir, cache string) (bool, error) {
	g, err := readGoProcEnv(procDir)
	if err != nil {
		return false, err
	}
	dir, set, ok := g.lookup("GOCACHE")
	switch {
	case !ok:
		return true, nil
	case set:
	case filepath.IsAbs(g.env["XDG_CACHE_HOME"]):
		dir = filepath.Join(g.env["XDG_CACHE_HOME"], "go-build")
	case filepath.IsAbs(g.env["HOME"]):
		dir = filepath.Join(g.env["HOME"], ".cache", "go-build")
	default:
		return true, nil
	}
	return goCacheDirIs(dir, cache), nil
}

// goProcessUsesModCache reports whether the Go process at procDir
// (/proc/<pid>) uses modcache as its module cache. Go takes GOMODCACHE, or
// when it is empty the first GOPATH entry plus /pkg/mod, where GOPATH
// defaults to $HOME/go; both follow Go's precedence (see goProcEnv). It fails
// closed: a value that cannot be established, or a relative or empty result,
// counts the process as a user.
func goProcessUsesModCache(procDir, modcache string) (bool, error) {
	g, err := readGoProcEnv(procDir)
	if err != nil {
		return false, err
	}
	dir, ok := g.envOr("GOMODCACHE", func() (string, bool) {
		gopath, ok := g.envOr("GOPATH", func() (string, bool) {
			home := g.env["HOME"]
			return filepath.Join(home, "go"), home != ""
		})
		if !ok {
			return "", false
		}
		list := filepath.SplitList(gopath)
		if len(list) == 0 || list[0] == "" {
			return "", false
		}
		return filepath.Join(list[0], "pkg", "mod"), true
	})
	if !ok || !filepath.IsAbs(dir) {
		return true, nil
	}
	return samePath(dir, modcache), nil
}

// goProcEnv resolves go env settings of one Go process the way the go
// command does: a non-empty value in the process environment wins; then the
// go env file (GOENV, else $XDG_CONFIG_HOME/go/env or $HOME/.config/go/env;
// none for GOENV=off); then $GOROOT/go.env, where GOROOT comes from the env
// file, then the process environment, then the running executable. Values
// are kept verbatim.
type goProcEnv struct {
	procDir string
	env     map[string]string
	file    map[string]string // the go env file; nil until read
	rootEnv map[string]string // $GOROOT/go.env; nil until read
}

func readGoProcEnv(procDir string) (*goProcEnv, error) {
	raw, err := os.ReadFile(filepath.Join(procDir, "environ"))
	if err != nil {
		return nil, err
	}
	env := map[string]string{}
	for _, kv := range strings.Split(string(raw), "\x00") {
		if name, value, ok := strings.Cut(kv, "="); ok {
			env[name] = value
		}
	}
	return &goProcEnv{procDir: procDir, env: env}, nil
}

// lookup returns key's value and whether any source sets it. ok is false
// when a source that may set it cannot be established: a relative GOENV
// (Go resolved it against the directory it started in, before -C and before
// tool subprocesses change directory, so /proc/<pid>/cwd does not establish
// it), no absolute config home, an unreadable file, or an unknown GOROOT.
func (g *goProcEnv) lookup(key string) (value string, set, ok bool) {
	if v := g.env[key]; v != "" {
		return v, true, true
	}
	if g.file == nil {
		file := g.env["GOENV"]
		switch {
		case file == "off":
			file = ""
		case file != "" && !filepath.IsAbs(file):
			return "", false, false
		case file != "":
		case filepath.IsAbs(g.env["XDG_CONFIG_HOME"]):
			file = filepath.Join(g.env["XDG_CONFIG_HOME"], "go", "env")
		case filepath.IsAbs(g.env["HOME"]):
			file = filepath.Join(g.env["HOME"], ".config", "go", "env")
		default:
			return "", false, false
		}
		settings := map[string]string{}
		if file != "" {
			read, err := goEnvFile(file)
			if err != nil {
				return "", false, false
			}
			settings = read
		}
		g.file = settings
	}
	if v, set := g.file[key]; set {
		return v, true, true
	}
	if g.rootEnv == nil {
		root := g.file["GOROOT"]
		if root == "" {
			root = g.env["GOROOT"]
		}
		if root == "" {
			exe, err := os.Readlink(filepath.Join(g.procDir, "exe"))
			if err != nil {
				return "", false, false
			}
			root = goRootOf(exe)
		}
		if !filepath.IsAbs(root) {
			return "", false, false
		}
		settings, err := goEnvFile(filepath.Join(root, "go.env"))
		if err != nil {
			return "", false, false
		}
		g.rootEnv = settings
	}
	value, set = g.rootEnv[key]
	return value, set, true
}

// envOr is Go's EnvOr: key's value from lookup, or def() when it is empty.
// ok is false when either cannot be established.
func (g *goProcEnv) envOr(key string, def func() (string, bool)) (string, bool) {
	value, _, ok := g.lookup(key)
	switch {
	case !ok:
		return "", false
	case value != "":
		return value, true
	}
	return def()
}

// goCacheDirIs reports whether a resolved GOCACHE value is cache: "off" is
// no cache, and a relative value (which Go rejects) fails closed.
func goCacheDirIs(dir, cache string) bool {
	switch {
	case dir == "off":
		return false
	case !filepath.IsAbs(dir):
		return true
	}
	return samePath(dir, cache)
}

// goEnvFile reads a Go environment file the way the go command does: one
// KEY=VALUE per line, # comments, values kept byte for byte, the last
// setting of a key winning. A missing file holds no settings; any other
// read error is returned.
func goEnvFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	settings := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if key, value, ok := strings.Cut(line, "="); ok {
			settings[key] = value
		}
	}
	return settings, nil
}

// goRootOf derives GOROOT from a Go toolchain executable: <root>/bin/go, or
// <root>/pkg/tool/<os_arch>/<tool>. Anything else returns "".
func goRootOf(exe string) string {
	exe = strings.TrimSuffix(exe, " (deleted)")
	dir := filepath.Dir(exe)
	switch {
	case filepath.Base(dir) == "bin":
		return filepath.Dir(dir)
	case filepath.Base(filepath.Dir(filepath.Dir(dir))) == "pkg" && filepath.Base(filepath.Dir(dir)) == "tool":
		return filepath.Dir(filepath.Dir(filepath.Dir(dir)))
	}
	return ""
}

// samePath compares two paths after resolving symlinks where possible.
func samePath(a, b string) bool {
	resolve := func(p string) string {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return filepath.Clean(p)
	}
	return resolve(a) == resolve(b)
}

// processGone reports an error that means the process exited while it was
// being inspected.
func processGone(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH)
}

// goToolchainBusy reports a Go toolchain process. For the go command any
// build-like subcommand anywhere in its arguments counts, so global flags
// such as `-C dir` cannot hide the subcommand.
func goToolchainBusy(argv []string) bool {
	switch filepath.Base(argv[0]) {
	case "compile", "link", "asm", "cgo", "vet", "cover":
		return true
	case "go":
		for _, arg := range argv[1:] {
			switch arg {
			case "build", "test", "vet", "run", "install", "generate", "list", "tool", "get", "mod":
				return true
			}
		}
	}
	return false
}

func dockerBuildBusy(argv []string) bool {
	base := filepath.Base(argv[0])
	if base != "docker" && base != "docker-buildx" && base != "buildctl" && base != "docker-compose" {
		return false
	}
	for _, arg := range argv[1:] {
		if arg == "build" || arg == "bake" {
			return true
		}
	}
	return false
}

// dockerImageBusy reports an image build (as for docker-builder) or an image
// pull (`docker pull`, `docker image pull`, `docker compose pull`,
// `docker-compose pull`): a pulled image has no container yet, so a prune
// running meanwhile could remove what the client is about to use.
func dockerImageBusy(argv []string) bool {
	if dockerBuildBusy(argv) {
		return true
	}
	base := filepath.Base(argv[0])
	if base != "docker" && base != "docker-compose" {
		return false
	}
	for _, arg := range argv[1:] {
		if arg == "pull" {
			return true
		}
	}
	return false
}

// goModuleUser reports a process that may read or fill a Go module cache: a
// Go toolchain command, any go command, or gopls.
func goModuleUser(argv []string) bool {
	switch filepath.Base(argv[0]) {
	case "go", "gopls":
		return true
	}
	return goToolchainBusy(argv)
}

// pnpmBusy reports a running pnpm: the pnpm or pnpx executable itself, or a
// script launcher (node, corepack, ...) running one, which is how an npm-,
// nvm- or corepack-installed pnpm appears (`node /path/bin/pnpm install`).
func pnpmBusy(argv []string) bool {
	if pnpmName(argv[0]) {
		return true
	}
	switch filepath.Base(argv[0]) {
	case "node", "nodejs", "bun", "corepack", "npx", "npm":
	default:
		return false
	}
	for _, arg := range argv[1:] {
		if pnpmName(arg) {
			return true
		}
	}
	return false
}

func pnpmName(arg string) bool {
	base := filepath.Base(arg)
	for _, ext := range []string{".cjs", ".mjs", ".js"} {
		base = strings.TrimSuffix(base, ext)
	}
	return base == "pnpm" || base == "pnpx"
}

// executableUnder reports whether the process at procDir runs an executable
// below root. An unreadable link is an error, not "no".
func executableUnder(procDir, root string) (bool, error) {
	exe, err := os.Readlink(filepath.Join(procDir, "exe"))
	if processGone(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return core.PathWithin(strings.TrimSuffix(exe, " (deleted)"), root), nil
}

// holdsHandleUnder reports whether any descriptor in fdDir resolves below
// root. An unreadable descriptor table or link is an error, not "no".
func holdsHandleUnder(fdDir, root string) (bool, error) {
	fds, err := os.ReadDir(fdDir)
	if processGone(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	prefix := filepath.Clean(root) + string(filepath.Separator)
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
		if processGone(err) {
			continue // descriptor closed meanwhile
		}
		if err != nil {
			return false, err
		}
		if strings.HasPrefix(target, prefix) || target == filepath.Clean(root) {
			return true, nil
		}
	}
	return false, nil
}

// allocatedBytes is the allocated size of every regular file below dir.
func allocatedBytes(ctx context.Context, dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil // removed while walking: a concurrent build
			}
			return err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		info, err := d.Info()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			total += st.Blocks * 512
		}
		return nil
	})
	return total, err
}

func freeBytes(path string) *uint64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return nil
	}
	free := st.Bavail * uint64(st.Bsize)
	return &free
}

func boundedOutput(out []byte) string {
	return truncate(strings.TrimSpace(string(out)), 2000)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// archiveOnlyTrimRefusal says why trim may not run because its physical
// target is, or cannot be shown not to be, inside an archive_only root. A
// Docker trim is checked against the data root the daemon reports, not only
// the default one; a docker-images trim also against containerd's root, where
// the containerd image store keeps image content and snapshots.
func archiveOnlyTrimRefusal(ctx context.Context, policy *config.Policy, trim config.CacheTrim) string {
	targets := []string{trim.TrimTarget()}
	if trim.Kind == config.CacheTrimDockerBuilder || trim.Kind == config.CacheTrimDockerImages {
		root, err := dockerDataRoot(ctx, trim.Binary)
		if err != nil {
			return fmt.Sprintf("docker data root unknown, so it cannot be shown to be outside every archive_only root: %v", err)
		}
		targets = append(targets, root)
	}
	if trim.Kind == config.CacheTrimDockerImages {
		root, err := containerdRoot(containerdConfig)
		if err != nil {
			return fmt.Sprintf("containerd root unknown, so it cannot be shown to be outside every archive_only root: %v", err)
		}
		targets = append(targets, root)
	}
	for _, target := range targets {
		inside, err := config.ResolvesIntoArchiveOnlyRoot(policy, target)
		switch {
		case err != nil:
			return fmt.Sprintf("cannot be shown to be outside every archive_only root: %v", err)
		case inside:
			return fmt.Sprintf("%s resolves into an archive_only root", target)
		}
	}
	return ""
}

// containerdConfig is containerd's default configuration file.
const containerdConfig = "/etc/containerd/config.toml"

// containerdRoot is the root a containerd configuration file sets with its
// top-level `root` key, else containerd's default when the file does not
// exist. It fails closed: a file that cannot be read or parsed as TOML, or a
// root that is not a non-empty absolute path string, is an error.
func containerdRoot(file string) (string, error) {
	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return config.ContainerdDataRoot, nil
	}
	if err != nil {
		return "", err
	}
	var doc map[string]any
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return "", fmt.Errorf("parse %s: %w", file, err)
	}
	value, set := doc["root"]
	if !set {
		return config.ContainerdDataRoot, nil
	}
	root, ok := value.(string)
	if !ok || !filepath.IsAbs(root) {
		return "", fmt.Errorf("%s sets root %v, not an absolute path", file, value)
	}
	return filepath.Clean(root), nil
}

// dockerReclaimableImageBytes is the image space Docker reports as
// reclaimable (held by images no container uses), from `docker system df
// --format json`. Docker prints it rounded to four significant digits.
func dockerReclaimableImageBytes(ctx context.Context, binary string) (int64, error) {
	runCtx, cancel := context.WithTimeout(ctx, cacheTrimTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, binary, "system", "df", "--format", "json")
	cmd.Env = dockerEnv()
	cmd.Dir = "/"
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("docker system df: %w", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		var row struct{ Type, Reclaimable string }
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return 0, fmt.Errorf("docker system df: %w", err)
		}
		if row.Type != "Images" {
			continue
		}
		// "19.45GB (80%)": the size, then the share of all image bytes.
		size, _, _ := strings.Cut(row.Reclaimable, " ")
		bytes, err := parseDockerSize(size)
		if err != nil {
			return 0, fmt.Errorf("docker system df reclaimable images %q: %w", row.Reclaimable, err)
		}
		return bytes, nil
	}
	return 0, errors.New("docker system df reported no Images row")
}

// parseDockerSize parses a size as Docker prints it (decimal units, for
// example "0B", "970.8kB", "19.45GB").
func parseDockerSize(s string) (int64, error) {
	i := strings.IndexFunc(s, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	if i <= 0 {
		return 0, errors.New("not a size")
	}
	value, err := strconv.ParseFloat(s[:i], 64)
	if err != nil {
		return 0, err
	}
	unit := map[string]float64{"B": 1, "kB": 1e3, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12, "PB": 1e15}[s[i:]]
	if unit == 0 || value*unit >= math.MaxInt64 {
		return 0, errors.New("unknown unit or out of range")
	}
	return int64(value * unit), nil
}

// binaryOutside refuses a trim whose binary resolves into the cache it
// trims: the command would delete the program running it.
func binaryOutside(trim config.CacheTrim) error {
	resolved, err := filepath.EvalSymlinks(trim.Binary)
	if err != nil {
		return fmt.Errorf("resolve binary: %w", err)
	}
	if core.PathWithin(resolved, trim.Path) {
		return fmt.Errorf("binary %s resolves into %s", resolved, trim.Path)
	}
	return nil
}

// pnpmEnv is the environment pnpm runs with. pnpm installed by npm, nvm or
// corepack is a `#!/usr/bin/env node` script that needs the node beside it,
// so the binary's own directory (as configured, not resolved) leads PATH.
func pnpmEnv(binary string) []string {
	return []string{"HOME=" + os.Getenv("HOME"), "PATH=" + filepath.Dir(binary) + ":/usr/bin:/bin",
		"COREPACK_ENABLE_DOWNLOAD_PROMPT=0"}
}

// pnpmStoreIs checks that pnpm, given --store-dir path, acts on path itself.
// pnpm appends its store layout version (v10, v11, ...) to a directory that
// does not already end in it, so a configured parent directory would be
// measured but never pruned.
func pnpmStoreIs(ctx context.Context, binary string, env []string, path string) error {
	runCtx, cancel := context.WithTimeout(ctx, cacheTrimTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, binary, "store", "path", "--store-dir", path)
	cmd.Env = env
	cmd.Dir = "/"
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("pnpm store path: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	got := strings.TrimSpace(lines[len(lines)-1])
	if !filepath.IsAbs(got) || !samePath(got, path) {
		return fmt.Errorf("pnpm uses store %q for --store-dir %s; configure that directory as the path", got, path)
	}
	return nil
}

// dockerDataRoot asks the Docker daemon for its data root.
func dockerDataRoot(ctx context.Context, binary string) (string, error) {
	runCtx, cancel := context.WithTimeout(ctx, cacheTrimTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, binary, "info", "--format", "{{.DockerRootDir}}")
	cmd.Env = dockerEnv()
	cmd.Dir = "/"
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	root := strings.TrimSpace(string(out))
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("docker info reported data root %q", root)
	}
	return filepath.Clean(root), nil
}

// dockerEnv is the environment every Docker provider command runs with.
func dockerEnv() []string {
	return []string{"HOME=" + os.Getenv("HOME"), "PATH=/usr/bin:/bin"}
}
