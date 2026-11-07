package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
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

type cacheTrimReport struct {
	Kind        string   `json:"kind"`
	Path        string   `json:"path,omitempty"`
	MaxBytes    int64    `json:"max_bytes"`
	Status      string   `json:"status"`
	SizeBefore  *int64   `json:"size_before_bytes,omitempty"`
	SizeAfter   *int64   `json:"size_after_bytes,omitempty"`
	FreeBefore  *uint64  `json:"free_before_bytes,omitempty"`
	FreeAfter   *uint64  `json:"free_after_bytes,omitempty"`
	Command     []string `json:"command,omitempty"`
	ActiveUsers []string `json:"active_users,omitempty"`
	Output      string   `json:"output,omitempty"`
	Error       string   `json:"error,omitempty"`
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
	case config.CacheTrimGoBuild:
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
		args = []string{"clean", "-cache"}
		env = []string{"GOCACHE=" + trim.Path, "GOTOOLCHAIN=local", "GOENV=off", "GOFLAGS=", "GOPROXY=off",
			"HOME=" + os.Getenv("HOME"), "PATH=/usr/bin:/bin"}
	case config.CacheTrimDockerBuilder:
		// Docker enforces the bound itself and removes only unused build
		// cache: never images, containers or volumes.
		args = []string{"builder", "prune", "--force", "--max-used-space", strconv.FormatInt(trim.MaxBytes, 10)}
		env = dockerEnv()
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
	if trim.Kind == config.CacheTrimGoBuild {
		if size, sizeErr := allocatedBytes(ctx, trim.Path); sizeErr == nil {
			report.SizeAfter = &size
		}
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
// toolchain commands for go-build (plus any handle open under the cache), or
// image builds for Docker. It fails closed: a process that cannot be
// inspected counts as a possible user. A false positive only postpones the
// trim to the next cycle.
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
		switch trim.Kind {
		case config.CacheTrimGoBuild:
			busy = goToolchainBusy(argv)
			if busy {
				// A Go process with its own GOCACHE elsewhere does not use
				// this cache; only one that resolves here (or cannot be
				// resolved) blocks the trim.
				uses, err := goProcessUsesCache(filepath.Join(procRoot, pid), trim.Path)
				if processGone(err) {
					continue
				}
				if err != nil {
					users = append(users, fmt.Sprintf("%s (cannot inspect environment: %v)", pid, err))
					continue
				}
				busy = uses
			}
			if !busy {
				holds, err := holdsHandleUnder(filepath.Join(procRoot, pid, "fd"), trim.Path)
				if err != nil {
					users = append(users, fmt.Sprintf("%s (cannot inspect handles: %v)", pid, err))
					continue
				}
				busy = holds
			}
		case config.CacheTrimDockerBuilder:
			busy = dockerBuildBusy(argv)
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
// GOCACHE: the process environment, then the go env file (GOENV, or
// $XDG_CONFIG_HOME/go/env or $HOME/.config/go/env, unless GOENV=off), then
// $GOROOT/go.env, then the default $XDG_CACHE_HOME/go-build or
// $HOME/.cache/go-build. GOCACHE=off uses no cache. It fails closed: a value
// that cannot be established, or an existing file that cannot be read,
// counts the process as a user.
func goProcessUsesCache(procDir, cache string) (bool, error) {
	raw, err := os.ReadFile(filepath.Join(procDir, "environ"))
	if err != nil {
		return false, err
	}
	env := map[string]string{}
	for _, kv := range strings.Split(string(raw), "\x00") {
		if name, value, ok := strings.Cut(kv, "="); ok {
			env[name] = value
		}
	}
	dir, set := env["GOCACHE"], env["GOCACHE"] != ""
	if !set {
		file := env["GOENV"]
		switch {
		case file == "off":
			file = ""
		case file != "":
		case filepath.IsAbs(env["XDG_CONFIG_HOME"]):
			file = filepath.Join(env["XDG_CONFIG_HOME"], "go", "env")
		case filepath.IsAbs(env["HOME"]):
			file = filepath.Join(env["HOME"], ".config", "go", "env")
		default:
			return true, nil
		}
		if file != "" {
			value, found, err := goEnvFileValue(file, "GOCACHE")
			if err != nil {
				return true, nil
			}
			dir, set = value, found
		}
	}
	if !set {
		root := env["GOROOT"]
		if root == "" {
			exe, err := os.Readlink(filepath.Join(procDir, "exe"))
			if err != nil {
				return true, nil
			}
			root = goRootOf(exe)
		}
		if !filepath.IsAbs(root) {
			return true, nil
		}
		value, found, err := goEnvFileValue(filepath.Join(root, "go.env"), "GOCACHE")
		if err != nil {
			return true, nil
		}
		dir, set = value, found
	}
	switch {
	case dir == "off":
		return false, nil
	case set:
	case filepath.IsAbs(env["XDG_CACHE_HOME"]):
		dir = filepath.Join(env["XDG_CACHE_HOME"], "go-build")
	case filepath.IsAbs(env["HOME"]):
		dir = filepath.Join(env["HOME"], ".cache", "go-build")
	default:
		return true, nil
	}
	if !filepath.IsAbs(dir) {
		return true, nil
	}
	return samePath(dir, cache), nil
}

// goEnvFileValue reads one KEY=VALUE setting from a Go environment file. A
// missing file holds no settings; any other read error is returned.
func goEnvFileValue(path, key string) (string, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	value, found := "", false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == key {
			value, found = strings.TrimSpace(v), true
		}
	}
	return value, found, nil
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
// docker-builder trim is checked against the data root the daemon reports,
// not only the default one.
func archiveOnlyTrimRefusal(ctx context.Context, policy *config.Policy, trim config.CacheTrim) string {
	targets := []string{trim.TrimTarget()}
	if trim.Kind == config.CacheTrimDockerBuilder {
		root, err := dockerDataRoot(ctx, trim.Binary)
		if err != nil {
			return fmt.Sprintf("docker data root unknown, so it cannot be shown to be outside every archive_only root: %v", err)
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
