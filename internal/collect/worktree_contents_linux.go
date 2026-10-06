//go:build linux

package collect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
)

const (
	worktreeMaxEntries  = 100000
	worktreeMaxDepth    = 64
	worktreeMaxGitBytes = 16 << 20
)

// proveWorktreeContents proves ignored files disposable, not merely Git-clean.
// Policy paths retain the receipt's original identity after quarantine. No
// policy conclusion is reused by mutation-time recollection.
func proveWorktreeContents(ctx context.Context, runner gitRunner, path string, opts *Options) error {
	ctx, cancel := context.WithTimeout(ctx, runner.timeout)
	defer cancel()
	origin := path
	if source, ok := opts.WorktreeOrigins[path]; ok {
		origin = source
	}
	if !core.IsCanonicalPath(origin) {
		return errors.New("worktree policy origin is not canonical")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("worktree contents cannot be opened: %w", err)
	}
	root := os.NewFile(uintptr(fd), path)
	defer root.Close()
	var initial unix.Stat_t
	if err := unix.Fstat(fd, &initial); err != nil {
		return err
	}
	mountID, err := worktreeMountID(fd, "")
	if err != nil {
		return err
	}
	// Index modes expose gitlinks even when their directories are empty or
	// absent. Git paths are NUL-delimited, never split on whitespace/newlines.
	index, err := runner.runOutput(ctx, path, worktreeMaxGitBytes, "ls-files", "--stage", "-z")
	if err != nil {
		return err
	}
	tracked := make(map[string]string)
	records := 0
	for index != "" {
		record, rest, ok := strings.Cut(index, "\x00")
		if !ok {
			return errors.New("incomplete Git index listing")
		}
		index = rest
		metadata, name, ok := strings.Cut(record, "\t")
		if !ok || !validWorktreeRelative(name) {
			return errors.New("invalid Git index path")
		}
		mode, _, ok := strings.Cut(metadata, " ")
		if !ok || (mode != "100644" && mode != "100755" && mode != "120000") {
			return errors.New("nested Git or unsupported index mode prevents whole-worktree cleanup")
		}
		records++
		if records > worktreeMaxEntries {
			return errors.New("worktree index entry bound exceeded")
		}
		tracked[name] = mode
	}
	count := 0
	if err := walkWorktreeContents(ctx, root, "", origin, opts.WorktreePolicy, tracked, uint64(initial.Dev), mountID, 0, &count); err != nil {
		return fmt.Errorf("worktree contents unproven: %w", err)
	}
	var current unix.Stat_t
	if err := unix.Lstat(path, &current); err != nil {
		return err
	}
	if !sameWorktreeDirectory(initial, current) {
		return errors.New("worktree identity changed during contents proof")
	}
	return ctx.Err()
}

func validWorktreeRelative(path string) bool {
	return path != "" && path != "." && !filepath.IsAbs(path) && filepath.Clean(path) == path && path != ".." && !strings.HasPrefix(path, "../")
}

func destructiveUnboundedCache(rule config.CacheRule) bool {
	return (rule.Action == core.ActionQuarantine || rule.Action == core.ActionDeleteCandidate) && rule.MaxBytes == 0 && rule.TTL == 0
}

func approvedWorktreeCache(path, origin string, policy *config.Policy) bool {
	if policy == nil {
		return false
	}
	approved := false
	for _, rule := range policy.Caches {
		if !core.IsCanonicalPath(rule.Path) {
			return false
		}
		if core.PathsOverlap(path, rule.Path) && !destructiveUnboundedCache(rule) {
			return false
		}
		if rule.Path != origin && core.PathWithin(rule.Path, origin) && core.PathWithin(path, rule.Path) && destructiveUnboundedCache(rule) {
			approved = true
		}
	}
	return approved
}

func worktreePolicyVeto(path string, policy *config.Policy) error {
	if policy == nil {
		return nil
	}
	for _, protected := range policy.Protect.Paths {
		if core.PathsOverlap(path, protected) {
			return errors.New("worktree descendant overlaps a protected path")
		}
	}
	for _, root := range policy.Roots {
		if root.ReportOnly && core.PathsOverlap(path, root.Path) {
			return errors.New("worktree descendant overlaps a report-only root")
		}
	}
	for _, rule := range policy.Caches {
		if core.PathsOverlap(path, rule.Path) && !destructiveUnboundedCache(rule) {
			return errors.New("worktree descendant has a preserving or bounded cache rule")
		}
	}
	name := filepath.Base(path)
	for _, patterns := range [][]string{policy.Protect.NamePatterns, policy.Classification.EvidenceNames} {
		for _, pattern := range patterns {
			matched, err := filepath.Match(pattern, name)
			if err != nil || matched {
				return errors.New("worktree descendant has a protected credential or evidence name")
			}
		}
	}
	return nil
}

func walkWorktreeContents(ctx context.Context, dir *os.File, relative, origin string, policy *config.Policy, tracked map[string]string, device, mountID uint64, depth int, count *int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth >= worktreeMaxDepth {
		return errors.New("worktree contents depth bound exceeded")
	}
	var before unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &before); err != nil {
		return err
	}
	for {
		children, readErr := dir.Readdirnames(128)
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		for _, name := range children {
			if err := ctx.Err(); err != nil {
				return err
			}
			*count++
			if *count > worktreeMaxEntries {
				return errors.New("worktree contents entry bound exceeded")
			}
			if name == ".git" {
				if relative == "" {
					continue
				}
				return errors.New("nested Git metadata prevents whole-worktree cleanup")
			}
			rel := filepath.Join(relative, name)
			if err := worktreePolicyVeto(filepath.Join(origin, rel), policy); err != nil {
				return err
			}
			var stat unix.Stat_t
			if err := unix.Fstatat(int(dir.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			childMount, err := worktreeMountID(int(dir.Fd()), name)
			if err != nil {
				return err
			}
			if childMount != mountID {
				return errors.New("worktree contents cross a mount boundary")
			}
			if uint64(stat.Dev) != device {
				return errors.New("worktree contents cross a filesystem boundary")
			}
			switch stat.Mode & unix.S_IFMT {
			case unix.S_IFREG, unix.S_IFLNK:
				if stat.Mode&unix.S_IFMT == unix.S_IFREG && core.IsDatabasePath(rel) {
					return errors.New("worktree descendant may be a live database")
				}
				mode, known := tracked[rel]
				if known {
					if (mode == "120000") != (stat.Mode&unix.S_IFMT == unix.S_IFLNK) {
						return errors.New("tracked descendant type changed")
					}
				} else {
					if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
						return errors.New("untracked symlink is not reconstructible")
					}
					if !approvedWorktreeCache(filepath.Join(origin, rel), origin, policy) {
						return errors.New("untracked or ignored content has no explicit regenerable-cache approval")
					}
				}
			case unix.S_IFDIR:
				if stat.Mode&0444 == 0 || stat.Mode&0111 == 0 {
					return errors.New("worktree descendant directory is unreadable")
				}
				fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if err != nil {
					return err
				}
				child := os.NewFile(uintptr(fd), name)
				var opened unix.Stat_t
				err = unix.Fstat(fd, &opened)
				if err == nil && (stat.Dev != opened.Dev || stat.Ino != opened.Ino) {
					err = errors.New("worktree descendant identity changed")
				}
				if err == nil {
					err = walkWorktreeContents(ctx, child, rel, origin, policy, tracked, device, mountID, depth+1, count)
				}
				if err == nil {
					var current unix.Stat_t
					err = unix.Fstatat(int(dir.Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW)
					if err == nil && !sameWorktreeDirectory(opened, current) {
						err = errors.New("worktree descendant directory changed during proof")
					}
				}
				child.Close()
				if err != nil {
					return err
				}
			default:
				return errors.New("special worktree descendant is not reconstructible")
			}
		}
		if readErr == io.EOF {
			var after unix.Stat_t
			if err := unix.Fstat(int(dir.Fd()), &after); err != nil {
				return err
			}
			if !sameWorktreeDirectory(before, after) {
				return errors.New("worktree directory changed during proof")
			}
			return nil
		}
	}
}

// Device IDs alone miss bind mounts on the same filesystem. An unavailable
// mount identity is incomplete evidence, never permission to traverse it.
func worktreeMountID(parent int, name string) (uint64, error) {
	var stat unix.Statx_t
	err := unix.Statx(parent, name, unix.AT_SYMLINK_NOFOLLOW|unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stat)
	if err != nil {
		return 0, err
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 {
		return 0, errors.New("worktree mount identity unavailable")
	}
	return stat.Mnt_id, nil
}

func sameWorktreeDirectory(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
