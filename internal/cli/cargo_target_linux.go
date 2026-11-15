//go:build linux

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/action"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
)

// cargoTagSignature starts the CACHEDIR.TAG cargo writes into every target
// directory it creates.
const cargoTagSignature = "Signature: 8a477f597d28d172789f06886806bc55"

// cargoLockFiles are the build locks cargo takes in a profile directory:
// .cargo-lock (every cargo; shared by newer ones), .cargo-build-lock and
// .cargo-artifact-lock (newer ones). The trim holds each one present and
// never removes them, so a build starting mid-trim blocks on the same file.
var cargoLockFiles = []string{".cargo-lock", ".cargo-build-lock", ".cargo-artifact-lock"}

// trimCargoTarget removes what `cargo clean` would from a cargo target
// directory whose allocated size exceeds max_bytes: the contents of each
// profile directory (a top-level directory holding .cargo-lock) and of tmp,
// and .rustc_info.json. It keeps the directory itself, its CACHEDIR.TAG and
// cargo's lock files. It runs no command (cargo clean needs the source
// tree). A target directory without cargo's CACHEDIR.TAG is refused. The
// trim is skipped as in use while anything in the top two levels changed
// within min_idle, while a process may use the directory (cargoTargetUser),
// or while any cargo lock is held; it holds every lock while removing.
// Removal never follows a symlink and never crosses into another filesystem.
func trimCargoTarget(ctx context.Context, procRoot string, trim config.CacheTrim, report cacheTrimReport) cacheTrimReport {
	fail := func(err error) cacheTrimReport {
		report.Status, report.Error = cacheTrimFailed, err.Error()
		return report
	}
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
	device := uint64(info.Sys().(*syscall.Stat_t).Dev)
	if err := cargoTargetTagged(trim.Path); err != nil {
		return fail(err)
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
	profiles, err := cargoProfiles(trim.Path, device)
	if err != nil {
		return fail(err)
	}
	recent, err := cargoTargetChange(trim.Path, profiles, time.Now().Add(-trim.MinIdle.Duration()))
	if err != nil {
		return fail(err)
	}
	if recent != "" {
		report.Status, report.ActiveUsers = cacheInUse, []string{recent}
		return report
	}
	if users := cacheUsers(procRoot, trim); len(users) != 0 {
		report.Status, report.ActiveUsers = cacheInUse, users
		return report
	}
	release, held := lockCargoProfiles(trim.Path, profiles)
	defer release()
	if len(held) != 0 {
		report.Status, report.ActiveUsers = cacheInUse, held
		return report
	}
	report.FreeBefore = freeBytes(trimFilesystem(trim))
	removeErr := removeCargoOutputs(ctx, trim.Path, device, profiles)
	report.FreeAfter = freeBytes(trimFilesystem(trim))
	if after, err := allocatedBytes(ctx, trim.Path); err == nil {
		reclaimed := max(size-after, 0)
		report.SizeAfter, report.Reclaimed = &after, &reclaimed
	}
	if removeErr != nil {
		return fail(removeErr)
	}
	report.Status = cacheTrimmed
	return report
}

// cargoTargetTagged checks that dir holds the CACHEDIR.TAG cargo writes, a
// regular file starting with the cache directory tag signature.
func cargoTargetTagged(dir string) error {
	refuse := fmt.Errorf("%s has no cargo CACHEDIR.TAG; not a cargo target directory, refused", dir)
	fd, err := unix.Open(filepath.Join(dir, "CACHEDIR.TAG"), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) {
		return refuse
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "CACHEDIR.TAG")
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return refuse
	}
	head := make([]byte, len(cargoTagSignature))
	if _, err := io.ReadFull(file, head); err != nil || !bytes.Equal(head, []byte(cargoTagSignature)) {
		return refuse
	}
	return nil
}

// cargoProfiles lists the profile directories of target: top-level real
// directories holding a regular .cargo-lock. A profile directory on another
// filesystem is an error.
func cargoProfiles(target string, device uint64) ([]string, error) {
	entries, err := os.ReadDir(target)
	if err != nil {
		return nil, err
	}
	var profiles []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		lock, err := os.Lstat(filepath.Join(target, entry.Name(), ".cargo-lock"))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !lock.Mode().IsRegular() {
			continue
		}
		info, err := os.Lstat(filepath.Join(target, entry.Name()))
		if err != nil {
			return nil, err
		}
		if uint64(info.Sys().(*syscall.Stat_t).Dev) != device {
			return nil, fmt.Errorf("%s is on another filesystem; refused", filepath.Join(target, entry.Name()))
		}
		profiles = append(profiles, entry.Name())
	}
	return profiles, nil
}

// cargoTargetChange names the newest entry modified after cutoff among
// target, its entries and each profile directory's entries, or "" when
// nothing there changed since. Symlinks are not followed.
func cargoTargetChange(target string, profiles []string, cutoff time.Time) (string, error) {
	dirs := []string{target}
	for _, profile := range profiles {
		dirs = append(dirs, filepath.Join(target, profile))
	}
	var newest time.Time
	var newestPath string
	consider := func(path string) error {
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.ModTime().After(newest) {
			newest, newestPath = info.ModTime(), path
		}
		return nil
	}
	if err := consider(target); err != nil {
		return "", err
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return "", err
		}
		for _, entry := range entries {
			if err := consider(filepath.Join(dir, entry.Name())); err != nil {
				return "", err
			}
		}
	}
	if !newest.After(cutoff) {
		return "", nil
	}
	return fmt.Sprintf("%s modified %s, within min_idle", newestPath, newest.UTC().Format(time.RFC3339)), nil
}

// lockCargoProfiles takes, without waiting, an exclusive flock on every
// cargo lock file present in each profile directory. held lists each lock it
// could not take: one a build holds, or one it could not open or lock, which
// counts as held. release drops every lock taken.
func lockCargoProfiles(target string, profiles []string) (release func(), held []string) {
	var files []*os.File
	release = func() {
		for _, file := range files {
			_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
			file.Close()
		}
	}
	for _, profile := range profiles {
		for _, name := range cargoLockFiles {
			path := filepath.Join(target, profile, name)
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if errors.Is(err, unix.ENOENT) && name != ".cargo-lock" {
				continue
			}
			if err != nil {
				held = append(held, fmt.Sprintf("%s (cannot open: %v)", path, err))
				continue
			}
			file := os.NewFile(uintptr(fd), path)
			if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
				file.Close()
				held = append(held, path+" (not a regular file)")
				continue
			}
			if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
				file.Close()
				if errors.Is(err, unix.EWOULDBLOCK) {
					held = append(held, path+" (held by a cargo build)")
				} else {
					held = append(held, fmt.Sprintf("%s (cannot lock: %v)", path, err))
				}
				continue
			}
			files = append(files, file)
		}
	}
	return release, held
}

// removeCargoOutputs removes every entry of each profile directory except
// cargo's lock files, every entry of tmp (when it is a real directory), and
// .rustc_info.json. It carries on past a failed entry and returns every
// failure.
func removeCargoOutputs(ctx context.Context, target string, device uint64, profiles []string) error {
	var errs []error
	contents := func(dir string, keep []string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			errs = append(errs, err)
			return
		}
		for _, entry := range entries {
			if !slices.Contains(keep, entry.Name()) {
				errs = append(errs, removeCargoEntry(ctx, filepath.Join(dir, entry.Name()), device))
			}
		}
	}
	for _, profile := range profiles {
		contents(filepath.Join(target, profile), cargoLockFiles)
	}
	tmp := filepath.Join(target, "tmp")
	if info, err := os.Lstat(tmp); err == nil && info.IsDir() {
		contents(tmp, nil)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, err)
	}
	errs = append(errs, removeCargoEntry(ctx, filepath.Join(target, ".rustc_info.json"), device))
	return errors.Join(errs...)
}

// removeCargoEntry removes one file, symlink (never its target) or
// directory tree at path, refusing one on another filesystem than device or
// with a mount below it.
func removeCargoEntry(ctx context.Context, path string, device uint64) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	st := info.Sys().(*syscall.Stat_t)
	if uint64(st.Dev) != device {
		return fmt.Errorf("%s is on another filesystem; not removed", path)
	}
	if err := action.RemoveAnchored(ctx, path, core.FilesystemID{Device: device, Inode: st.Ino}, st.Ctim.Sec*1e9+st.Ctim.Nsec); err != nil {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}
