//go:build linux

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
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
// tree). A directory that is not a cargo target (identify) is refused; one
// a path_glob matched is reported as not_cargo_target instead. The
// trim is skipped as in use while anything in the top two levels changed
// within min_idle, while a process may use the directory (cargoTargetUser),
// or while any cargo lock is held; it holds every lock while removing.
//
// The target and its profile directories are opened once, when validated;
// locking and removal go through those descriptors only. Under the locks,
// before removing anything, the path must still name the validated target
// and profiles and still be a cargo target, else the trim fails and
// removes nothing. Removal never follows a symlink and never crosses into
// another filesystem.
//
// A target a path_glob discovered is passed with bound, the identity it had
// when discovered (discoverCargoTargets); one that is no longer that
// directory is refused before anything else is read from it.
func trimCargoTarget(ctx context.Context, procRoot string, trim config.CacheTrim, bound core.FilesystemID, report cacheTrimReport) cacheTrimReport {
	fail := func(err error) cacheTrimReport {
		report.Status, report.Error = cacheTrimFailed, err.Error()
		return report
	}
	target, err := openCargoTarget(trim.Path, bound)
	if errors.Is(err, unix.ENOENT) {
		report.Status = cacheTrimNotFound
		return report
	}
	if errors.Is(err, errNotCargoTarget) && trim.PathGlob != "" {
		report.Status, report.Error = cacheTrimNotCargo, err.Error()
		return report
	}
	if err != nil {
		return fail(err)
	}
	defer target.close()
	size, err := allocatedBytes(ctx, trim.Path)
	if err != nil {
		return fail(fmt.Errorf("measure: %w", err))
	}
	report.SizeBefore = &size
	if size <= trim.MaxBytes {
		report.Status = cacheUnderBound
		return report
	}
	if err := target.findProfiles(); err != nil {
		return fail(err)
	}
	recent, err := target.changedSince(time.Now().Add(-trim.MinIdle.Duration()))
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
	release, held := target.lock()
	defer release()
	if len(held) != 0 {
		report.Status, report.ActiveUsers = cacheInUse, held
		return report
	}
	if err := target.verify(); err != nil {
		return fail(err)
	}
	report.FreeBefore = freeBytes(trimFilesystem(trim))
	removeErr := target.removeOutputs(ctx)
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

// cargoTarget is a validated cargo target directory held open with its
// profile directories.
type cargoTarget struct {
	path     string
	fd       int
	id       core.FilesystemID
	profiles []cargoProfile
	// profilesFound records that findProfiles has run.
	profilesFound bool
}

type cargoProfile struct {
	name string
	fd   int
	id   core.FilesystemID
}

// openCargoTarget opens path, refusing a symlink in any component, checks
// that it is still bound (when set) and that it is a cargo target directory
// (identify).
func openCargoTarget(path string, bound core.FilesystemID) (*cargoTarget, error) {
	fd, err := action.OpenDirNoSymlinks(path)
	if err != nil {
		return nil, err
	}
	target := &cargoTarget{path: path, fd: fd}
	id, err := fdIdentity(fd)
	if err != nil {
		target.close()
		return nil, err
	}
	target.id = id
	if !bound.Zero() && id != bound {
		target.close()
		return nil, fmt.Errorf("%s is not the directory discovered there (%s, now %s); refused", path, bound, id)
	}
	if err := target.identify(); err != nil {
		target.close()
		return nil, err
	}
	return target, nil
}

func (t *cargoTarget) close() {
	for _, profile := range t.profiles {
		unix.Close(profile.fd)
	}
	unix.Close(t.fd)
}

// errNotCargoTarget marks a directory that is neither tagged nor laid out
// as a cargo target directory.
var errNotCargoTarget = errors.New("not a cargo target directory")

// identify checks that the target is a cargo target directory: it holds
// the CACHEDIR.TAG cargo writes (a regular file starting with cargo's
// cache directory tag signature), or it holds no CACHEDIR.TAG at all and at
// least one profile directory (findProfiles: a top-level real directory
// holding a regular .cargo-lock), the layout cargo builds into (cargo
// writes the tag only into a target directory it creates, so a pre-created
// CARGO_TARGET_DIR has none). Any other CACHEDIR.TAG belongs to another
// tool and is refused.
func (t *cargoTarget) identify() error {
	refuse := func(why string) error {
		return fmt.Errorf("%s %s; %w, refused", t.path, why, errNotCargoTarget)
	}
	fd, err := unix.Openat(t.fd, "CACHEDIR.TAG", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		if err := t.findProfiles(); err != nil {
			return err
		}
		if len(t.profiles) != 0 {
			return nil
		}
		return refuse("has neither cargo's CACHEDIR.TAG nor a profile directory holding .cargo-lock")
	}
	if errors.Is(err, unix.ELOOP) {
		return refuse("has a CACHEDIR.TAG symlink, not cargo's CACHEDIR.TAG")
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "CACHEDIR.TAG")
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return refuse("has a CACHEDIR.TAG that is not a regular file, not cargo's CACHEDIR.TAG")
	}
	head := make([]byte, len(cargoTagSignature))
	if _, err := io.ReadFull(file, head); err != nil || !bytes.Equal(head, []byte(cargoTagSignature)) {
		return refuse("has a CACHEDIR.TAG without cargo's signature, not cargo's CACHEDIR.TAG")
	}
	return nil
}

// findProfiles opens, once, the profile directories: top-level real
// directories holding a regular .cargo-lock. One on another filesystem is
// an error.
func (t *cargoTarget) findProfiles() error {
	if t.profilesFound {
		return nil
	}
	t.profilesFound = true
	names, err := dirNames(t.fd)
	if err != nil {
		return err
	}
	for _, name := range names {
		fd, err := unix.Openat(t.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return err
		}
		var lock unix.Stat_t
		err = unix.Fstatat(fd, ".cargo-lock", &lock, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) || (err == nil && lock.Mode&unix.S_IFMT != unix.S_IFREG) {
			unix.Close(fd)
			continue
		}
		id, idErr := fdIdentity(fd)
		if err == nil {
			err = idErr
		}
		if err == nil && id.Device != t.id.Device {
			err = fmt.Errorf("%s is on another filesystem; refused", filepath.Join(t.path, name))
		}
		if err != nil {
			unix.Close(fd)
			return err
		}
		t.profiles = append(t.profiles, cargoProfile{name: name, fd: fd, id: id})
	}
	return nil
}

// changedSince names the newest entry modified after cutoff among the
// target, its entries and each profile directory's entries, or "" when
// nothing there changed since. Symlinks are not followed.
func (t *cargoTarget) changedSince(cutoff time.Time) (string, error) {
	var st unix.Stat_t
	if err := unix.Fstat(t.fd, &st); err != nil {
		return "", err
	}
	newest, newestPath := time.Unix(st.Mtim.Unix()), t.path
	dirs := map[string]int{t.path: t.fd}
	for _, profile := range t.profiles {
		dirs[filepath.Join(t.path, profile.name)] = profile.fd
	}
	for dir, fd := range dirs {
		names, err := dirNames(fd)
		if err != nil {
			return "", err
		}
		for _, name := range names {
			err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			if err != nil {
				return "", err
			}
			if mtime := time.Unix(st.Mtim.Unix()); mtime.After(newest) {
				newest, newestPath = mtime, filepath.Join(dir, name)
			}
		}
	}
	if !newest.After(cutoff) {
		return "", nil
	}
	return fmt.Sprintf("%s modified %s, within min_idle", newestPath, newest.UTC().Format(time.RFC3339)), nil
}

// lock takes, without waiting, an exclusive flock on every cargo lock file
// present in each profile directory, opened through the profile's
// descriptor. held lists each lock it could not take: one a build holds, or
// one it could not open or lock, which counts as held. release drops every
// lock taken.
func (t *cargoTarget) lock() (release func(), held []string) {
	var files []*os.File
	release = func() {
		for _, file := range files {
			_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
			file.Close()
		}
	}
	for _, profile := range t.profiles {
		for _, name := range cargoLockFiles {
			path := filepath.Join(t.path, profile.name, name)
			fd, err := unix.Openat(profile.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
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

// verify checks, just before removal, that the path still names the
// validated target, each profile name still the validated profile, and that
// the target is still a cargo target directory.
func (t *cargoTarget) verify() error {
	changed := fmt.Errorf("%s changed since it was validated; nothing removed", t.path)
	fd, err := action.OpenDirNoSymlinks(t.path)
	if err != nil {
		return fmt.Errorf("%w: %v", changed, err)
	}
	defer unix.Close(fd)
	if id, err := fdIdentity(fd); err != nil || id != t.id {
		return changed
	}
	for _, profile := range t.profiles {
		var st unix.Stat_t
		if err := unix.Fstatat(fd, profile.name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
			(core.FilesystemID{Device: uint64(st.Dev), Inode: st.Ino}) != profile.id {
			return changed
		}
	}
	if err := t.identify(); err != nil {
		return fmt.Errorf("%w: %v", changed, err)
	}
	return nil
}

// removeOutputs removes, anchored at the validated descriptors, every entry
// of each profile directory except cargo's lock files, every entry of tmp
// (when it is a real directory), and .rustc_info.json. It carries on past a
// failed entry and returns every failure.
func (t *cargoTarget) removeOutputs(ctx context.Context) error {
	var errs []error
	remove := func(dir int, path, name string) {
		if err := action.RemoveAt(ctx, dir, name, t.id.Device); err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("remove %s: %w", filepath.Join(path, name), err))
		}
	}
	contents := func(dir int, path string, keep []string) {
		names, err := dirNames(dir)
		if err != nil {
			errs = append(errs, fmt.Errorf("list %s: %w", path, err))
			return
		}
		for _, name := range names {
			if !slices.Contains(keep, name) {
				remove(dir, path, name)
			}
		}
	}
	for _, profile := range t.profiles {
		contents(profile.fd, filepath.Join(t.path, profile.name), cargoLockFiles)
	}
	tmp, err := unix.Openat(t.fd, "tmp", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	switch {
	case err == nil:
		contents(tmp, filepath.Join(t.path, "tmp"), nil)
		unix.Close(tmp)
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.ELOOP):
	default:
		errs = append(errs, fmt.Errorf("open %s: %w", filepath.Join(t.path, "tmp"), err))
	}
	remove(t.fd, t.path, ".rustc_info.json")
	return errors.Join(errs...)
}

// dirNames lists the directory open as fd through a fresh descriptor, so fd
// itself keeps no read offset.
func dirNames(fd int) ([]string, error) {
	dup, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(dup), ".")
	defer file.Close()
	return file.Readdirnames(-1)
}

func fdIdentity(fd int) (core.FilesystemID, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return core.FilesystemID{}, err
	}
	return core.FilesystemID{Device: uint64(st.Dev), Inode: st.Ino}, nil
}

// cargoMatch is one directory a cargo-target path_glob matched, with the
// identity it had when discovered.
type cargoMatch struct {
	path string
	id   core.FilesystemID
}

// discoverCargoTargets opens parent without following symlinks and lists,
// in name order, its real directories whose name matches pattern, leaving
// out the paths in skip. Each is opened through parent's descriptor with
// O_NOFOLLOW and its identity bound, so a match later replaced (by a
// symlink or another directory) is refused when its trim opens it.
func discoverCargoTargets(parent, pattern string, skip map[string]bool) ([]cargoMatch, error) {
	dir, err := action.OpenDirNoSymlinks(parent)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	names, err := dirNames(dir)
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	var matches []cargoMatch
	for _, name := range names {
		path := filepath.Join(parent, name)
		if matched, _ := filepath.Match(pattern, name); !matched || skip[path] {
			continue
		}
		fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		id, err := fdIdentity(fd)
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		matches = append(matches, cargoMatch{path: path, id: id})
	}
	return matches, nil
}
