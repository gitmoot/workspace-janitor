//go:build linux

package action

import (
	"errors"
	"fmt"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
	"path/filepath"
)

// deletionMarkerName is the file Delete writes into a receipt directory,
// durably, just before it deletes the quarantined object.
const deletionMarkerName = "deleting"

// markerContent binds a marker to one receipt: its action, the receipt
// directory's own identity, and the object's identity.
func markerContent(item core.CleanupItem, dir unix.Stat_t) []byte {
	obj := item.Entry.FilesystemID
	return []byte(fmt.Sprintf("%s dir=%d:%d object=%d:%d\n",
		item.ActionID, uint64(dir.Dev), dir.Ino, obj.Device, obj.Inode))
}

// openReceiptDir opens the receipt directory without following a symlink and
// returns its handle and identity. Every later step works through the handle,
// so a directory renamed or replaced meanwhile is never mistaken for it.
func openReceiptDir(item core.CleanupItem) (int, unix.Stat_t, error) {
	var st unix.Stat_t
	fd, err := unix.Open(filepath.Dir(item.Destination),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, st, err
	}
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return -1, st, err
	}
	return fd, st, nil
}

// writeDeletionMarker records, inside the receipt directory that actually
// holds the object, that expiry is about to delete it. It refuses unless that
// directory, opened once, contains the recorded object.
func writeDeletionMarker(item core.CleanupItem) error {
	dir, dirStat, err := openReceiptDir(item)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	var obj unix.Stat_t
	if err := unix.Fstatat(dir, filepath.Base(item.Destination), &obj, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("receipt directory does not hold the object: %w", err)
	}
	if (core.FilesystemID{Device: uint64(obj.Dev), Inode: obj.Ino}) != item.Entry.FilesystemID {
		return errors.New("receipt directory holds a different object")
	}
	fd, err := unix.Openat(dir, deletionMarkerName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	content := markerContent(item, dirStat)
	if _, err := unix.Write(fd, content); err != nil {
		unix.Close(fd)
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		unix.Close(fd)
		return err
	}
	if err := unix.Close(fd); err != nil {
		return err
	}
	return unix.Fsync(dir)
}

// hasDeletionMarker reports whether expiry itself started deleting this exact
// object from the receipt directory now at its path. A directory moved away
// and replaced, even with the manifest and marker copied, has another
// identity and so does not match.
func hasDeletionMarker(item core.CleanupItem) bool {
	dir, dirStat, err := openReceiptDir(item)
	if err != nil {
		return false
	}
	defer unix.Close(dir)
	want := markerContent(item, dirStat)
	fd, err := unix.Openat(dir, deletionMarkerName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size != int64(len(want)) {
		return false
	}
	got := make([]byte, len(want)+1)
	n, err := unix.Read(fd, got)
	return err == nil && string(got[:n]) == string(want)
}
