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
// directory's own identity, and the object's identity. A removal that an
// identical original supersedes also names that outcome; a deletion keeps
// the format earlier releases wrote, so their markers still settle.
func markerContent(item core.CleanupItem, dir unix.Stat_t, outcome core.CleanupState) []byte {
	obj := item.Entry.FilesystemID
	content := fmt.Sprintf("%s dir=%d:%d object=%d:%d",
		item.ActionID, uint64(dir.Dev), dir.Ino, obj.Device, obj.Inode)
	if outcome == core.CleanupSuperseded {
		content += " " + string(outcome)
	}
	return []byte(content + "\n")
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

// writeDeletionMarker records that expiry is about to delete the object.
func writeDeletionMarker(item core.CleanupItem) error {
	return writeRemovalMarker(item, core.CleanupDeleted)
}

// writeRemovalMarker records, inside the receipt directory that actually
// holds the object, that expiry is about to remove it with outcome
// (CleanupDeleted or CleanupSuperseded); the latest attempt's marker
// replaces an earlier one. It refuses unless that directory, opened once,
// contains the recorded object.
func writeRemovalMarker(item core.CleanupItem, outcome core.CleanupState) error {
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
	content := markerContent(item, dirStat, outcome)
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

// deletionMarker reports the outcome with which expiry itself started
// removing this exact object from the receipt directory now at its path, or
// "" when there is no such marker. A directory moved away and replaced, even
// with the manifest and marker copied, has another identity and so does not
// match.
func deletionMarker(item core.CleanupItem) core.CleanupState {
	dir, dirStat, err := openReceiptDir(item)
	if err != nil {
		return ""
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, deletionMarkerName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ""
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > 4096 {
		return ""
	}
	got := make([]byte, st.Size+1)
	n, err := unix.Read(fd, got)
	if err != nil {
		return ""
	}
	for _, outcome := range []core.CleanupState{core.CleanupDeleted, core.CleanupSuperseded} {
		if string(got[:n]) == string(markerContent(item, dirStat, outcome)) {
			return outcome
		}
	}
	return ""
}
