//go:build linux

package action

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
)

// entryStamp is what a comparison saw of one entry before it read it. Every
// change to an inode's data, metadata or (for a directory) its entries
// advances its change time, and userspace cannot set that time back, so an
// unchanged stamp proves the entry still holds what was compared.
type entryStamp struct {
	dev, ino uint64
	ctimeNS  int64
	size     int64
}

// supersedeProof proves that the object at the original path was, entry by
// entry, the quarantined copy (identical), or held every entry of it
// (contained): stamps of both trees in walk order.
type supersedeProof struct {
	original, copy string
	copyID         core.FilesystemID
	maxEntries     int
	contained      bool
	stamps         []entryStamp
}

// compareChunk is how much of each file one comparison step reads.
const compareChunk = 1 << 20

// compareTrees compares the object at original with the quarantined copy in
// one walk of the copy, without following a symlink anywhere, crossing a
// mount, or changing either side (files are read with O_NOATIME where
// permitted), and proves the original identical to the copy or, failing
// that, containing it.
//
// Every entry of the copy must have its counterpart at the same relative
// path in the original, of the same type; a regular file or symlink with
// the same permission bits, owner and group, the same target for a symlink,
// and the same size and bytes for a regular file. Modification times are
// not compared: copying or extracting a tree commonly resets them, and they
// do not change what a restore would bring back. The original is identical
// when, besides, every directory has the same permission bits, owner, group
// and entry names. Otherwise it contains the copy: it may hold more
// entries, and its directories any permissions and owner. A containing
// original's directories, and its parent, are looked up through
// search-only descriptors and never need to be readable; only the copy's
// directories are listed, so maxEntries bounds the copy's entries alone.
//
// Anything else is not proof: another entry type, an unreadable file, an
// entry on another mount (by mount identity, so a bind mount of the same
// filesystem counts) or with no mount identity, more than maxEntries
// entries in the copy, or a compared counterpart in the original that is
// an entry of the copy (the same inode as any of them, at any path), since
// removing the copy would then remove what the original was proven to
// hold. Entries only the original has are never visited: one that
// bind-mounts or hard-links into the copy loses that view when the copy is
// removed, while the data stays at the proven, separate counterparts.
func compareTrees(ctx context.Context, original, copy string, copyID core.FilesystemID, maxEntries int) (*supersedeProof, error) {
	proof := &supersedeProof{original: original, copy: copy, copyID: copyID, maxEntries: maxEntries}
	w, err := proof.walk(ctx, true)
	if err != nil {
		return nil, err
	}
	proof.contained, proof.stamps = !w.exact, w.stamps
	return proof, nil
}

// reason is the receipt reason of a copy this proof superseded.
func (p *supersedeProof) reason() string {
	if p.contained {
		return containedReason
	}
	return supersededReason
}

// unchanged re-walks both trees' metadata, without reading content, and
// refuses unless every entry still has the stamp the comparison saw. An
// identical original must still be identical; a containing original's
// directories are stamped by identity only, so entries added to or removed
// from them beside the compared ones (a live original keeps changing) do
// not void the proof, while every compared counterpart is looked up again
// by name and must be unchanged.
func (p *supersedeProof) unchanged(ctx context.Context) error {
	w, err := p.walk(ctx, false)
	if err != nil {
		return err
	}
	if !slices.Equal(w.stamps, p.stamps) {
		return errors.New("the original or the quarantined copy changed after they were compared")
	}
	return nil
}

// walk compares (content) or re-checks the two trees.
func (p *supersedeProof) walk(ctx context.Context, content bool) (*treeWalk, error) {
	if p.maxEntries <= 0 {
		return nil, errors.New("no comparison entry budget (limits.deep_size_max_entries)")
	}
	// The walk only looks up and reads; neither parent needs to be
	// readable, the original's in particular may be search-only.
	originalParent, err := openSearchDirNoSymlinks(filepath.Dir(p.original))
	if err != nil {
		return nil, fmt.Errorf("original: %w", err)
	}
	defer unix.Close(originalParent)
	copyParent, err := openSearchDirNoSymlinks(filepath.Dir(p.copy))
	if err != nil {
		return nil, fmt.Errorf("quarantined copy: %w", err)
	}
	defer unix.Close(copyParent)
	w := &treeWalk{ctx: ctx, content: content, budget: p.maxEntries, exact: true, copyIDs: map[[2]uint64]struct{}{}}
	if content {
		w.a, w.b = make([]byte, compareChunk), make([]byte, compareChunk)
	} else {
		w.exact, w.mustMatch = !p.contained, !p.contained
	}
	if err := w.roots(originalParent, copyParent, filepath.Base(p.original), filepath.Base(p.copy), p.copyID); err != nil {
		return nil, err
	}
	for _, id := range w.originalIDs {
		if _, ok := w.copyIDs[id]; ok {
			return nil, errors.New("an entry of the original is an entry of the quarantined copy (a bind mount or hard link)")
		}
	}
	if !w.exact {
		for _, i := range w.originalDirs {
			w.stamps[i] = entryStamp{dev: w.stamps[i].dev, ino: w.stamps[i].ino}
		}
	}
	return w, nil
}

type treeWalk struct {
	ctx     context.Context
	content bool
	budget  int
	// exact: no difference that only containment permits was seen yet.
	// mustMatch: such a difference is an error (re-checking an identical
	// proof).
	exact, mustMatch bool
	a, b             []byte
	stamps           []entryStamp
	// originalDirs indexes the stamps of the original's directories.
	originalDirs []int
	// identities of every entry of the copy, and of every original
	// counterpart, which must not be among them.
	copyIDs     map[[2]uint64]struct{}
	originalIDs [][2]uint64
	// devices and mounts of the two roots; every entry must stay on its
	// root's.
	originalDev, copyDev     uint64
	originalMount, copyMount uint64
}

// entryStat is what statx reported of one entry, without following a
// symlink.
type entryStat struct {
	dev, ino, mount uint64
	mode            uint32
	uid, gid        uint32
	size            int64
	ctimeNS         int64
}

func (s *entryStat) kind() uint32 { return s.mode & unix.S_IFMT }

const statxWanted = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_UID | unix.STATX_GID | unix.STATX_INO | unix.STATX_SIZE | unix.STATX_CTIME

// statAt stats name in dirfd with its mount identity (the unique one where
// the kernel has it). Without a mount identity a bind mount of the same
// filesystem cannot be told apart, so there is no proof.
func statAt(dirfd int, name string) (entryStat, error) {
	var sx unix.Statx_t
	if err := unix.Statx(dirfd, name, unix.AT_SYMLINK_NOFOLLOW, statxWanted|unix.STATX_MNT_ID|unix.STATX_MNT_ID_UNIQUE, &sx); err != nil {
		return entryStat{}, err
	}
	if sx.Mask&statxWanted != statxWanted {
		return entryStat{}, fmt.Errorf("%s: the kernel did not report every compared attribute", name)
	}
	if sx.Mask&(unix.STATX_MNT_ID|unix.STATX_MNT_ID_UNIQUE) == 0 {
		return entryStat{}, fmt.Errorf("%s: the kernel reports no mount identity, so a mount crossing cannot be ruled out", name)
	}
	return entryStat{
		dev: unix.Mkdev(sx.Dev_major, sx.Dev_minor), ino: sx.Ino, mount: sx.Mnt_id,
		mode: uint32(sx.Mode), uid: sx.Uid, gid: sx.Gid, size: int64(sx.Size),
		ctimeNS: sx.Ctime.Sec*1e9 + int64(sx.Ctime.Nsec),
	}, nil
}

func (w *treeWalk) roots(originalParent, copyParent int, originalName, copyName string, copyID core.FilesystemID) error {
	o, err := statAt(originalParent, originalName)
	if err != nil {
		return fmt.Errorf("original: %w", err)
	}
	c, err := statAt(copyParent, copyName)
	if err != nil {
		return fmt.Errorf("quarantined copy: %w", err)
	}
	if (core.FilesystemID{Device: c.dev, Inode: c.ino}) != copyID {
		return errors.New("quarantined copy is not the recorded object")
	}
	w.originalDev, w.originalMount, w.copyDev, w.copyMount = o.dev, o.mount, c.dev, c.mount
	return w.pair(originalParent, copyParent, originalName, copyName, &o, &c)
}

// differs records a difference only containment permits.
func (w *treeWalk) differs(format string, args ...any) error {
	if w.mustMatch {
		return fmt.Errorf(format, args...)
	}
	w.exact = false
	return nil
}

// pair compares one entry of each tree, already stat'ed by name in its
// opened parent.
func (w *treeWalk) pair(originalParent, copyParent int, originalName, copyName string, o, c *entryStat) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if w.budget--; w.budget < 0 {
		return errors.New("tree has more entries than limits.deep_size_max_entries")
	}
	switch {
	case o.dev != w.originalDev || o.mount != w.originalMount || c.dev != w.copyDev || c.mount != w.copyMount:
		return fmt.Errorf("%s crosses a mount", copyName)
	case o.kind() != c.kind():
		return fmt.Errorf("%s differs in type", copyName)
	case o.mode != c.mode || o.uid != c.uid || o.gid != c.gid:
		// A containing original's directory is the live original's own.
		if c.kind() != unix.S_IFDIR {
			return fmt.Errorf("%s differs in permissions, owner or group", copyName)
		}
		if err := w.differs("%s differs in permissions, owner or group", copyName); err != nil {
			return err
		}
	}
	w.copyIDs[[2]uint64{c.dev, c.ino}] = struct{}{}
	w.originalIDs = append(w.originalIDs, [2]uint64{o.dev, o.ino})
	if o.kind() == unix.S_IFDIR {
		w.originalDirs = append(w.originalDirs, len(w.stamps))
	}
	w.stamps = append(w.stamps, stampOf(o), stampOf(c))
	switch c.kind() {
	case unix.S_IFREG:
		if o.size != c.size {
			return fmt.Errorf("%s differs in size", copyName)
		}
		if !w.content {
			return nil
		}
		return w.files(originalParent, copyParent, originalName, copyName, o, c)
	case unix.S_IFLNK:
		if !w.content {
			return nil
		}
		ot, err := readlinkAt(originalParent, originalName, o.size)
		if err != nil {
			return err
		}
		ct, err := readlinkAt(copyParent, copyName, c.size)
		if err != nil {
			return err
		}
		if ot != ct {
			return fmt.Errorf("%s differs in symlink target", copyName)
		}
		return nil
	case unix.S_IFDIR:
		return w.dirs(originalParent, copyParent, originalName, copyName, o, c)
	default:
		return fmt.Errorf("%s is neither a directory, a regular file nor a symlink", copyName)
	}
}

// dirs compares the entries of a copy directory with their counterparts.
// The original directory is held by a search-only descriptor: its entries
// are looked up by name, and it is listed only while the trees may still
// be identical.
func (w *treeWalk) dirs(originalParent, copyParent int, originalName, copyName string, o, c *entryStat) error {
	od, err := openPathAt(originalParent, originalName, o)
	if err != nil {
		return err
	}
	defer unix.Close(od)
	cd, err := openAt(copyParent, copyName, c, unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer cd.Close()
	cn, err := names(cd, w.budget)
	if err != nil {
		return err
	}
	if w.exact {
		if err := w.sameNames(originalParent, originalName, o, copyName, cn); err != nil {
			return err
		}
	}
	for _, name := range cn {
		oc, err := statAt(od, name)
		if errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("%s is missing at the original path", name)
		}
		if err != nil {
			return err
		}
		cc, err := statAt(int(cd.Fd()), name)
		if err != nil {
			return err
		}
		if err := w.pair(od, int(cd.Fd()), name, name, &oc, &cc); err != nil {
			return err
		}
	}
	return nil
}

// sameNames lists the original directory originalName in originalParent,
// reading at most one name more than the copy's, and records a difference
// unless it has exactly the copy's names. It is opened by name through its
// parent (a listing needs read, not search, permission on it) and must be
// the inode that was stat'ed. One that cannot be listed is not proven
// identical.
func (w *treeWalk) sameNames(originalParent int, originalName string, o *entryStat, copyName string, copyNames []string) error {
	dir, err := openAt(originalParent, originalName, o, unix.O_DIRECTORY)
	if err != nil {
		return w.differs("%s cannot be listed at the original path: %v", copyName, err)
	}
	defer dir.Close()
	on, err := names(dir, len(copyNames))
	if err != nil || !slices.Equal(on, copyNames) {
		return w.differs("%s differs in entry names", copyName)
	}
	return nil
}

// names lists a directory, sorted, refusing one with more than limit
// entries.
func names(dir *os.File, limit int) ([]string, error) {
	var out []string
	for {
		batch, err := dir.Readdirnames(128)
		out = append(out, batch...)
		if len(out) > limit {
			return nil, errors.New("tree has more entries than limits.deep_size_max_entries")
		}
		if err == io.EOF {
			slices.Sort(out)
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func (w *treeWalk) files(originalParent, copyParent int, originalName, copyName string, o, c *entryStat) error {
	of, err := openAt(originalParent, originalName, o, 0)
	if err != nil {
		return err
	}
	defer of.Close()
	cf, err := openAt(copyParent, copyName, c, 0)
	if err != nil {
		return err
	}
	defer cf.Close()
	for remaining := c.size; ; {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		n, oerr := io.ReadFull(of, w.a)
		m, cerr := io.ReadFull(cf, w.b)
		if n != m || !bytes.Equal(w.a[:n], w.b[:m]) {
			return fmt.Errorf("%s differs in content", copyName)
		}
		remaining -= int64(n)
		oend, cend := endOfRead(oerr), endOfRead(cerr)
		if oend != nil && oend != io.EOF {
			return oend
		}
		if cend != nil && cend != io.EOF {
			return cend
		}
		if oend == io.EOF || cend == io.EOF {
			if oend != cend || remaining != 0 {
				return fmt.Errorf("%s changed size while it was compared", copyName)
			}
			return nil
		}
	}
}

// endOfRead maps io.ReadFull's short-read errors to io.EOF.
func endOfRead(err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return io.EOF
	}
	return err
}

// openAt opens name in parent for reading without following a symlink and
// refuses unless it is still the inode that was stat'ed.
func openAt(parent int, name string, want *entryStat, flags int) (*os.File, error) {
	flags |= unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NOCTTY
	fd, err := unix.Openat(parent, name, flags|unix.O_NOATIME, 0)
	if errors.Is(err, unix.EPERM) {
		fd, err = unix.Openat(parent, name, flags, 0)
	}
	if err != nil {
		return nil, err
	}
	if err := sameInode(fd, name, want); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

// openPathAt opens the directory name in parent as a search-only (O_PATH)
// descriptor without following a symlink, and refuses unless it is still
// the inode that was stat'ed.
func openPathAt(parent int, name string, want *entryStat) (int, error) {
	fd, err := unix.Openat(parent, name, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := sameInode(fd, name, want); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func sameInode(fd int, name string, want *entryStat) error {
	var got unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_INO, &got); err != nil {
		return err
	}
	if unix.Mkdev(got.Dev_major, got.Dev_minor) != want.dev || got.Ino != want.ino {
		return fmt.Errorf("%s was replaced while it was compared", name)
	}
	return nil
}

func readlinkAt(parent int, name string, size int64) (string, error) {
	buf := make([]byte, size+1)
	n, err := unix.Readlinkat(parent, name, buf)
	if err != nil {
		return "", err
	}
	if int64(n) != size {
		return "", fmt.Errorf("%s changed while it was compared", name)
	}
	return string(buf[:n]), nil
}

func stampOf(st *entryStat) entryStamp {
	return entryStamp{dev: st.dev, ino: st.ino, ctimeNS: st.ctimeNS, size: st.size}
}
