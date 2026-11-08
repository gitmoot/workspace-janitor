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

// identicalTrees proves that the object at the original path was, entry by
// entry, the quarantined copy: stamps of both trees in walk order.
type identicalTrees struct {
	original, copy string
	copyID         core.FilesystemID
	maxEntries     int
	stamps         []entryStamp
}

// compareChunk is how much of each file one comparison step reads.
const compareChunk = 1 << 20

// compareTrees compares the object at original with the quarantined copy
// without following a symlink anywhere, crossing a mount, or changing
// either side (files are read with O_NOATIME where permitted). Identical
// means the same tree shape and entry names, and for every entry the same
// type, permission bits, owner and group; the same target for a symlink;
// and the same size and bytes for a regular file. Modification times are
// not compared: copying or extracting a tree commonly resets them, and they
// do not change what a restore would bring back. Anything else (another
// entry type, a mount, an unreadable entry, more than maxEntries entries
// on a side, the original's directory being the copy's) is not proof.
func compareTrees(ctx context.Context, original, copy string, copyID core.FilesystemID, maxEntries int) (*identicalTrees, error) {
	proof := &identicalTrees{original: original, copy: copy, copyID: copyID, maxEntries: maxEntries}
	stamps, err := proof.walk(ctx, true)
	if err != nil {
		return nil, err
	}
	proof.stamps = stamps
	return proof, nil
}

// unchanged re-walks both trees' metadata, without reading content, and
// refuses unless every entry still has the stamp the comparison saw.
func (p *identicalTrees) unchanged(ctx context.Context) error {
	stamps, err := p.walk(ctx, false)
	if err != nil {
		return err
	}
	if !slices.Equal(stamps, p.stamps) {
		return errors.New("the original or the quarantined copy changed after they were compared")
	}
	return nil
}

func (p *identicalTrees) walk(ctx context.Context, content bool) ([]entryStamp, error) {
	if p.maxEntries <= 0 {
		return nil, errors.New("no comparison entry budget (limits.deep_size_max_entries)")
	}
	originalParent, err := openExistingDirNoSymlinks(filepath.Dir(p.original))
	if err != nil {
		return nil, fmt.Errorf("original: %w", err)
	}
	defer unix.Close(originalParent)
	copyParent, err := openExistingDirNoSymlinks(filepath.Dir(p.copy))
	if err != nil {
		return nil, fmt.Errorf("quarantined copy: %w", err)
	}
	defer unix.Close(copyParent)
	w := &treeWalk{ctx: ctx, content: content, budget: p.maxEntries}
	if content {
		w.a, w.b = make([]byte, compareChunk), make([]byte, compareChunk)
	}
	if err := w.roots(originalParent, copyParent, filepath.Base(p.original), filepath.Base(p.copy), p.copyID); err != nil {
		return nil, err
	}
	return w.stamps, nil
}

type treeWalk struct {
	ctx     context.Context
	content bool
	budget  int
	a, b    []byte
	stamps  []entryStamp
	// devices of the two roots; every entry must stay on its root's.
	originalDev, copyDev uint64
}

func (w *treeWalk) roots(originalParent, copyParent int, originalName, copyName string, copyID core.FilesystemID) error {
	var o, c unix.Stat_t
	if err := unix.Fstatat(originalParent, originalName, &o, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("original: %w", err)
	}
	if err := unix.Fstatat(copyParent, copyName, &c, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("quarantined copy: %w", err)
	}
	if (core.FilesystemID{Device: uint64(c.Dev), Inode: c.Ino}) != copyID {
		return errors.New("quarantined copy is not the recorded object")
	}
	w.originalDev, w.copyDev = uint64(o.Dev), uint64(c.Dev)
	return w.pair(originalParent, copyParent, originalName, copyName, &o, &c)
}

// pair compares one entry of each tree, already stat'ed (no-follow) by name
// in its opened parent.
func (w *treeWalk) pair(originalParent, copyParent int, originalName, copyName string, o, c *unix.Stat_t) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if w.budget--; w.budget < 0 {
		return errors.New("tree has more entries than limits.deep_size_max_entries")
	}
	switch {
	case uint64(o.Dev) != w.originalDev || uint64(c.Dev) != w.copyDev:
		return fmt.Errorf("%s crosses a mount", copyName)
	case o.Mode != c.Mode:
		return fmt.Errorf("%s differs in type or permissions", copyName)
	case o.Uid != c.Uid || o.Gid != c.Gid:
		return fmt.Errorf("%s differs in owner or group", copyName)
	}
	w.stamps = append(w.stamps, stampOf(o), stampOf(c))
	switch c.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		if o.Size != c.Size {
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
		ot, err := readlinkAt(originalParent, originalName, o.Size)
		if err != nil {
			return err
		}
		ct, err := readlinkAt(copyParent, copyName, c.Size)
		if err != nil {
			return err
		}
		if ot != ct {
			return fmt.Errorf("%s differs in symlink target", copyName)
		}
		return nil
	case unix.S_IFDIR:
		if o.Dev == c.Dev && o.Ino == c.Ino {
			return fmt.Errorf("%s is the quarantined copy itself", copyName)
		}
		return w.dirs(originalParent, copyParent, originalName, copyName, o, c)
	default:
		return fmt.Errorf("%s is neither a directory, a regular file nor a symlink", copyName)
	}
}

func (w *treeWalk) dirs(originalParent, copyParent int, originalName, copyName string, o, c *unix.Stat_t) error {
	od, err := openAt(originalParent, originalName, o, unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer od.Close()
	cd, err := openAt(copyParent, copyName, c, unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer cd.Close()
	on, err := w.names(od)
	if err != nil {
		return err
	}
	cn, err := w.names(cd)
	if err != nil {
		return err
	}
	if !slices.Equal(on, cn) {
		return fmt.Errorf("%s differs in entry names", copyName)
	}
	for _, name := range cn {
		var oc, cc unix.Stat_t
		if err := unix.Fstatat(int(od.Fd()), name, &oc, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if err := unix.Fstatat(int(cd.Fd()), name, &cc, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if err := w.pair(int(od.Fd()), int(cd.Fd()), name, name, &oc, &cc); err != nil {
			return err
		}
	}
	return nil
}

// names lists a directory, sorted, refusing one longer than the budget.
func (w *treeWalk) names(dir *os.File) ([]string, error) {
	var out []string
	for {
		batch, err := dir.Readdirnames(128)
		out = append(out, batch...)
		if len(out) > w.budget {
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

func (w *treeWalk) files(originalParent, copyParent int, originalName, copyName string, o, c *unix.Stat_t) error {
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
	for remaining := c.Size; ; {
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

// openAt opens name in parent without following a symlink and refuses
// unless it is still the inode that was stat'ed.
func openAt(parent int, name string, want *unix.Stat_t, flags int) (*os.File, error) {
	flags |= unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NOCTTY
	fd, err := unix.Openat(parent, name, flags|unix.O_NOATIME, 0)
	if errors.Is(err, unix.EPERM) {
		fd, err = unix.Openat(parent, name, flags, 0)
	}
	if err != nil {
		return nil, err
	}
	var got unix.Stat_t
	if err := unix.Fstat(fd, &got); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if got.Dev != want.Dev || got.Ino != want.Ino {
		unix.Close(fd)
		return nil, fmt.Errorf("%s was replaced while it was compared", name)
	}
	return os.NewFile(uintptr(fd), name), nil
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

func stampOf(st *unix.Stat_t) entryStamp {
	return entryStamp{dev: uint64(st.Dev), ino: st.Ino, ctimeNS: st.Ctim.Sec*1e9 + st.Ctim.Nsec, size: st.Size}
}
