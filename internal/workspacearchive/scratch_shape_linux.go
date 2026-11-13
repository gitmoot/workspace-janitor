//go:build linux

package workspacearchive

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"golang.org/x/sys/unix"
)

// typeSocket is the member type of a shape entry's socket. Shape entries are
// deleted without an archive, so it never appears in a manifest.
const typeSocket = "socket"

// maxCookieDigits bounds Chrome's SingletonCookie target: a decimal uint64.
const maxCookieDigits = 20

// ObserveShape observes name as one of the enabled built-in shapes
// (config.ScratchShapes) and reports whether it is exactly that shape. Only
// a matching entry is returned; callers observe any other entry with
// Observe, as if no shape were enabled. A shape entry's fixed member names
// are not screened as sensitive and its socket is not refused, but its own
// name is screened, and a mount crossing or extended attribute anywhere
// makes it no shape at all.
func (s *ScratchDir) ObserveShape(ctx context.Context, name string, shapes, patterns []string) (ScratchEntry, bool) {
	if !slices.Contains(shapes, config.ScratchShapeChromeSingletonLock) {
		return ScratchEntry{Name: name}, false
	}
	return s.chromeSingletonLock(ctx, name, patterns)
}

// chromeSingletonLock matches a directory holding exactly SingletonCookie, a
// symlink to a decimal number, and SingletonSocket, a Unix socket.
func (s *ScratchDir) chromeSingletonLock(ctx context.Context, name string, patterns []string) (ScratchEntry, bool) {
	entry := ScratchEntry{Name: name}
	if ctx.Err() != nil || name == "" || name == "." || name == ".." || filepath.Base(name) != name || secretLike(name, s.path, patterns) {
		return entry, false
	}
	same := func(st state) bool { return st.id.Device == s.st.id.Device && st.mountID == s.st.mountID }
	top, err := statxAt(int(s.dir.Fd()), name, 0)
	if err != nil || top.kind() != unix.S_IFDIR || !same(top) {
		return entry, false
	}
	dir, err := openChild(s.dir, name, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return entry, false
	}
	defer dir.Close()
	if opened, err := fstate(dir); err != nil || opened.id != top.id || hasXattrs(unix.Flistxattr(int(dir.Fd()), nil)) {
		return entry, false
	}
	names, err := readNames(dir, 2)
	if err != nil || !slices.Equal(names, []string{ChromeSingletonCookie, ChromeSingletonSocket}) {
		return entry, false
	}
	fd := int(dir.Fd())
	child := func(name string, kind uint32) (state, bool) {
		st, err := statxAt(fd, name, 0)
		ok := err == nil && st.kind() == kind && same(st) && !hasXattrs(unix.Llistxattr(descriptorPath(dir)+"/"+name, nil))
		return st, ok
	}
	cookie, ok := child(ChromeSingletonCookie, unix.S_IFLNK)
	if !ok {
		return entry, false
	}
	target, err := readlinkAt(fd, ChromeSingletonCookie)
	if err != nil || !decimal(target) {
		return entry, false
	}
	socket, ok := child(ChromeSingletonSocket, unix.S_IFSOCK)
	if !ok {
		return entry, false
	}
	// A child added or removed while it was listed changes the directory.
	if again, err := fstate(dir); err != nil || again != top {
		return entry, false
	}
	member := func(path, kind string, st state) Member {
		return Member{Path: path, Type: kind, Mode: st.mode & 07777, UID: st.uid, GID: st.gid, ModifiedNS: st.mtimeNS}
	}
	link := member(name+"/"+ChromeSingletonCookie, TypeSymlink, cookie)
	link.Linkname = target
	entry.inv = inventory{
		members: []Member{member(name, TypeDirectory, top), link, member(name+"/"+ChromeSingletonSocket, typeSocket, socket)},
		states:  []state{top, cookie, socket},
	}
	entry.Type, entry.Identity, entry.CtimeNS, entry.Members = TypeDirectory, top.id, top.ctimeNS, 3
	entry.NewestMtimeNS = max(top.mtimeNS, cookie.mtimeNS, socket.mtimeNS)
	entry.Shape, entry.socket = config.ScratchShapeChromeSingletonLock, socket.id
	return entry, true
}

func decimal(s string) bool {
	if s == "" || len(s) > maxCookieDigits {
		return false
	}
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// sock_diag (NETLINK_SOCK_DIAG) constants for AF_UNIX from
// <linux/unix_diag.h>; golang.org/x/sys/unix does not define them.
const (
	unixDiagReqLen = 24 // struct unix_diag_req
	unixDiagMsgLen = 16 // struct unix_diag_msg
	udiagShowName  = 1 << 0
	udiagShowVFS   = 1 << 1
	unixDiagName   = 0
	unixDiagVFS    = 1
	tcpListen      = 10
	nlmFDumpIntr   = 0x10
)

// ListeningUnixSockets returns the inodes of the files that the listening
// Unix sockets of this process's network namespace are bound to. It asks the
// kernel's sock_diag interface (what `ss -xl` reads) for each listener's
// bound file, so a socket file is matched by identity however its bind path
// was spelled: relative to some working directory, through ".", ".." or a
// symlink, a hard link, or renamed since. /proc/net/unix cannot do that: it
// prints the bind path as written, and its Inode column is the socket's
// sockfs inode, not the file's. A dump that fails, is interrupted or
// reports a path-bound listener without its file is an error, so no socket
// is shown idle.
func ListeningUnixSockets() (UnixListeners, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, fmt.Errorf("listening socket check: %w", err)
	}
	defer unix.Close(fd)
	ne := binary.NativeEndian
	req := make([]byte, unix.SizeofNlMsghdr+unixDiagReqLen)
	ne.PutUint32(req[0:], uint32(len(req)))
	ne.PutUint16(req[4:], unix.SOCK_DIAG_BY_FAMILY)
	ne.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	ne.PutUint32(req[8:], 1)
	req[16] = unix.AF_UNIX
	ne.PutUint32(req[20:], 1<<tcpListen)
	ne.PutUint32(req[28:], udiagShowName|udiagShowVFS)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("listening socket check: %w", err)
	}
	return readUnixListeners(func(buf []byte) (int, error) {
		for {
			n, _, flags, _, err := unix.Recvmsg(fd, buf, nil, 0)
			switch {
			case errors.Is(err, unix.EINTR):
				continue
			case err == nil && flags&unix.MSG_TRUNC != 0:
				return 0, errors.New("truncated sock_diag datagram")
			}
			return n, err
		}
	})
}

// readUnixListeners reads one sock_diag dump through recv, one datagram per
// call, up to its NLMSG_DONE.
func readUnixListeners(recv func([]byte) (int, error)) (UnixListeners, error) {
	ne := binary.NativeEndian
	listeners := UnixListeners{}
	buf := make([]byte, 1<<16)
	for {
		n, err := recv(buf)
		if err != nil {
			return nil, fmt.Errorf("listening socket check: %w", err)
		}
		if n == 0 {
			return nil, errors.New("listening socket check: sock_diag dump ended without NLMSG_DONE")
		}
		for msgs := buf[:n]; len(msgs) != 0; {
			if len(msgs) < unix.SizeofNlMsghdr {
				return nil, errors.New("listening socket check: truncated sock_diag reply")
			}
			size, kind, flags := int(ne.Uint32(msgs[0:])), ne.Uint16(msgs[4:]), ne.Uint16(msgs[6:])
			if size < unix.SizeofNlMsghdr || size > len(msgs) {
				return nil, errors.New("listening socket check: malformed sock_diag reply")
			}
			if flags&nlmFDumpIntr != 0 {
				return nil, errors.New("listening socket check: the socket table changed during the dump")
			}
			body := msgs[unix.SizeofNlMsghdr:size]
			switch kind {
			case unix.NLMSG_DONE:
				return listeners, nil
			case unix.NLMSG_ERROR:
				if len(body) < 4 {
					return nil, errors.New("listening socket check: malformed sock_diag error")
				}
				return nil, fmt.Errorf("listening socket check: %w", unix.Errno(-int32(ne.Uint32(body))))
			case unix.SOCK_DIAG_BY_FAMILY:
				if err := listeners.add(body); err != nil {
					return nil, fmt.Errorf("listening socket check: %w", err)
				}
			default:
				return nil, fmt.Errorf("listening socket check: unexpected netlink message type %d", kind)
			}
			msgs = msgs[min(len(msgs), (size+3)&^3):]
		}
	}
}

// add records one unix_diag_msg and its attributes.
func (l UnixListeners) add(msg []byte) error {
	if len(msg) < unixDiagMsgLen {
		return errors.New("malformed unix_diag_msg")
	}
	if msg[0] != unix.AF_UNIX || msg[2] != tcpListen {
		return nil
	}
	ne := binary.NativeEndian
	var name []byte
	vfs, named := false, false
	for attrs := msg[unixDiagMsgLen:]; len(attrs) != 0; {
		if len(attrs) < 4 {
			return errors.New("malformed unix_diag attribute")
		}
		size, kind := int(ne.Uint16(attrs[0:])), ne.Uint16(attrs[2:])
		if size < 4 || size > len(attrs) {
			return errors.New("malformed unix_diag attribute")
		}
		payload := attrs[4:size]
		switch kind {
		case unixDiagName:
			name, named = payload, true
		case unixDiagVFS:
			// struct unix_diag_vfs { __u32 udiag_vfs_ino; __u32 udiag_vfs_dev; }
			if len(payload) < 8 {
				return errors.New("malformed unix_diag_vfs")
			}
			l[ne.Uint32(payload[0:])] = true
			vfs = true
		}
		attrs = attrs[min(len(attrs), (size+3)&^3):]
	}
	// An abstract name starts with a NUL and has no file; a listener bound
	// to a path always reports its file, unless the kernel cannot say.
	if named && len(name) != 0 && name[0] != 0 && !vfs {
		return fmt.Errorf("listening socket %q reported no bound file", name)
	}
	return nil
}
