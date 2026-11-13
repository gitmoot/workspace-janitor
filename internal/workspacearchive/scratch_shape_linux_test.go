//go:build linux

package workspacearchive

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
)

// The live dump finds a listener by its socket file's inode, and stops
// finding it once the socket no longer listens.
func TestListeningUnixSocketsByFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	id := core.FilesystemID{Device: st.Dev, Inode: st.Ino}
	listening, err := ListeningUnixSockets()
	if err != nil || !listening.Bound(id) {
		t.Fatalf("listening socket %s (inode %d) not found: %v", path, st.Ino, err)
	}
	l.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatal(err)
	}
	if listening, err = ListeningUnixSockets(); err != nil || listening.Bound(id) {
		t.Fatalf("closed socket %s still listening: %v", path, err)
	}
}

// diagMsg encodes one netlink message of kind with body.
func diagMsg(kind, flags uint16, body []byte) []byte {
	ne := binary.NativeEndian
	msg := make([]byte, unix.SizeofNlMsghdr, unix.SizeofNlMsghdr+len(body)+3)
	ne.PutUint32(msg[0:], uint32(unix.SizeofNlMsghdr+len(body)))
	ne.PutUint16(msg[4:], kind)
	ne.PutUint16(msg[6:], flags)
	msg = append(msg, body...)
	for len(msg)%4 != 0 {
		msg = append(msg, 0)
	}
	return msg
}

// diagListener encodes a listening unix_diag_msg with a name attribute and,
// when vfs, a unix_diag_vfs attribute for inode.
func diagListener(name string, vfs bool, inode uint32) []byte {
	ne := binary.NativeEndian
	body := make([]byte, unixDiagMsgLen)
	body[0], body[2] = unix.AF_UNIX, tcpListen
	attr := func(kind uint16, payload []byte) {
		a := make([]byte, 4, 4+len(payload)+3)
		ne.PutUint16(a[0:], uint16(4+len(payload)))
		ne.PutUint16(a[2:], kind)
		a = append(a, payload...)
		for len(a)%4 != 0 {
			a = append(a, 0)
		}
		body = append(body, a...)
	}
	attr(unixDiagName, []byte(name))
	if vfs {
		payload := make([]byte, 8)
		ne.PutUint32(payload, inode)
		attr(unixDiagVFS, payload)
	}
	return diagMsg(unix.SOCK_DIAG_BY_FAMILY, unix.NLM_F_MULTI, body)
}

func replay(datagrams ...[]byte) func([]byte) (int, error) {
	return func(buf []byte) (int, error) {
		if len(datagrams) == 0 {
			return 0, errors.New("no more datagrams")
		}
		n := copy(buf, datagrams[0])
		datagrams = datagrams[1:]
		return n, nil
	}
}

// Every way the dump can be incomplete or unreadable is an error, so a
// shape entry is never shown idle on partial information.
func TestReadUnixListenersFailsClosed(t *testing.T) {
	done := diagMsg(unix.NLMSG_DONE, unix.NLM_F_MULTI, make([]byte, 4))
	errno := make([]byte, 4)
	eperm := int32(unix.EPERM)
	binary.NativeEndian.PutUint32(errno, uint32(-eperm))
	good, err := readUnixListeners(replay(append(diagListener("\x00abstract", false, 0), diagListener("SingletonSocket", true, 77)...), done))
	if err != nil || !good.Bound(core.FilesystemID{Inode: 77}) || !good.Bound(core.FilesystemID{Inode: 1<<32 | 77}) || good.Bound(core.FilesystemID{Inode: 78}) {
		t.Fatalf("well-formed dump: %v %v", good, err)
	}
	for name, test := range map[string]struct {
		recv func([]byte) (int, error)
		want string
	}{
		"recv error":     {replay(), "no more datagrams"},
		"no done":        {replay(diagListener("/a", true, 1), []byte{}), "without NLMSG_DONE"},
		"netlink error":  {replay(diagMsg(unix.NLMSG_ERROR, 0, errno)), "operation not permitted"},
		"interrupted":    {replay(diagMsg(unix.SOCK_DIAG_BY_FAMILY, unix.NLM_F_MULTI|nlmFDumpIntr, make([]byte, unixDiagMsgLen)), done), "changed during the dump"},
		"truncated":      {replay(diagListener("/a", true, 1)[:20]), "malformed sock_diag reply"},
		"path no file":   {replay(diagListener("/tmp/x/SingletonSocket", false, 0), done), "reported no bound file"},
		"unknown type":   {replay(diagMsg(0x99, 0, nil)), "unexpected netlink message type"},
		"short diag msg": {replay(diagMsg(unix.SOCK_DIAG_BY_FAMILY, 0, make([]byte, 8)), done), "malformed unix_diag_msg"},
	} {
		if _, err := readUnixListeners(test.recv); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: want error %q, got %v", name, test.want, err)
		}
	}
}
