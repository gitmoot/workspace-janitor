//go:build linux

package workspacearchive

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
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
	entry.Shape = config.ScratchShapeChromeSingletonLock
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

// soAcceptCon is __SO_ACCEPTCON, the /proc/net/unix Flags bit of a
// listening socket.
const soAcceptCon = 1 << 16

// ListeningUnixSockets returns the paths inside dir that a listening Unix
// socket is bound to, from procRoot/net/unix: a row whose Flags column has
// __SO_ACCEPTCON set, keyed by its Path column exactly as printed. The
// table lists the sockets of this process's network namespace. A table
// that cannot be read or parsed is an error, so no socket is shown idle.
func ListeningUnixSockets(procRoot, dir string) (map[string]bool, error) {
	if procRoot == "" {
		return nil, errors.New("listening socket check requires a procfs root")
	}
	table := filepath.Join(procRoot, "net", "unix")
	f, err := os.Open(table)
	if err != nil {
		return nil, fmt.Errorf("listening socket check: %w", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), "Num ") {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("listening socket check: %w", err)
		}
		return nil, fmt.Errorf("listening socket check: %s has no header", table)
	}
	listening := map[string]bool{}
	for line := 2; scanner.Scan(); line++ {
		flags, path, err := unixSocketRow(scanner.Text())
		if err != nil {
			return nil, fmt.Errorf("listening socket check: %s line %d: %w", table, line, err)
		}
		if flags&soAcceptCon != 0 && core.PathWithin(path, dir) && path != dir {
			listening[path] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("listening socket check: %w", err)
	}
	return listening, nil
}

// unixSocketRow parses one /proc/net/unix row, "Num: RefCount Protocol
// Flags Type St Inode[ Path]", where Path is the rest of the line after
// one space and may itself contain spaces.
func unixSocketRow(row string) (uint64, string, error) {
	rest := row
	var fields [7]string
	for i := range fields {
		rest = strings.TrimLeft(rest, " ")
		end := strings.IndexByte(rest, ' ')
		if end < 0 {
			end = len(rest)
		}
		fields[i], rest = rest[:end], rest[end:]
		if fields[i] == "" {
			return 0, "", errors.New("malformed row")
		}
	}
	if !strings.HasSuffix(fields[0], ":") {
		return 0, "", errors.New("malformed row")
	}
	flags, err := strconv.ParseUint(fields[3], 16, 32)
	if err != nil {
		return 0, "", fmt.Errorf("malformed flags %q", fields[3])
	}
	return flags, strings.TrimPrefix(rest, " "), nil
}
