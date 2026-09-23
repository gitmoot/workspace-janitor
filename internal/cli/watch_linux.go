//go:build linux

package cli

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type watchEvent struct {
	Root     string
	Name     string
	Overflow bool
}

type topWatcher struct {
	fd      int
	roots   map[int32]string
	pending []watchEvent
	buffer  []byte
}

func openTopWatcher(paths []string) (*topWatcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return nil, err
	}
	w := &topWatcher{fd: fd, roots: make(map[int32]string, len(paths)), buffer: make([]byte, 32*1024)}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !filepath.IsAbs(path) {
			w.close()
			return nil, fmt.Errorf("watch root %s is not a present absolute directory: %v", path, err)
		}
		mask := uint32(unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO |
			unix.IN_ATTRIB | unix.IN_CLOSE_WRITE | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF |
			unix.IN_ONLYDIR | unix.IN_DONT_FOLLOW)
		wd, err := unix.InotifyAddWatch(fd, path, mask)
		if err != nil {
			w.close()
			return nil, fmt.Errorf("watch root %s: %w", path, err)
		}
		w.roots[int32(wd)] = path
	}
	return w, nil
}

func (w *topWatcher) close() error { return unix.Close(w.fd) }

// next reports top-level changes only. The fixed poll interval bounds context
// cancellation without a goroutine blocked forever in read(2).
func (w *topWatcher) next(ctx context.Context) (watchEvent, error) {
	for {
		if len(w.pending) != 0 {
			event := w.pending[0]
			w.pending = w.pending[1:]
			return event, nil
		}
		if err := ctx.Err(); err != nil {
			return watchEvent{}, err
		}
		fds := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN}}
		_, err := unix.Poll(fds, int((200 * time.Millisecond).Milliseconds()))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return watchEvent{}, err
		}
		if fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return watchEvent{Overflow: true}, nil
		}
		n, err := unix.Read(w.fd, w.buffer)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return watchEvent{}, err
		}
		w.pending, err = parseWatchEvents(w.buffer[:n], w.roots)
		if err != nil {
			// A truncated or malformed kernel batch cannot establish absence.
			return watchEvent{Overflow: true}, nil
		}
	}
}

func parseWatchEvents(data []byte, roots map[int32]string) ([]watchEvent, error) {
	const header = 16 // struct inotify_event, before its variable-length name
	var events []watchEvent
	for len(data) > 0 {
		if len(data) < header {
			return nil, errors.New("truncated inotify header")
		}
		wd := int32(binary.NativeEndian.Uint32(data[:4]))
		mask := binary.NativeEndian.Uint32(data[4:8])
		nameLen := binary.NativeEndian.Uint32(data[12:16])
		if nameLen > uint32(len(data)-header) {
			return nil, errors.New("truncated inotify name")
		}
		name := strings.TrimRight(string(data[header:header+int(nameLen)]), "\x00")
		data = data[header+int(nameLen):]
		if mask&(unix.IN_Q_OVERFLOW|unix.IN_IGNORED|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF) != 0 {
			events = append(events, watchEvent{Overflow: true})
			continue
		}
		if root, ok := roots[wd]; ok && name != "" {
			events = append(events, watchEvent{Root: root, Name: name})
		}
	}
	return events, nil
}
