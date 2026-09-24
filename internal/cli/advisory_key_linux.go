//go:build linux

package cli

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var errUnsafeAdvisoryKey = errors.New("advisory key file is absent, unsafe, or malformed")

func validatePrivateAdvisoryState(path string) error {
	var stat unix.Stat_t
	if unix.Fstatat(unix.AT_FDCWD, path, &stat, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) ||
		stat.Mode&0077 != 0 {
		return errors.New("advisory state directory is not private; no outbound call")
	}
	return nil
}

// readAdvisoryKey traverses without symlinks and checks the opened inode,
// rather than checking a pathname before opening it. It never imports other
// dotenv variables into the process environment or includes file data in an
// error. The caller keeps the returned key only in memory for this run.
func readAdvisoryKey(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return "", errUnsafeAdvisoryKey
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", errUnsafeAdvisoryKey
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		flags := unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if i == len(parts)-1 {
			flags = unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_CLOEXEC
		}
		next, openErr := unix.Openat(fd, part, flags, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return "", errUnsafeAdvisoryKey
		}
		fd = next
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 || stat.Mode&0111 != 0 || stat.Mode&0400 == 0 ||
		stat.Nlink != 1 || stat.Size <= 0 || stat.Size > 64*1024 {
		_ = unix.Close(fd)
		return "", errUnsafeAdvisoryKey
	}
	file := os.NewFile(uintptr(fd), "advisory-key")
	defer file.Close()
	reader := bufio.NewReader(io.LimitReader(file, 64*1024+1))
	var key string
	found := false
	total := 0
	for {
		line, readErr := reader.ReadString('\n')
		total += len(line)
		if total > 64*1024 {
			return "", errUnsafeAdvisoryKey
		}
		if readErr != nil && readErr != io.EOF {
			return "", errUnsafeAdvisoryKey
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		trimmed := strings.TrimSpace(line)
		name, value, ok := strings.Cut(trimmed, "=")
		if strings.TrimSpace(name) == "OPENROUTER_API_KEY" && name != "OPENROUTER_API_KEY" {
			return "", errUnsafeAdvisoryKey
		}
		if name == "OPENROUTER_API_KEY" {
			if !ok || found {
				return "", errUnsafeAdvisoryKey
			}
			found = true
			value = strings.TrimSpace(value)
			if len(value) >= 2 && (value[0] == '\'' && value[len(value)-1] == '\'' ||
				value[0] == '"' && value[len(value)-1] == '"') {
				value = value[1 : len(value)-1]
			}
			if len(value) == 0 || len(value) > 4096 {
				return "", errUnsafeAdvisoryKey
			}
			for _, c := range value {
				if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' ||
					'0' <= c && c <= '9' || c == '-' || c == '_') {
					return "", errUnsafeAdvisoryKey
				}
			}
			key = value
		}
		if readErr == io.EOF {
			break
		}
	}
	if !found {
		return "", errUnsafeAdvisoryKey
	}
	return key, nil
}
