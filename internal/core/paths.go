package core

import (
	"path/filepath"
	"strings"
)

// isAbsClean reports whether p is an absolute path in cleaned form. Domain
// records store canonical paths only: "/repos/x/../y" and "/repos/x/" are
// rejected so identity comparisons and prefix checks stay sound.
func isAbsClean(p string) bool {
	if p == "" || !filepath.IsAbs(p) {
		return false
	}
	return filepath.Clean(p) == p
}

// IsCanonicalPath reports whether p is an absolute, cleaned filesystem path.
func IsCanonicalPath(p string) bool { return isAbsClean(p) }

// PathWithin reports whether path is target or lives inside it.
//
// Both are expected to be absolute, cleaned paths. The root directory is
// handled explicitly: naive prefix matching on target+"/" builds "//" and
// then matches nothing, which would silently turn a protection covering "/"
// into no protection at all.
func PathWithin(path, target string) bool {
	if path == "" || target == "" {
		return false
	}
	path = filepath.Clean(path)
	target = filepath.Clean(target)
	if path == target {
		return true
	}
	if target == string(filepath.Separator) {
		return filepath.IsAbs(path)
	}
	return strings.HasPrefix(path, target+string(filepath.Separator))
}

// PathsOverlap reports whether mutating one path would affect the other, in
// either direction: a parent that contains the protected path, and a
// protected parent that contains the entry.
func PathsOverlap(a, b string) bool { return PathWithin(a, b) || PathWithin(b, a) }
