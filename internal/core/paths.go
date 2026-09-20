package core

import "path/filepath"

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
