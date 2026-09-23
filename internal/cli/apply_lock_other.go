//go:build !linux

package cli

import "errors"

func lockApply(string) (func(), error) {
	return nil, errors.New("confirmed apply requires Linux process locking")
}

// Confirmed restore worked before Linux-only process locking was introduced.
// Preserve that path; confirmed apply still fails closed on this platform.
func lockRestore(string) (func(), error) { return func() {}, nil }
