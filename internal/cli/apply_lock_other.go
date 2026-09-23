//go:build !linux

package cli

import "errors"

func lockApply(string) (func(), error) {
	return nil, errors.New("confirmed apply and restore require Linux process locking")
}
