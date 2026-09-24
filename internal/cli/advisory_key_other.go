//go:build !linux

package cli

import "errors"

var errUnsafeAdvisoryKey = errors.New("advisory key file requires Linux no-follow descriptor checks")

func readAdvisoryKey(string) (string, error) { return "", errUnsafeAdvisoryKey }

func validatePrivateAdvisoryState(string) error { return errUnsafeAdvisoryKey }
