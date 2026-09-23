//go:build !linux

package action

import "errors"

func createReceiptDir(_ string) error {
	return errors.New("durable quarantine is not supported on this platform")
}
