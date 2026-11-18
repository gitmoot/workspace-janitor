//go:build !linux

package cli

import (
	"context"
	"errors"
	"time"
)

func runNotifyCommand(context.Context, []string, time.Duration) ([]byte, error) {
	return nil, errors.New("notify_command requires Linux process groups")
}
