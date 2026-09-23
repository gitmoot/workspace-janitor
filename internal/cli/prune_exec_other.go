//go:build !linux

package cli

import (
	"context"
	"fmt"
	"time"
)

func executeOfficialPrune(context.Context, []string, time.Duration) error {
	return fmt.Errorf("official prune requires a Linux process-group timeout")
}

func lockOfficialPrune(string) (func(), error) {
	return nil, fmt.Errorf("official prune requires Linux")
}

func recordOfficialPrune(string, pruneReport) error {
	return fmt.Errorf("official prune requires Linux")
}
