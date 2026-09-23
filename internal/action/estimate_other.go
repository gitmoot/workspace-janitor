//go:build !linux

package action

import (
	"context"
	"fmt"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// ReclaimEstimate is a conservative estimate of blocks freed by deletion.
type ReclaimEstimate struct {
	Bytes           int64 `json:"bytes"`
	SharedInodes    int   `json:"shared_inodes"`
	ObservedEntries int   `json:"observed_entries"`
}

// EstimateReclaim does not claim savings without an allocated-block API.
func EstimateReclaim(context.Context, []core.Entry, int) (ReclaimEstimate, error) {
	return ReclaimEstimate{}, fmt.Errorf("allocated-block estimates are unavailable on this platform")
}
