//go:build !linux

package workspacearchive

import "context"

// DependentIndex is unavailable off Linux; every archive operation refuses.
type DependentIndex struct{}

func BuildDependentIndex(context.Context, []string, int) *DependentIndex { return &DependentIndex{} }
