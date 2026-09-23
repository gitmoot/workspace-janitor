//go:build !linux

package cli

import (
	"context"
	"errors"
)

type watchEvent struct {
	Root     string
	Name     string
	Overflow bool
}

type topWatcher struct{}

func openTopWatcher([]string) (*topWatcher, error) {
	return nil, errors.New("top-level watcher requires Linux inotify")
}
func (*topWatcher) close() error { return nil }
func (*topWatcher) next(context.Context) (watchEvent, error) {
	return watchEvent{}, errors.New("top-level watcher requires Linux inotify")
}
