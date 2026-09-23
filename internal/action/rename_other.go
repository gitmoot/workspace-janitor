//go:build !linux

package action

import (
	"errors"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

func renameNoReplace(_, _ string, _ core.FilesystemID) error {
	return errors.New("atomic no-replace quarantine is not supported on this platform")
}

func syncDir(_ string) error {
	return errors.New("durable quarantine is not supported on this platform")
}
