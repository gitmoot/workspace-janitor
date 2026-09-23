//go:build !linux

package action

import (
	"context"
	"errors"
	"os"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

func fileIdentity(_ os.FileInfo) core.FilesystemID { return core.FilesystemID{} }
func deleteAnchored(_ string, _ core.FilesystemID) error {
	return errors.New("anchored quarantine deletion is not supported on this platform")
}
func verifyDeletionTree(_ context.Context, _ string, _ core.FilesystemID) error {
	return errors.New("anchored quarantine deletion is not supported on this platform")
}
