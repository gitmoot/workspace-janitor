package action

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

const maxManifestBytes = 4 << 20

// ensureManifest makes a prepared journal row recoverable even if the process
// stopped after committing the row but before installing its manifest. The
// move path calls this before every rename. A conflicting or partial manifest
// is never overwritten or trusted.
func ensureManifest(item core.CleanupItem) error {
	if item.State != core.CleanupPrepared {
		return errors.New("only prepared receipts can install a manifest")
	}
	item.Normalize()
	body, err := json.Marshal(item)
	if err != nil {
		return err
	}
	if len(body) > maxManifestBytes {
		return errors.New("receipt manifest exceeds size bound")
	}
	base := filepath.Dir(item.Destination)
	path := filepath.Join(base, "manifest.json")
	if err := matchesManifest(path, body); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(base, ".manifest-*")
	if err != nil {
		return fmt.Errorf("create manifest staging file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(body)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("sync staged manifest: %w", err)
	}
	info, err := os.Lstat(tmp.Name())
	if err != nil {
		return err
	}
	if err := renameNoReplace(tmp.Name(), path, fileIdentity(info)); err != nil {
		// Another process may have installed the same manifest. A different
		// manifest at this name is a collision, not permission to overwrite.
		if matchErr := matchesManifest(path, body); matchErr == nil {
			return nil
		}
		return fmt.Errorf("install manifest without replacement: %w", err)
	}
	return syncDir(base)
}

func matchesManifest(path string, want []byte) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > maxManifestBytes {
		return errors.New("manifest is not a bounded regular file")
	}
	got, err := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return errors.New("receipt manifest differs from prepared journal row")
	}
	return nil
}
