//go:build linux

package workspacearchive

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// withoutNoReplaceRename models a filesystem such as sshfs, which rejects
// renameat2(RENAME_NOREPLACE) with EINVAL. before runs first on each call.
func withoutNoReplaceRename(t *testing.T, before func()) {
	t.Helper()
	original := renameat2
	renameat2 = func(int, string, int, string, uint) error {
		if before != nil {
			before()
		}
		return unix.EINVAL
	}
	t.Cleanup(func() { renameat2 = original })
}

// The live Storage Box archive directory is sshfs: every category archive
// failed to publish with "invalid argument" until Create stopped requiring
// RENAME_NOREPLACE.
func TestCreatePublishesWhereNoReplaceRenameIsUnsupported(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.populate(t)
	before := treeSnapshot(t, f.source)
	withoutNoReplaceRename(t, nil)

	_, binding, err := Create(ctx, f.rule, f.scope, allow)
	if err != nil {
		t.Fatalf("Create on a filesystem without no-replace rename: %v", err)
	}
	sameTree(t, before, treeSnapshot(t, f.source))
	if names := f.archiveEntries(t); strings.Join(names, ",") != "released.manifest.json,released.tar" {
		t.Fatalf("archive directory holds %v; want only the published tar and manifest", names)
	}
	if _, _, err := Check(ctx, pin(f.rule, binding), true); err != nil {
		t.Fatalf("published archive does not verify: %v", err)
	}
}

// A name that appears after Create's up-front existence check must still
// never be replaced: a plain rename fallback would overwrite it.
func TestCreateFallbackNeverReplacesAnOutputCreatedDuringPublish(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.populate(t)
	intruder := filepath.Join(f.archive, TarName(f.rule))
	const foreign = "another writer's archive"
	withoutNoReplaceRename(t, func() {
		if _, err := os.Lstat(intruder); errors.Is(err, os.ErrNotExist) {
			if err := os.WriteFile(intruder, []byte(foreign), 0o600); err != nil {
				t.Error(err)
			}
		}
	})

	_, _, err := Create(ctx, f.rule, f.scope, allow)
	if !errors.Is(err, unix.EEXIST) {
		t.Fatalf("Create = %v, want a refusal because the output name already exists", err)
	}
	data, readErr := os.ReadFile(intruder)
	if readErr != nil || string(data) != foreign {
		t.Fatalf("existing output was replaced: %q, %v", data, readErr)
	}
	if names := f.archiveEntries(t); strings.Join(names, ",") != "released.tar" {
		t.Fatalf("archive directory holds %v; a refused publication must not publish a manifest", names)
	}
}
