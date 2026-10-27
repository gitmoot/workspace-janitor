//go:build linux

package workspacearchive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

// Bind proves that the pinned archive can stand in for the local tree at
// localPath, which is the released workspace itself or its quarantined copy.
// It verifies the pinned manifest hash and, when full, the whole archive and
// history bundle; then it walks the local tree and requires it to equal the
// manifest member list exactly: same paths, types, sizes, modes, owners,
// modification times and link targets, and with full the same per-file
// SHA-256. Any extra, missing or changed member refuses, because removing the
// local copy would lose it. The source refusals are repeated against the local
// tree: secret-like names, unsupported members, outbound Git history, and live
// process references and external dependents of both localPath and the
// rule's original path.
//
// Only a full binding may authorize deletion: without full, files that kept
// their size and modification time are not re-read. Memory is bounded by the
// pinned manifest; contents are streamed. Bind never modifies anything.
func Bind(ctx context.Context, rule config.WorkspaceArchiveRule, scope Scope, localPath string, full bool) (*core.WorkspaceArchiveBinding, error) {
	if !core.IsCanonicalPath(localPath) || localPath == "/" {
		return nil, errors.New("local workspace path must be a canonical absolute directory path")
	}
	if core.PathsOverlap(localPath, rule.Archive.Directory) || core.PathsOverlap(rule.Path, rule.Archive.Directory) {
		return nil, errors.New("archive directory must be outside the archived workspace")
	}
	if len(scope.SearchRoots) == 0 {
		return nil, errors.New("external dependent scan requires at least one search root")
	}
	m, root, tarFile, err := load(ctx, rule)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	defer tarFile.Close()
	if full {
		if err := verifyArchive(ctx, m, root, tarFile); err != nil {
			return nil, err
		}
	}
	local, err := openDirectory(localPath)
	if err != nil {
		return nil, fmt.Errorf("local workspace: %w", err)
	}
	defer local.Close()
	// One member beyond the manifest is already a difference, so the
	// manifest's own size bounds the walk.
	walk, err := scanTree(ctx, local, localPath, scope.SensitiveNames, len(m.Members), full, true)
	if err != nil {
		return nil, fmt.Errorf("local tree cannot be matched to its archive; local changes would be lost: %w", err)
	}
	if secretLike(filepath.Base(rule.Path), filepath.Dir(rule.Path), scope.SensitiveNames) {
		return nil, fmt.Errorf("secret-like files keep %s local: .", rule.Path)
	}
	if err := walk.err(); err != nil {
		return nil, err
	}
	if err := sameMembers(walk.inv.members, m.Members, full); err != nil {
		return nil, err
	}
	if (walk.inv.worktreeAdmin != "") != (m.Bundle != nil) {
		return nil, errors.New("local linked-worktree history pointer differs from the archive's history bundle record")
	}
	if m.Bundle != nil {
		head, err := runGit(ctx, localPath, nil, nil, "rev-parse", "--verify", "HEAD")
		if err != nil {
			return nil, fmt.Errorf("linked worktree HEAD cannot be confirmed: %w", err)
		}
		if head != m.Bundle.Head {
			return nil, errors.New("linked worktree HEAD moved after archiving; the history bundle would not restore it")
		}
	}
	live := []string{localPath}
	if rule.Path != localPath {
		live = append(live, rule.Path)
	}
	for _, path := range live {
		if err := liveReferences(ctx, scope.ProcRoot, path); err != nil {
			return nil, err
		}
		if err := externalDependents(ctx, path, scope.SearchRoots, scope.limit()); err != nil {
			return nil, err
		}
	}
	// The live checks take time; the tree must still be the one compared.
	if err := walk.inv.unchanged(local); err != nil {
		return nil, errors.New("local tree changed while being bound to its archive; local changes would be lost")
	}
	digest := sha256.New()
	if err := json.NewEncoder(digest).Encode(m.Members); err != nil {
		return nil, err
	}
	return &core.WorkspaceArchiveBinding{
		Manifest: rule.Archive.Manifest, ManifestSHA256: rule.Archive.ManifestSHA256,
		MemberCount: len(m.Members), TreeDigest: hex.EncodeToString(digest.Sum(nil)), CreatedAt: m.CreatedAt.UTC(),
	}, nil
}

// sameMembers compares two walks in archive order. Without full, regular file
// contents are not compared; every other recorded fact is.
func sameMembers(local, archived []Member, full bool) error {
	for i, want := range archived {
		if i >= len(local) {
			return fmt.Errorf("local tree lacks archived member %s; the archive does not match the local tree", want.Path)
		}
		got := local[i]
		if got.Path != want.Path {
			return fmt.Errorf("local tree has %s where the archive records %s; local changes would be lost", got.Path, want.Path)
		}
		if !full && want.Type == TypeFile {
			got.SHA256 = want.SHA256
		}
		if got != want {
			return fmt.Errorf("local member %s differs from the archive (type, size, mode, owner, modification time, link target or content); local changes would be lost", want.Path)
		}
	}
	if len(local) > len(archived) {
		return fmt.Errorf("local tree has %s, which the archive lacks; local changes would be lost", local[len(archived)].Path)
	}
	return nil
}
