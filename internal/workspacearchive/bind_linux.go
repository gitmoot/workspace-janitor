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

// Bind proves that the pinned archive can stand in for the local unit at
// localPath, which is the released workspace itself or its quarantined copy,
// a directory tree or a regular file. It verifies the pinned manifest hash
// and, when full, the whole archive and history bundle; then it walks the
// local tree and requires it to equal the manifest member list exactly: same
// paths, types, sizes, modes, owners, modification times and link targets,
// and with full the same per-file SHA-256. When the rule has a companion, the
// local companion at localPath plus its suffix must equal the archived one
// the same way, or stay absent when the archive recorded it absent. Any
// extra, missing or changed member refuses, because removing the local copy
// would lose it. The source refusals are repeated against the local unit:
// secret-like names, unsupported members, outbound Git history, and live
// process references, live mentions and external dependents of both the
// local names and the rule's original names.
//
// Only a full binding may authorize deletion: without full, files that kept
// their size and modification time are not re-read. Memory is bounded by the
// pinned manifest; contents are streamed. Bind never modifies anything.
func Bind(ctx context.Context, rule config.WorkspaceArchiveRule, scope Scope, localPath string, full bool) (*core.WorkspaceArchiveBinding, error) {
	if !core.IsCanonicalPath(localPath) || localPath == "/" {
		return nil, errors.New("local workspace path must be a canonical absolute path")
	}
	if err := validCompanion(rule); err != nil {
		return nil, err
	}
	original := unitPaths(rule, rule.Path)
	paths := unitPaths(rule, localPath)
	if rule.Path != localPath {
		paths = append(paths, original...)
	}
	for _, path := range paths {
		if core.PathsOverlap(path, rule.Archive.Directory) {
			return nil, errors.New("archive directory must be outside the archived workspace")
		}
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
	parent, err := openDirectory(filepath.Dir(localPath))
	if err != nil {
		return nil, fmt.Errorf("local workspace: %w", err)
	}
	defer parent.Close()
	local, _, err := openEntry(parent, localPath, true)
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
	for _, path := range original {
		if secretLike(filepath.Base(path), filepath.Dir(path), scope.SensitiveNames) {
			return nil, fmt.Errorf("secret-like files keep %s local: .", path)
		}
	}
	if err := walk.err(); err != nil {
		return nil, err
	}
	if err := sameMembers(walk.inv.members, m.Members, full); err != nil {
		return nil, err
	}
	var c *companion
	if rule.Companion != "" {
		if c, err = observeCompanion(ctx, parent, localPath+rule.CompanionSuffix(), scope.SensitiveNames, walk.rootState, full); err != nil {
			return nil, err
		}
		defer c.close()
		if err := sameCompanion(c, m.Companion, full); err != nil {
			return nil, err
		}
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
	if err := scope.live(ctx, paths, rule.Mentions); err != nil {
		return nil, err
	}
	// The live checks take time; the unit must still be the one compared.
	if err := walk.inv.unchanged(local); err != nil {
		return nil, errors.New("local tree changed while being bound to its archive; local changes would be lost")
	}
	if c != nil {
		if err := c.unchanged(parent); err != nil {
			return nil, fmt.Errorf("local companion changed while being bound to its archive; local changes would be lost: %w", err)
		}
	}
	digest := sha256.New()
	encoder := json.NewEncoder(digest)
	if err := encoder.Encode(m.Members); err != nil {
		return nil, err
	}
	binding := &core.WorkspaceArchiveBinding{
		Manifest: rule.Archive.Manifest, ManifestSHA256: rule.Archive.ManifestSHA256,
		MemberCount: len(m.Members), CreatedAt: m.CreatedAt.UTC(), CompanionSuffix: rule.CompanionSuffix(),
	}
	// The companion is part of the bound unit: a different one is a
	// different fingerprint.
	if m.Companion != nil {
		if err := encoder.Encode(m.Companion); err != nil {
			return nil, err
		}
		binding.MemberCount++
		binding.CompanionID = c.state.id
	}
	binding.TreeDigest = hex.EncodeToString(digest.Sum(nil))
	return binding, nil
}

// VerifyCompanion is Bind's companion half for a companion left at path
// without its primary, as when an expiry stopped between deleting the two.
// Its identity proves nothing about its bytes: an append keeps it. The
// pinned archive must verify in full and record a companion, and the local
// file must equal it in type, size, mode, owner, modification time and
// SHA-256. The companion screens and the live process, mention and external
// dependent checks are repeated for path and the rule's companion name.
// VerifyCompanion never modifies anything.
func VerifyCompanion(ctx context.Context, rule config.WorkspaceArchiveRule, scope Scope, path string) error {
	if !core.IsCanonicalPath(path) || path == "/" {
		return errors.New("local companion path must be a canonical absolute path")
	}
	if err := validCompanion(rule); err != nil {
		return err
	}
	if rule.Companion == "" {
		return errors.New("the workspace archive rule binds no companion")
	}
	for _, name := range []string{path, rule.Companion} {
		if core.PathsOverlap(name, rule.Archive.Directory) {
			return errors.New("archive directory must be outside the archived workspace")
		}
	}
	if len(scope.SearchRoots) == 0 {
		return errors.New("external dependent scan requires at least one search root")
	}
	m, root, tarFile, err := load(ctx, rule)
	if err != nil {
		return err
	}
	defer root.Close()
	defer tarFile.Close()
	if err := verifyArchive(ctx, m, root, tarFile); err != nil {
		return err
	}
	if m.Companion == nil {
		return fmt.Errorf("the archive records the companion absent, so %s was never archived; local changes would be lost", path)
	}
	parent, err := openDirectory(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("local companion: %w", err)
	}
	defer parent.Close()
	parentSt, err := fstate(parent)
	if err != nil {
		return err
	}
	c, err := observeCompanion(ctx, parent, path, scope.SensitiveNames, parentSt, true)
	if err != nil {
		return err
	}
	defer c.close()
	if err := sameCompanion(c, m.Companion, true); err != nil {
		return err
	}
	if err := scope.live(ctx, []string{path, rule.Companion}, rule.Mentions); err != nil {
		return err
	}
	// The live checks take time; the companion must still be the one compared.
	if err := c.unchanged(parent); err != nil {
		return fmt.Errorf("local companion changed while being verified; local changes would be lost: %w", err)
	}
	return nil
}

// sameCompanion compares the local companion with the archive's record: a
// recorded absence must persist, and a recorded file must be present and
// equal in every fact sameMembers compares. Its name is the unit's, which
// differs at a quarantined copy, so it is not compared.
func sameCompanion(c *companion, want *Member, full bool) error {
	switch {
	case want == nil && c.file != nil:
		return fmt.Errorf("local companion appeared at %s, which the archive records absent; local changes would be lost", c.path)
	case want == nil:
		return nil
	case c.file == nil:
		return fmt.Errorf("local companion %s is missing; the archive does not match the local unit", c.path)
	}
	got := c.member
	got.Path = want.Path
	if !full {
		got.SHA256 = want.SHA256
	}
	if got != *want {
		return fmt.Errorf("local companion %s differs from the archive (type, size, mode, owner, modification time or content); local changes would be lost", c.path)
	}
	return nil
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
