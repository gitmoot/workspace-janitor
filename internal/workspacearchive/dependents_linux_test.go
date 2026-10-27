//go:build linux

package workspacearchive

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dependentFixture builds one search root holding six trees and, outside all
// of them, a pointer of each kind into exactly one tree.
func dependentFixture(t *testing.T) (root string, refused map[string]bool) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	refused = map[string]bool{}
	for _, name := range []string{"direct", "chained", "through-dir", "gitdir", "alternates", "clean"} {
		tree := filepath.Join(root, name)
		write(t, filepath.Join(tree, "sub", "data"), []byte(name+"\n"), 0o644)
		refused[tree] = name != "clean"
	}
	links := filepath.Join(root, "links")
	if err := os.MkdirAll(links, 0o755); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, filepath.Join(root, "direct", "sub"), filepath.Join(links, "direct"))
	mustSymlink(t, filepath.Join(links, "chain-2"), filepath.Join(links, "chain-1"))
	mustSymlink(t, filepath.Join(root, "chained"), filepath.Join(links, "chain-2"))
	mustSymlink(t, filepath.Join(root, "through-dir"), filepath.Join(links, "alias"))
	mustSymlink(t, filepath.Join(links, "alias", "sub", "data"), filepath.Join(links, "via-alias"))
	write(t, filepath.Join(root, "repo", ".git"), []byte("gitdir: "+filepath.Join(root, "gitdir", "admin")+"\n"), 0o644)
	write(t, filepath.Join(root, "repo2", "objects", "info", "alternates"), []byte(filepath.Join(root, "alternates", "objects")+"\n"), 0o644)
	return root, refused
}

// The shared index reaches the same verdict as the per-tree walk for every
// pointer kind: a symlink straight into a tree, a chain ending in it, a link
// through a symlinked directory, a gitdir file and an alternates file each
// refuse exactly the tree they reach, and an unreferenced tree passes.
func TestDependentIndexMatchesPerTreeScan(t *testing.T) {
	ctx := context.Background()
	root, refused := dependentFixture(t)
	index := BuildDependentIndex(ctx, []string{root}, 1000)
	for tree, want := range refused {
		indexed := index.dependents(tree)
		walked := externalDependents(ctx, tree, []string{root}, 1000)
		if (indexed != nil) != want {
			t.Errorf("%s: index verdict %v, want refused=%t", tree, indexed, want)
		}
		if (walked != nil) != (indexed != nil) {
			t.Errorf("%s: index verdict %v differs from per-tree walk %v", tree, indexed, walked)
		}
	}
}

// One index walk covers trees whose separate per-tree walks would each exceed
// the per-tree bound.
func TestDependentIndexFitsWhereManyPerTreeWalksExceedTheirBound(t *testing.T) {
	ctx := context.Background()
	root, refused := dependentFixture(t)
	clean := filepath.Join(root, "clean")
	if refused[clean] {
		t.Fatal("fixture marks the clean tree refused")
	}
	if err := externalDependents(ctx, clean, []string{root}, 10); err == nil || !strings.Contains(err.Error(), "bound") {
		t.Fatalf("per-tree walk with a small bound: %v", err)
	}
	if err := BuildDependentIndex(ctx, []string{root}, 1000).dependents(clean); err != nil {
		t.Fatalf("index refused an unreferenced tree: %v", err)
	}
}

// An index whose walk exceeds its own bound refuses every tree, never
// reporting "no dependents".
func TestDependentIndexOverItsBoundRefusesEveryTree(t *testing.T) {
	root, refused := dependentFixture(t)
	// The root lists 9 names, so the listing fits and the total walk does not.
	index := BuildDependentIndex(context.Background(), []string{root}, 12)
	for tree := range refused {
		if err := index.dependents(tree); err == nil || !strings.Contains(err.Error(), "dependent index bound") {
			t.Errorf("%s: over-bound index verdict %v", tree, err)
		}
	}
}

// An unresolvable symlink outside a tree may reach it, so it refuses every
// tree it lies outside, exactly like the per-tree walk.
func TestDependentIndexRefusesUnresolvableLinks(t *testing.T) {
	ctx := context.Background()
	root, refused := dependentFixture(t)
	loop := filepath.Join(root, "links", "loop")
	mustSymlink(t, loop, loop)
	index := BuildDependentIndex(ctx, []string{root}, 1000)
	for tree := range refused {
		indexed := index.dependents(tree)
		if indexed == nil || !strings.Contains(indexed.Error(), "cannot be resolved") {
			t.Errorf("%s: index ignored an unresolvable link: %v", tree, indexed)
		}
		if walked := externalDependents(ctx, tree, []string{root}, 1000); walked == nil {
			t.Errorf("%s: per-tree walk ignored an unresolvable link", tree)
		}
	}
}
