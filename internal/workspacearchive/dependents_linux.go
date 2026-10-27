//go:build linux

package workspacearchive

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
)

// pointer is one record that can make a tree a dependency of something
// outside it: a symlink (with every path its chain reaches and its lexical
// target), a gitdir file target or an object alternates target.
type pointer struct {
	path    string
	what    string
	target  string
	reaches []string
	// unresolved is set for a symlink chain that could not be followed to
	// its end; such a link may reach anything, so it is a dependent of every
	// tree it lies outside of.
	unresolved string
}

// DependentIndex is a snapshot of every dependent pointer under a set of
// search roots, taken by one bounded walk per root with the same rules as the
// per-tree dependent scan: same filesystem as the root, the same depth bound,
// symlinks followed as the kernel would, `.git` gitdir files and
// objects/info/alternates. Many trees can then be checked against one walk.
// A walk that failed or exceeded its bound refuses every tree.
type DependentIndex struct {
	pointers []pointer
	err      error
}

// BuildDependentIndex walks every search root once, visiting at most limit
// entries in total.
func BuildDependentIndex(ctx context.Context, roots []string, limit int) *DependentIndex {
	index := &DependentIndex{}
	if len(roots) == 0 {
		index.err = errors.New("external dependent scan requires at least one search root")
		return index
	}
	visited := 0
	for _, root := range roots {
		dir, err := openDirectory(root)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			index.err = fmt.Errorf("dependent index of %s: %w", root, err)
			return index
		}
		rootState, err := fstate(dir)
		if err == nil {
			err = index.walk(ctx, dir, root, rootState.id.Device, 0, &visited, limit)
		}
		dir.Close()
		if err != nil {
			index.err = fmt.Errorf("dependent index of %s: %w", root, err)
			return index
		}
	}
	return index
}

func (x *DependentIndex) walk(ctx context.Context, dir *os.File, dirAbs string, device uint64, depth int, visited *int, limit int) error {
	names, err := readNames(dir, limit)
	if err != nil {
		return err
	}
	fd := int(dir.Fd())
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		*visited++
		if *visited > limit {
			return fmt.Errorf("exceeded the %d-entry dependent index bound; raise limits.dependent_index_max_entries", limit)
		}
		path := filepath.Join(dirAbs, name)
		st, err := statxAt(fd, name, 0)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return err
		}
		switch st.kind() {
		case unix.S_IFLNK:
			target, err := readlinkAt(fd, name)
			if err != nil {
				return err
			}
			record := pointer{path: path, what: "symlink", target: target}
			reached, err := resolveLink(path, target)
			if err != nil {
				record.unresolved = err.Error()
			} else {
				lexical := target
				if !filepath.IsAbs(lexical) {
					lexical = filepath.Join(dirAbs, lexical)
				}
				record.reaches = append(reached, filepath.Clean(lexical))
			}
			x.pointers = append(x.pointers, record)
		case unix.S_IFREG:
			isAlternates := name == "alternates" && filepath.Base(dirAbs) == "info" && filepath.Base(filepath.Dir(dirAbs)) == "objects"
			if name != ".git" && !isAlternates {
				continue
			}
			data, err := readSmall(dir, name)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			if isAlternates {
				for _, target := range alternateTargets(data, filepath.Dir(dirAbs)) {
					x.pointers = append(x.pointers, pointer{path: path, what: "alternates", target: target, reaches: []string{target}})
				}
			} else if target, ok := gitdirTarget(data, dirAbs); ok {
				x.pointers = append(x.pointers, pointer{path: path, what: "gitdir", target: target, reaches: []string{target}})
			}
		case unix.S_IFDIR:
			if depth+1 >= dependentDepth || st.id.Device != device {
				continue
			}
			child, err := openChild(dir, name, unix.O_RDONLY|unix.O_DIRECTORY)
			if err != nil {
				return err
			}
			err = x.walk(ctx, child, path, device, depth+1, visited, limit)
			child.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// dependents reports the indexed pointers outside source that reach into it,
// with the same wording and the same refusal of unresolvable links as the
// per-tree scan.
func (x *DependentIndex) dependents(source string) error {
	if x.err != nil {
		return x.err
	}
	var hits []string
	hit := func(detail string) {
		if len(hits) < maxReported {
			hits = append(hits, detail)
		}
	}
	for _, record := range x.pointers {
		if core.PathWithin(record.path, source) {
			continue
		}
		if record.unresolved != "" {
			hit(fmt.Sprintf("symlink %s -> %s cannot be resolved: %s", record.path, record.target, record.unresolved))
			continue
		}
		for _, p := range record.reaches {
			if !core.PathWithin(p, source) {
				continue
			}
			if record.what == "symlink" {
				hit(fmt.Sprintf("symlink %s -> %s reaches %s", record.path, record.target, p))
			} else {
				hit(fmt.Sprintf("%s %s -> %s", record.what, record.path, record.target))
			}
			break
		}
	}
	if len(hits) > 0 {
		return fmt.Errorf("external dependents keep %s local: %s", source, strings.Join(hits, "; "))
	}
	return nil
}

// dependents runs the dependent check for source: against the shared index
// when the scope carries one, otherwise by walking the search roots.
func (s Scope) dependents(ctx context.Context, source string) error {
	if s.Dependents != nil {
		return s.Dependents.dependents(source)
	}
	return externalDependents(ctx, source, s.SearchRoots, s.limit())
}
