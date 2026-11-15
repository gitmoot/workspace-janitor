//go:build linux

package workspacearchive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
)

const (
	// maxPublishedNameBytes bounds the hash of one published file: a larger
	// file keeps the tree local rather than stretching the inspection.
	maxPublishedNameBytes = 64 << 20
	// maxPublishedListing bounds each Git listing (index, HEAD tree) the
	// published check reads; a larger repository keeps every match refused.
	maxPublishedListing = 16 << 20
)

type gitEntry struct{ mode, blob string }

// publishedTree resolves secret-like names under
// protect.published_name_matches: allow. Only a regular, non-hard-linked file
// that the tree's own repository tracks as an ordinary file, whose bytes are
// its index blob, which is the entry at HEAD, with HEAD on a remote-tracking
// branch, is published: its content is already on the remote. Untracked,
// ignored, modified, unpublished or uncheckable files are not.
type publishedTree struct {
	ctx    context.Context
	source string
	// loaded records that the repository was examined; index and tree are
	// nil unless the tree is its repository's top level with a published
	// HEAD and both listings completed within their bounds.
	loaded      bool
	head, label string
	index, tree map[string]gitEntry
}

type listingBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (b *listingBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > maxPublishedListing {
		b.exceeded = true
		return 0, errors.New("Git listing bound exceeded")
	}
	return b.Buffer.Write(p)
}

// listing runs one NUL-delimited Git listing of three space-separated fields
// and a path, and maps each path to its mode (fields[0]) and object
// (fields[object]). A staged listing accepts only stage-0 entries.
func (p *publishedTree) listing(object int, staged bool, args ...string) map[string]gitEntry {
	var out listingBuffer
	if _, err := runGit(p.ctx, p.source, &out, nil, args...); err != nil || out.exceeded {
		return nil
	}
	entries := make(map[string]gitEntry)
	for _, record := range strings.Split(strings.TrimSuffix(out.String(), "\x00"), "\x00") {
		if record == "" {
			continue
		}
		metadata, path, ok := strings.Cut(record, "\t")
		fields := strings.Fields(metadata)
		if !ok || len(fields) != 3 || path == "" || (staged && fields[2] != "0") {
			return nil
		}
		entries[path] = gitEntry{mode: fields[0], blob: fields[object]}
	}
	return entries
}

func (p *publishedTree) load() bool {
	if p.loaded {
		return p.tree != nil
	}
	p.loaded = true
	top, err := runGit(p.ctx, p.source, nil, nil, "rev-parse", "--show-toplevel")
	if err != nil || top != p.source {
		return false
	}
	head, err := runGit(p.ctx, p.source, nil, nil, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return false
	}
	unpublished, err := runGit(p.ctx, p.source, nil, nil, "rev-list", "--count", head, "--not", "--remotes")
	if err != nil || unpublished != "0" {
		return false
	}
	// No origin is not an error: the report then names the checkout path.
	origin, _ := runGit(p.ctx, p.source, nil, nil, "config", "--get", "remote.origin.url")
	index := p.listing(1, true, "ls-files", "--stage", "-z")
	tree := p.listing(2, false, "ls-tree", "-r", "-z", "--full-tree", head)
	if index == nil || tree == nil {
		return false
	}
	p.head, p.label, p.index, p.tree = head, core.RepositoryLabel(origin, p.source), index, tree
	return true
}

// file reports whether member path, the child name of dir observed as st,
// is a published tracked file.
func (p *publishedTree) file(dir *os.File, name, path string, st state) bool {
	if st.kind() != unix.S_IFREG || st.nlink != 1 || st.size < 0 || st.size > maxPublishedNameBytes || !p.load() {
		return false
	}
	indexed, ok := p.index[path]
	if !ok || (indexed.mode != "100644" && indexed.mode != "100755") ||
		(indexed.mode == "100755") != (st.mode&0111 != 0) || p.tree[path] != indexed {
		return false
	}
	f, err := openChild(dir, name, unix.O_RDONLY)
	if err != nil {
		return false
	}
	defer f.Close()
	if opened, err := fstate(f); err != nil || opened != st {
		return false
	}
	actual, err := core.GitBlobID(p.ctx, f, st.size, indexed.blob, nil)
	if err != nil || actual != indexed.blob {
		return false
	}
	after, err := fstate(f)
	if err != nil || after != st {
		return false
	}
	named, err := statxAt(int(dir.Fd()), name, 0)
	return err == nil && named == st
}

// secret is the report for a published file with a built-in secret name.
func (p *publishedTree) secret(path string) core.PublishedSecret {
	return core.PublishedSecret{Repository: p.label, Path: path, Head: p.head}
}

// publishedMatch is the evidence line for one resolved secret-like name.
func publishedMatch(kind, path string) string {
	return fmt.Sprintf("protected-name match on published tracked %s %q", kind, path)
}

// secretRefusal is the secret screen's refusal. published lists the
// built-in secret names among them that are published in Git: leaks to
// rotate and remove from the history, reported with the refusal.
type secretRefusal struct {
	source    string
	secrets   []string
	published []core.PublishedSecret
}

func (e *secretRefusal) Error() string {
	message := fmt.Sprintf("secret-like files keep %s local: %s", e.source, strings.Join(e.secrets, ", "))
	if len(e.published) == 0 {
		return message
	}
	leaks := make([]string, len(e.published))
	for i, secret := range e.published {
		leaks[i] = fmt.Sprintf("%s in %s at %s", secret.Path, secret.Repository, secret.Head)
	}
	return message + "; published in Git, rotate and remove from the history: " + strings.Join(leaks, ", ")
}
