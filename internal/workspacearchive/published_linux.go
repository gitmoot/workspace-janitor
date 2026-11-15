//go:build linux

package workspacearchive

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
)

// maxPublishedNameBytes bounds the hash of one published secret-like file: a
// larger file keeps the tree local rather than stretching the inspection.
const maxPublishedNameBytes = 64 << 20

// publishedTree resolves secret-like names under
// protect.published_name_matches: allow. Only a regular, non-hard-linked file
// that the tree's own repository tracks as an ordinary file, whose bytes are
// its index blob, which is the blob at HEAD, with HEAD on a remote-tracking
// branch, is resolved: its content is already published. Untracked, ignored,
// modified, unpublished or uncheckable files keep the tree local.
type publishedTree struct {
	ctx    context.Context
	source string
	// checked records that head was looked up; head is empty unless the
	// tree is its repository's top level with a published HEAD.
	checked bool
	head    string
}

func (p *publishedTree) publishedHead() string {
	if p.checked {
		return p.head
	}
	p.checked = true
	top, err := runGit(p.ctx, p.source, nil, nil, "rev-parse", "--show-toplevel")
	if err != nil || top != p.source {
		return ""
	}
	head, err := runGit(p.ctx, p.source, nil, nil, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return ""
	}
	unpublished, err := runGit(p.ctx, p.source, nil, nil, "rev-list", "--count", head, "--not", "--remotes")
	if err != nil || unpublished != "0" {
		return ""
	}
	p.head = head
	return head
}

// resolve reports whether member path, the child name of dir observed as st,
// is a published tracked file.
func (p *publishedTree) resolve(dir *os.File, name, path string, st state) bool {
	if st.kind() != unix.S_IFREG || st.nlink != 1 || st.size < 0 || st.size > maxPublishedNameBytes {
		return false
	}
	head := p.publishedHead()
	if head == "" {
		return false
	}
	index, err := runGit(p.ctx, p.source, nil, nil, "--literal-pathspecs", "ls-files", "--stage", "-z", "--", path)
	if err != nil {
		return false
	}
	record, ok := strings.CutSuffix(index, "\x00")
	if !ok || strings.Contains(record, "\x00") {
		return false
	}
	metadata, indexed, ok := strings.Cut(record, "\t")
	if !ok || indexed != path {
		return false
	}
	fields := strings.Fields(metadata)
	if len(fields) != 3 || fields[2] != "0" || (fields[0] != "100644" && fields[0] != "100755") ||
		(fields[0] == "100755") != (st.mode&0111 != 0) {
		return false
	}
	blob := fields[1]
	if committed, err := runGit(p.ctx, p.source, nil, nil, "rev-parse", "--verify", head+":"+path); err != nil || committed != blob {
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
	actual, err := core.GitBlobID(p.ctx, f, st.size, blob, nil)
	if err != nil || actual != blob {
		return false
	}
	after, err := fstate(f)
	if err != nil || after != st {
		return false
	}
	named, err := statxAt(int(dir.Fd()), name, 0)
	return err == nil && named == st
}

// publishedMatch is the evidence line for one resolved secret-like name.
func publishedMatch(path string) string {
	return fmt.Sprintf("protected-name match on published tracked file %q", path)
}
