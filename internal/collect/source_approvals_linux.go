//go:build linux

package collect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
)

const maxApprovedSourceBytes = 1 << 20

type worktreeIndexEntry struct {
	mode string
	blob string
}

type sourceApprovalVerifier struct {
	ctx    context.Context
	runner gitRunner
	path   string
	origin string
	policy *config.Policy
	state  *core.GitState
	now    time.Time
	used   bool
	// headChecked records that HEAD was compared with the commit whose
	// publication the collector measured; headTree is that commit's file
	// listing, nil unless HEAD is still it and the listing completed.
	headChecked      bool
	headTree         map[string]worktreeIndexEntry
	publishedMatches []string
	publishedCount   int
	// publishedSecrets are built-in secret names found published in Git;
	// secretRefusal, the refusal for the first, is returned after the walk.
	publishedSecrets []core.PublishedSecret
	secretRefusal    error
}

func (v *sourceApprovalVerifier) approve(parent *os.File, name, relative, pattern string, stat unix.Stat_t, indexed worktreeIndexEntry) error {
	refusal := protectedWorktreeName(relative, pattern)
	if v.policy == nil || v.policy.SourceNameApprovals == nil || !config.SourceApprovalPath(relative) ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size < 0 || stat.Size > maxApprovedSourceBytes ||
		(indexed.mode != "100644" && indexed.mode != "100755") ||
		(indexed.mode == "100755") != (stat.Mode&0111 != 0) ||
		v.state == nil || !v.state.Clean() || !v.state.PublicationKnown || v.state.Remote == "" {
		return refusal
	}
	policy := v.policy.SourceNameApprovals
	var approval *config.SourceNameApproval
	for i := range policy.Files {
		candidate := &policy.Files[i]
		if candidate.Repository == v.origin && candidate.Path == relative && candidate.NamePattern == pattern {
			// Direct collector callers must fail closed on ambiguous policies too.
			if approval != nil {
				return refusal
			}
			approval = candidate
		}
	}
	if approval == nil || approval.Remote != v.state.Remote || approval.Generation == "" || approval.Generation != policy.Generation ||
		approval.Record == "" || approval.ReviewedAt.IsZero() || v.now.Before(approval.ReviewedAt) || !v.now.Before(approval.ExpiresAt) ||
		approval.Blob != indexed.blob {
		return refusal
	}
	authorized := false
	for _, reviewer := range policy.Reviewers {
		authorized = authorized || (reviewer != "" && reviewer == approval.Reviewer)
	}
	if !authorized {
		return refusal
	}
	// The origin URL is bound by the approval. Publication uses the same local,
	// remote-tracking evidence as the ordinary Git safety guard; never fetch.
	commit, err := v.runner.runOutput(v.ctx, v.path, 256, "rev-parse", "--verify", approval.Commit+"^{commit}")
	if err != nil || commit != approval.Commit {
		return refusal
	}
	unpublished, err := v.runner.runOutput(v.ctx, v.path, 256, "rev-list", "--count", approval.Commit, "--not", "--remotes=origin")
	if err != nil || unpublished != "0" {
		return refusal
	}
	blob, err := v.runner.runOutput(v.ctx, v.path, 256, "rev-parse", "--verify", approval.Commit+":"+relative)
	if err != nil || blob != indexed.blob {
		return refusal
	}
	content := sha256.New()
	actual, ok, err := trackedFileBlob(v.ctx, parent, name, stat, indexed.blob, content)
	if err != nil {
		return err
	}
	if !ok || hex.EncodeToString(content.Sum(nil)) != approval.SHA256 || actual != approval.Blob {
		return refusal
	}
	v.used = true
	return nil
}

// trackedFileBlob reopens name without following links and hashes the bytes
// stat observed as a Git blob in the object format of like. ok is false
// unless the file kept its identity, links, size and times before and after
// the read. The error is only ever a cancellation.
func trackedFileBlob(ctx context.Context, parent *os.File, name string, stat unix.Stat_t, like string, also io.Writer) (string, bool, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", false, nil
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || !sameApprovedSource(stat, opened) {
		return "", false, nil
	}
	blob, err := core.GitBlobID(ctx, file, stat.Size, like, also)
	if err != nil {
		return "", false, ctx.Err()
	}
	var after, named unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameApprovedSource(opened, after) {
		return "", false, nil
	}
	if err := unix.Fstatat(int(parent.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameApprovedSource(after, named) {
		return "", false, nil
	}
	return blob, true, nil
}

// maxPublishedNameBytes bounds the hash of one published protected-name file:
// a larger file keeps its refusal rather than stretching the bounded proof.
const maxPublishedNameBytes = 64 << 20

// maxPublishedNameEvidence bounds the published matches listed as evidence
// (the rest are counted) and the published secrets reported.
const maxPublishedNameEvidence = 32

// publishable reports whether protect.published_name_matches: allow can
// resolve anything in this worktree: the Git collector measured its HEAD as
// on a remote-tracking branch with nothing dirty, stashed or locked, and HEAD
// is still that commit. Its first call loads the HEAD tree. The error is only
// ever a cancellation.
func (v *sourceApprovalVerifier) publishable() (bool, error) {
	if v.policy == nil || !v.policy.Protect.AllowsPublishedNameMatches() ||
		v.state == nil || v.state.Bare || !v.state.Clean() || v.state.Head == "" {
		return false, nil
	}
	if !v.headChecked {
		v.headChecked = true
		head, err := v.runner.runOutput(v.ctx, v.path, 256, "rev-parse", "--verify", "HEAD^{commit}")
		if err != nil || head != v.state.Head {
			return false, v.ctx.Err()
		}
		v.headTree, err = headTree(v.ctx, v.runner, v.path, v.state.Head)
		if err != nil {
			return false, v.ctx.Err()
		}
	}
	return v.headTree != nil, v.ctx.Err()
}

// headTree lists every file of commit by path, within the proof's bounds.
func headTree(ctx context.Context, runner gitRunner, path, commit string) (map[string]worktreeIndexEntry, error) {
	listing, err := runner.runOutput(ctx, path, worktreeMaxGitBytes, "ls-tree", "-r", "-z", "--full-tree", commit)
	if err != nil {
		return nil, err
	}
	tree := make(map[string]worktreeIndexEntry)
	for listing != "" {
		record, rest, ok := strings.Cut(listing, "\x00")
		if !ok {
			return nil, errors.New("incomplete Git tree listing")
		}
		listing = rest
		metadata, name, ok := strings.Cut(record, "\t")
		fields := strings.Fields(metadata)
		if !ok || len(fields) != 3 || !validWorktreeRelative(name) {
			return nil, errors.New("invalid Git tree listing")
		}
		if len(tree) >= worktreeMaxEntries {
			return nil, errors.New("Git tree entry bound exceeded")
		}
		tree[name] = worktreeIndexEntry{mode: fields[0], blob: fields[2]}
	}
	return tree, nil
}

// published reports whether one descendant is a published tracked file under
// protect.published_name_matches: allow. It must be regular, not hard-linked
// and tracked as an ordinary file; its bytes must be the index blob, which
// must be the entry (mode and blob) at the measured, published HEAD.
// Anything else, including an incomplete check, is not published. The error
// is only ever a cancellation.
func (v *sourceApprovalVerifier) published(parent *os.File, name, relative string, stat unix.Stat_t, indexed worktreeIndexEntry) (bool, error) {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size < 0 || stat.Size > maxPublishedNameBytes ||
		(indexed.mode != "100644" && indexed.mode != "100755") ||
		(indexed.mode == "100755") != (stat.Mode&0111 != 0) {
		return false, nil
	}
	if ok, err := v.publishable(); !ok || err != nil {
		return false, err
	}
	if v.headTree[relative] != indexed {
		return false, nil
	}
	actual, ok, err := trackedFileBlob(v.ctx, parent, name, stat, indexed.blob, nil)
	if err != nil || !ok || actual != indexed.blob {
		return false, err
	}
	return true, nil
}

func (v *sourceApprovalVerifier) recordPublished(kind, relative string, matches []string) {
	v.publishedCount++
	if len(v.publishedMatches) < maxPublishedNameEvidence {
		v.publishedMatches = append(v.publishedMatches, fmt.Sprintf("protected-name match on published tracked %s %q (%s)", kind, relative, strings.Join(matches, ", ")))
	}
}

// publishedEvidence lists the resolved published matches, then how many
// more were resolved than are listed.
func (v *sourceApprovalVerifier) publishedEvidence() []string {
	if more := v.publishedCount - len(v.publishedMatches); more > 0 {
		return append(v.publishedMatches, fmt.Sprintf("%d more protected-name match(es) on published tracked files or directories", more))
	}
	return v.publishedMatches
}

// recordSecret reports a built-in secret name that is a published tracked
// file. The worktree stays refused, and so does any protected-name directory
// holding it; the walk continues so that every such leak is reported.
func (v *sourceApprovalVerifier) recordSecret(relative string, within *protectedSubtree) {
	if v.secretRefusal == nil {
		v.secretRefusal = &worktreePolicyRefusal{fmt.Sprintf("worktree descendant %q is a secret published in Git at %s; rotate it and remove it from the history", relative, v.state.Head)}
	}
	if within != nil {
		within.holdsSecret = true
	}
	if len(v.publishedSecrets) < maxPublishedNameEvidence {
		v.publishedSecrets = append(v.publishedSecrets, core.PublishedSecret{Repository: core.RepositoryLabel(v.state.Remote, v.origin), Path: relative, Head: v.state.Head})
	}
}

func sameApprovedSource(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func (v *sourceApprovalVerifier) fingerprint() (string, error) {
	if !v.used {
		return "", nil
	}
	data, err := json.Marshal(v.policy.SourceNameApprovals)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

// protectedSubtree is a directory whose own name refuses unless every file
// below it is a published tracked file that is not a built-in secret.
type protectedSubtree struct {
	refusal     error
	matches     []string
	holdsSecret bool
}

// checkNames applies classification.evidence_names and protect.name_patterns
// to one descendant. Explicit paths, report-only roots and preserving cache
// rules are checked elsewhere and cannot be waived. A name-pattern match may
// be approved by source_name_approvals; any remaining match refuses unless
// protect.published_name_matches: allow resolves it.
//
// Under allow, the built-in secret screen also applies to every descendant,
// matched or not: a built-in secret name never passes, and a published one
// is reported. A published tracked file with a matching name is recorded and
// passes; a matching directory is returned as a subtree the walk must prove.
// Inside within, every file must be published. Each descendant's
// publication is proven (and its bytes hashed) at most once.
func (v *sourceApprovalVerifier) checkNames(parent *os.File, name, relative string, stat unix.Stat_t, indexed worktreeIndexEntry, within *protectedSubtree) (*protectedSubtree, error) {
	if v.policy == nil {
		return nil, nil
	}
	var refusal error
	var matches []string
	for _, pattern := range v.policy.Classification.EvidenceNames {
		matched, err := filepath.Match(pattern, name)
		evidence := &worktreePolicyRefusal{fmt.Sprintf("worktree descendant %q matches protected evidence name %q", relative, pattern)}
		if err != nil {
			return nil, evidence
		}
		if matched {
			refusal, matches = evidence, append(matches, fmt.Sprintf("evidence name %q", pattern))
			break
		}
	}
	for _, pattern := range v.policy.Protect.NamePatterns {
		matched, err := filepath.Match(pattern, name)
		if err != nil {
			return nil, protectedWorktreeName(relative, pattern)
		}
		if !matched {
			continue
		}
		err = v.approve(parent, name, relative, pattern, stat, indexed)
		var unapproved *worktreePolicyRefusal
		if err != nil && !errors.As(err, &unapproved) {
			return nil, err
		}
		if err != nil {
			if refusal == nil {
				refusal = err
			}
			matches = append(matches, fmt.Sprintf("pattern %q", pattern))
		}
	}
	if !v.policy.Protect.AllowsPublishedNameMatches() {
		return nil, refusal
	}
	dir := stat.Mode&unix.S_IFMT == unix.S_IFDIR
	if core.BuiltinSecretName(name, filepath.Join(v.origin, filepath.Dir(relative))) {
		if refusal == nil {
			refusal = &worktreePolicyRefusal{fmt.Sprintf("worktree descendant %q matches the built-in secret screen", relative)}
		}
		if dir {
			return nil, refusal
		}
		published, err := v.published(parent, name, relative, stat, indexed)
		if err != nil {
			return nil, err
		}
		if !published {
			return nil, refusal
		}
		v.recordSecret(relative, within)
		return nil, nil
	}
	if dir {
		if refusal == nil {
			return nil, nil
		}
		if ok, err := v.publishable(); err != nil {
			return nil, err
		} else if !ok {
			return nil, refusal
		}
		return &protectedSubtree{refusal: refusal, matches: matches}, nil
	}
	if refusal == nil && within == nil {
		return nil, nil
	}
	published, err := v.published(parent, name, relative, stat, indexed)
	switch {
	case err != nil:
		return nil, err
	case !published && refusal != nil:
		return nil, refusal
	case !published:
		return nil, within.refusal
	case refusal != nil:
		v.recordPublished("file", relative, matches)
	}
	return nil, nil
}
