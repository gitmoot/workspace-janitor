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
	// headChecked/headCurrent cache whether HEAD is still the commit whose
	// publication the collector measured.
	headChecked, headCurrent bool
	publishedMatches         []string
	publishedCount           int
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

// maxPublishedNameEvidence bounds the published matches listed as evidence;
// the rest are counted.
const maxPublishedNameEvidence = 32

// published resolves one protected-name match under
// protect.published_name_matches: allow. The file must be regular, not
// hard-linked and tracked as an ordinary file; its bytes must be the index
// blob, which must be the blob at the measured HEAD, which the Git collector
// measured as on a remote-tracking branch with nothing dirty, stashed or
// locked. Anything else, including an incomplete check, keeps the refusal.
// The error is only ever a cancellation.
func (v *sourceApprovalVerifier) published(parent *os.File, name, relative string, stat unix.Stat_t, indexed worktreeIndexEntry) (bool, error) {
	if v.policy == nil || !v.policy.Protect.AllowsPublishedNameMatches() ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size < 0 || stat.Size > maxPublishedNameBytes ||
		(indexed.mode != "100644" && indexed.mode != "100755") ||
		(indexed.mode == "100755") != (stat.Mode&0111 != 0) ||
		v.state == nil || v.state.Bare || !v.state.Clean() || v.state.Head == "" {
		return false, nil
	}
	// Publication was measured for the HEAD the collector saw; a HEAD that
	// moved since is unmeasured.
	if !v.headChecked {
		head, err := v.runner.runOutput(v.ctx, v.path, 256, "rev-parse", "--verify", "HEAD^{commit}")
		v.headChecked, v.headCurrent = true, err == nil && head == v.state.Head
	}
	if !v.headCurrent {
		return false, v.ctx.Err()
	}
	blob, err := v.runner.runOutput(v.ctx, v.path, 256, "rev-parse", "--verify", v.state.Head+":"+relative)
	if err != nil || blob != indexed.blob {
		return false, v.ctx.Err()
	}
	actual, ok, err := trackedFileBlob(v.ctx, parent, name, stat, indexed.blob, nil)
	if err != nil || !ok || actual != indexed.blob {
		return false, err
	}
	return true, nil
}

func (v *sourceApprovalVerifier) recordPublished(relative, pattern string) {
	v.publishedCount++
	if len(v.publishedMatches) < maxPublishedNameEvidence {
		v.publishedMatches = append(v.publishedMatches, fmt.Sprintf("protected-name match on published tracked file %q (pattern %q)", relative, pattern))
	}
}

// publishedEvidence lists the resolved published matches, then how many
// more were resolved than are listed.
func (v *sourceApprovalVerifier) publishedEvidence() []string {
	if more := v.publishedCount - len(v.publishedMatches); more > 0 {
		return append(v.publishedMatches, fmt.Sprintf("%d more protected-name match(es) on published tracked files", more))
	}
	return v.publishedMatches
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

// Evidence, explicit paths, report-only roots and preserving cache rules cannot
// be waived. Only the individual name-pattern match reaches approve, and then,
// when policy allows it, the published tracked-file check.
func (v *sourceApprovalVerifier) checkNames(parent *os.File, name, relative string, stat unix.Stat_t, indexed worktreeIndexEntry) error {
	if v.policy == nil {
		return nil
	}
	for _, pattern := range v.policy.Classification.EvidenceNames {
		if matched, err := filepath.Match(pattern, name); err != nil || matched {
			return &worktreePolicyRefusal{fmt.Sprintf("worktree descendant %q matches protected evidence name %q", relative, pattern)}
		}
	}
	published := false
	for _, pattern := range v.policy.Protect.NamePatterns {
		if matched, err := filepath.Match(pattern, name); err != nil || matched {
			if err != nil {
				return protectedWorktreeName(relative, pattern)
			}
			err := v.approve(parent, name, relative, pattern, stat, indexed)
			if err == nil {
				continue
			}
			var refusal *worktreePolicyRefusal
			if !errors.As(err, &refusal) {
				return err
			}
			// One file proof covers every pattern its name matches.
			if !published {
				if published, err = v.published(parent, name, relative, stat, indexed); err != nil {
					return err
				}
				if !published {
					return refusal
				}
			}
			v.recordPublished(relative, pattern)
		}
	}
	return nil
}
