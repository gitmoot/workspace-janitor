//go:build linux

package collect

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
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
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return refusal
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || !sameApprovedSource(stat, opened) {
		return refusal
	}
	contentHash := sha256.New()
	var blobHash hash.Hash
	switch len(indexed.blob) {
	case 40:
		// SHA-1 here verifies Git's object format, not the content approval.
		blobHash = sha1.New()
	case 64:
		blobHash = sha256.New()
	default:
		return refusal
	}
	fmt.Fprintf(blobHash, "blob %d\x00", stat.Size)
	writer := io.MultiWriter(contentHash, blobHash)
	var buffer [32 << 10]byte
	remaining := stat.Size
	for remaining > 0 {
		if err := v.ctx.Err(); err != nil {
			return err
		}
		chunk := int64(len(buffer))
		if remaining < chunk {
			chunk = remaining
		}
		n, err := io.ReadFull(file, buffer[:int(chunk)])
		if err != nil {
			return refusal
		}
		_, _ = writer.Write(buffer[:n])
		remaining -= int64(n)
	}
	var after, named unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !sameApprovedSource(opened, after) {
		return refusal
	}
	if err := unix.Fstatat(int(parent.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameApprovedSource(after, named) {
		return refusal
	}
	if hex.EncodeToString(contentHash.Sum(nil)) != approval.SHA256 || hex.EncodeToString(blobHash.Sum(nil)) != approval.Blob {
		return refusal
	}
	v.used = true
	return nil
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
// be waived. Only the individual name-pattern match reaches approve.
func (v *sourceApprovalVerifier) checkNames(parent *os.File, name, relative string, stat unix.Stat_t, indexed worktreeIndexEntry) error {
	if v.policy == nil {
		return nil
	}
	for _, pattern := range v.policy.Classification.EvidenceNames {
		if matched, err := filepath.Match(pattern, name); err != nil || matched {
			return &worktreePolicyRefusal{fmt.Sprintf("worktree descendant %q matches protected evidence name %q", relative, pattern)}
		}
	}
	for _, pattern := range v.policy.Protect.NamePatterns {
		if matched, err := filepath.Match(pattern, name); err != nil || matched {
			if err != nil {
				return protectedWorktreeName(relative, pattern)
			}
			if err := v.approve(parent, name, relative, pattern, stat, indexed); err != nil {
				return err
			}
		}
	}
	return nil
}
