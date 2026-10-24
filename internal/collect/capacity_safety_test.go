package collect

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

func TestPublicationIncludesSavedAndHiddenCommits(t *testing.T) {
	requireGit(t)
	for _, ref := range []string{"ORIG_HEAD", "refs/notes/saved", "refs/tags/saved", "refs/replace/saved"} {
		t.Run(ref, func(t *testing.T) {
			home, root := t.TempDir(), t.TempDir()
			repo := newRepo(t, home, filepath.Join(root, "app"))
			base := git(t, home, repo, "rev-parse", "HEAD")
			git(t, home, repo, "update-ref", "refs/remotes/origin/main", base)
			mustWrite(t, filepath.Join(repo, "README.md"), "unique work\n")
			git(t, home, repo, "commit", "-am", "unique")
			tip := git(t, home, repo, "rev-parse", "HEAD")
			git(t, home, repo, "reset", "--hard", base)
			git(t, home, repo, "update-ref", "-d", "ORIG_HEAD")
			git(t, home, repo, "update-ref", ref, tip)
			entry := entryFor(t, run(t, gitOptions(root)), repo)
			if entry.Git == nil || !entry.Git.PublicationKnown || entry.Git.UnpublishedCommits != 1 {
				t.Fatalf("unique commit reachable only by %s was not protected: %+v", ref, entry.Git)
			}
		})
	}
}

func TestPublicationIgnoresReplacementGraph(t *testing.T) {
	requireGit(t)
	home, root := t.TempDir(), t.TempDir()
	repo := newRepo(t, home, filepath.Join(root, "app"))
	base := git(t, home, repo, "rev-parse", "HEAD")
	git(t, home, repo, "update-ref", "refs/remotes/origin/main", base)
	mustWrite(t, filepath.Join(repo, "README.md"), "unique work\n")
	git(t, home, repo, "commit", "-am", "unique")
	tip := git(t, home, repo, "rev-parse", "HEAD")
	// Replacing the remote tip with the local tip makes ordinary rev-list
	// believe the local tip is reachable from the remote.
	git(t, home, repo, "replace", base, tip)
	entry := entryFor(t, run(t, gitOptions(root)), repo)
	if entry.Git == nil || !entry.Git.PublicationKnown || entry.Git.UnpublishedCommits == 0 {
		t.Fatalf("replace ref concealed unpublished work: %+v", entry.Git)
	}
}

func TestParentAccountsForDeinitializedSubmoduleWork(t *testing.T) {
	requireGit(t)
	home, root := t.TempDir(), t.TempDir()
	source := newRepo(t, home, filepath.Join(t.TempDir(), "source"))
	repo := newRepo(t, home, filepath.Join(root, "parent"))
	git(t, home, repo, "-c", "protocol.file.allow=always", "submodule", "add", source, "child")
	git(t, home, repo, "commit", "-am", "submodule")
	git(t, home, repo, "update-ref", "refs/remotes/origin/main", "HEAD")
	child := filepath.Join(repo, "child")
	mustWrite(t, filepath.Join(child, "README.md"), "unique commit\n")
	git(t, home, child, "commit", "-am", "unpublished child")
	mustWrite(t, filepath.Join(child, "README.md"), "unique stash\n")
	git(t, home, child, "stash", "push", "-m", "retained")
	git(t, home, repo, "submodule", "deinit", "-f", "child")
	entry := entryFor(t, run(t, gitOptions(root)), repo)
	if entry.Git == nil || entry.Git.Stashes != 1 || entry.Git.UnpublishedCommits == 0 {
		t.Fatalf("parent lost deinitialized submodule evidence: %+v", entry.Git)
	}
}

func TestReobserveDetectsIndexOnlyActivity(t *testing.T) {
	requireGit(t)
	home, root := t.TempDir(), t.TempDir()
	repo := newRepo(t, home, filepath.Join(root, "app"))
	options := gitOptions(root)
	first := entryFor(t, run(t, options), repo)
	stamp := time.Now().Add(time.Hour)
	if err := os.Chtimes(filepath.Join(repo, ".git", "index"), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	second := entryFor(t, run(t, options), repo)
	if first.Git.Head != second.Git.Head || first.Git.DirtyFiles != second.Git.DirtyFiles {
		t.Fatal("fixture changed Git content")
	}
	if Fingerprint(first) == Fingerprint(second) {
		t.Fatal("apply fingerprint accepted new index-only activity")
	}
}

func TestIncompleteSizeIsNotReportedAsComplete(t *testing.T) {
	root := t.TempDir()
	options := fixtureOptions(root)
	entries := []core.Entry{{Path: filepath.Join(root, "vanished"), Root: root, Kind: core.EntryKindDirectory}}
	report := collectDeepSize(context.Background(), &options, entries, time.Now())
	if report.Status != core.CollectorPartial || !entries[0].SizeIsLowerBound {
		t.Fatalf("incomplete measurement looks complete: %+v %+v", report, entries[0])
	}
}
