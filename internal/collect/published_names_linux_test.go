//go:build linux

package collect

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

// publishedNamesPolicy decodes the public policy shape, so these tests also
// build against code that predates protect.published_name_matches.
func publishedNamesPolicy(t *testing.T, setting string) *config.Policy {
	t.Helper()
	protect := map[string]any{"name_patterns": []string{"*token*", ".env"}}
	if setting != "" {
		protect["published_name_matches"] = setting
	}
	data, err := json.Marshal(map[string]any{"protect": protect})
	if err != nil {
		t.Fatal(err)
	}
	var policy config.Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatal(err)
	}
	return &policy
}

// publishedNamesRepo is a pushed clone whose published HEAD tracks
// api-token.txt and .env, both matching protected names.
func publishedNamesRepo(t *testing.T, home, root string) string {
	t.Helper()
	repo := pushedRepo(t, home, root, "app")
	mustWrite(t, filepath.Join(repo, "api-token.txt"), "synthetic published fixture, not a credential\n")
	mustWrite(t, filepath.Join(repo, ".env"), "FIXTURE=published\n")
	mustWrite(t, filepath.Join(repo, ".gitignore"), "private/\n")
	git(t, home, repo, "add", "api-token.txt", ".env", ".gitignore")
	git(t, home, repo, "commit", "-m", "track protected names")
	git(t, home, repo, "push", "origin", "main")
	return repo
}

func collectPublishedNames(t *testing.T, root string, policy *config.Policy, repo string) core.Entry {
	t.Helper()
	opts := gitOptions(root)
	opts.WorktreePolicy = policy
	return entryFor(t, run(t, opts), repo)
}

func requireNameRefusal(t *testing.T, entry core.Entry, name string) {
	t.Helper()
	if entry.Git == nil || entry.Git.ContentsKnown || !hasProtection(entry, core.ProtectPolicyProtected) ||
		!strings.Contains(entry.Git.ContentsProtection, "matches protected name") || !strings.Contains(entry.Git.ContentsProtection, name) {
		t.Fatalf("%s did not keep the worktree under a protected-name refusal: git=%+v protections=%+v", name, entry.Git, entry.Protections)
	}
}

func requirePublishedResolved(t *testing.T, entry core.Entry) {
	t.Helper()
	if entry.Git == nil || !entry.Git.ContentsKnown || entry.Git.ContentsProtection != "" || hasProtection(entry, core.ProtectPolicyProtected) {
		t.Fatalf("published tracked names still refuse the worktree: git=%+v protections=%+v", entry.Git, entry.Protections)
	}
}

// A tracked, pushed file matching a protected name no longer refuses the
// worktree under protect.published_name_matches: allow, and is recorded as
// evidence. Without the owner's setting the same names still refuse.
func TestPublishedTrackedNameMatchResolvesWorktreeProof(t *testing.T) {
	requireGit(t)
	home, root := t.TempDir(), t.TempDir()
	repo := publishedNamesRepo(t, home, root)
	entry := collectPublishedNames(t, root, publishedNamesPolicy(t, "allow"), repo)
	requirePublishedResolved(t, entry)
	recorded := map[string]bool{}
	for _, evidence := range entry.Evidence {
		if evidence.Signal == "worktree_published_name_match" {
			for _, name := range []string{"api-token.txt", ".env"} {
				recorded[name] = recorded[name] || strings.Contains(evidence.Detail, `"`+name+`"`)
			}
		}
	}
	if !recorded["api-token.txt"] || !recorded[".env"] {
		t.Fatalf("resolved matches were not recorded as evidence: %+v", entry.Evidence)
	}
	for _, setting := range []string{"", "refuse"} {
		// Either tracked name may be met first; both are refused.
		requireNameRefusal(t, collectPublishedNames(t, root, publishedNamesPolicy(t, setting), repo), "")
	}
}

// Only the published tracked file is resolved. Each case starts from a
// checkout the setting resolves, then adds an ignored or untracked .env, a
// tracked file committed only locally, or a local edit: each keeps the
// worktree.
func TestPublishedNameMatchesKeepUnpublishedRefusals(t *testing.T) {
	requireGit(t)
	allow := func(t *testing.T) *config.Policy { return publishedNamesPolicy(t, "allow") }
	published := func(t *testing.T) (home, root, repo string) {
		t.Helper()
		home, root = t.TempDir(), t.TempDir()
		repo = publishedNamesRepo(t, home, root)
		requirePublishedResolved(t, collectPublishedNames(t, root, allow(t), repo))
		return home, root, repo
	}
	t.Run("ignored_env", func(t *testing.T) {
		_, root, repo := published(t)
		mustWrite(t, filepath.Join(repo, "private", ".env"), "FIXTURE=ignored\n")
		requireNameRefusal(t, collectPublishedNames(t, root, allow(t), repo), "private/.env")
	})
	t.Run("untracked_env", func(t *testing.T) {
		_, root, repo := published(t)
		mustWrite(t, filepath.Join(repo, "config", ".env"), "FIXTURE=untracked\n")
		entry := collectPublishedNames(t, root, allow(t), repo)
		if entry.Git == nil || entry.Git.ContentsKnown || !hasProtection(entry, core.ProtectDirtyRepository) {
			t.Fatalf("untracked .env did not keep the worktree: git=%+v protections=%+v", entry.Git, entry.Protections)
		}
	})
	t.Run("tracked_unpushed", func(t *testing.T) {
		home, root, repo := published(t)
		mustWrite(t, filepath.Join(repo, "local-token.txt"), "synthetic local-only fixture\n")
		git(t, home, repo, "add", "local-token.txt")
		git(t, home, repo, "commit", "-m", "local only")
		requireNameRefusal(t, collectPublishedNames(t, root, allow(t), repo), "")
	})
	t.Run("tracked_modified", func(t *testing.T) {
		_, root, repo := published(t)
		mustWrite(t, filepath.Join(repo, "api-token.txt"), "locally edited fixture\n")
		entry := collectPublishedNames(t, root, allow(t), repo)
		if entry.Git == nil || entry.Git.ContentsKnown || !hasProtection(entry, core.ProtectDirtyRepository) {
			t.Fatalf("modified tracked name did not keep the worktree: git=%+v protections=%+v", entry.Git, entry.Protections)
		}
	})
	// Git status trusts assume-unchanged; the proof hashes the bytes itself.
	t.Run("tracked_modified_unreported", func(t *testing.T) {
		home, root, repo := published(t)
		git(t, home, repo, "update-index", "--assume-unchanged", "api-token.txt")
		mustWrite(t, filepath.Join(repo, "api-token.txt"), "locally edited, hidden from status\n")
		requireNameRefusal(t, collectPublishedNames(t, root, allow(t), repo), "api-token.txt")
	})
}
