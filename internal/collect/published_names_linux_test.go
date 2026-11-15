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
	protect := map[string]any{"name_patterns": []string{"*token*", ".env", "*.pem"}}
	if setting != "" {
		protect["published_name_matches"] = setting
	}
	data, err := json.Marshal(map[string]any{"protect": protect, "classification": map[string]any{"evidence_names": []string{"evidence*"}}})
	if err != nil {
		t.Fatal(err)
	}
	var policy config.Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatal(err)
	}
	return &policy
}

// publishedNamesRepo is a pushed clone whose published HEAD tracks a file
// and two directories matching protected names: api-token.txt, tokens/
// (with a nested directory) and evidence/ (an evidence name).
func publishedNamesRepo(t *testing.T, home, root string) string {
	t.Helper()
	repo := pushedRepo(t, home, root, "app")
	mustWrite(t, filepath.Join(repo, "api-token.txt"), "synthetic published fixture, not a credential\n")
	mustWrite(t, filepath.Join(repo, "tokens", "README.md"), "published directory\n")
	mustWrite(t, filepath.Join(repo, "tokens", "nested", "list.txt"), "published nested file\n")
	mustWrite(t, filepath.Join(repo, "evidence", "run.json"), "{}\n")
	mustWrite(t, filepath.Join(repo, ".gitignore"), "private/\n*.log\n")
	git(t, home, repo, "add", "api-token.txt", "tokens", "evidence", ".gitignore")
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

func requireNameRefusal(t *testing.T, entry core.Entry, fragment string) {
	t.Helper()
	if entry.Git == nil || entry.Git.ContentsKnown || !hasProtection(entry, core.ProtectPolicyProtected) ||
		!strings.Contains(entry.Git.ContentsProtection, "worktree descendant") || !strings.Contains(entry.Git.ContentsProtection, fragment) {
		t.Fatalf("%s did not keep the worktree under a protected-name refusal: git=%+v protections=%+v", fragment, entry.Git, entry.Protections)
	}
}

func requirePublishedResolved(t *testing.T, entry core.Entry) {
	t.Helper()
	if entry.Git == nil || !entry.Git.ContentsKnown || entry.Git.ContentsProtection != "" || hasProtection(entry, core.ProtectPolicyProtected) {
		t.Fatalf("published tracked names still refuse the worktree: git=%+v protections=%+v", entry.Git, entry.Protections)
	}
}

func requireDirty(t *testing.T, entry core.Entry) {
	t.Helper()
	if entry.Git == nil || entry.Git.ContentsKnown || !hasProtection(entry, core.ProtectDirtyRepository) {
		t.Fatalf("worktree with uncommitted content was not kept: git=%+v protections=%+v", entry.Git, entry.Protections)
	}
}

// A tracked, pushed file, and a directory holding only tracked, pushed files,
// whose names match protect.name_patterns or classification.evidence_names no
// longer refuse the worktree under protect.published_name_matches: allow, and
// each is recorded as evidence. Without the owner's setting they still refuse.
func TestPublishedTrackedNameMatchResolvesWorktreeProof(t *testing.T) {
	requireGit(t)
	home, root := t.TempDir(), t.TempDir()
	repo := publishedNamesRepo(t, home, root)
	entry := collectPublishedNames(t, root, publishedNamesPolicy(t, "allow"), repo)
	requirePublishedResolved(t, entry)
	want := map[string]string{"api-token.txt": "file", "tokens": "directory", "evidence": "directory"}
	for _, evidence := range entry.Evidence {
		for name, kind := range want {
			if evidence.Signal == "worktree_published_name_match" && strings.Contains(evidence.Detail, kind+` "`+name+`"`) {
				delete(want, name)
			}
		}
	}
	if len(want) != 0 {
		t.Fatalf("resolved matches %v were not recorded as evidence: %+v", want, entry.Evidence)
	}
	for _, setting := range []string{"", "refuse"} {
		// Any of the tracked names may be met first; all are refused.
		requireNameRefusal(t, collectPublishedNames(t, root, publishedNamesPolicy(t, setting), repo), "")
	}
}

// Only published tracked content is resolved. Each case starts from a
// checkout the setting resolves, then adds an ignored or untracked .env, a
// tracked file committed only locally, a local edit, or untracked or edited
// content inside a matching directory: each keeps the worktree.
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
		requireDirty(t, collectPublishedNames(t, root, allow(t), repo))
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
		requireDirty(t, collectPublishedNames(t, root, allow(t), repo))
	})
	// Git status trusts assume-unchanged; the proof hashes the bytes itself.
	t.Run("tracked_modified_unreported", func(t *testing.T) {
		home, root, repo := published(t)
		git(t, home, repo, "update-index", "--assume-unchanged", "api-token.txt")
		mustWrite(t, filepath.Join(repo, "api-token.txt"), "locally edited, hidden from status\n")
		requireNameRefusal(t, collectPublishedNames(t, root, allow(t), repo), "api-token.txt")
	})
	t.Run("directory_untracked_file", func(t *testing.T) {
		_, root, repo := published(t)
		mustWrite(t, filepath.Join(repo, "tokens", "nested", "new.txt"), "untracked\n")
		requireDirty(t, collectPublishedNames(t, root, allow(t), repo))
	})
	t.Run("directory_ignored_file", func(t *testing.T) {
		_, root, repo := published(t)
		mustWrite(t, filepath.Join(repo, "tokens", "nested", "run.log"), "ignored\n")
		requireNameRefusal(t, collectPublishedNames(t, root, allow(t), repo), `"tokens"`)
	})
	t.Run("directory_modified_file", func(t *testing.T) {
		_, root, repo := published(t)
		mustWrite(t, filepath.Join(repo, "tokens", "nested", "list.txt"), "locally edited\n")
		requireDirty(t, collectPublishedNames(t, root, allow(t), repo))
	})
	t.Run("directory_modified_file_unreported", func(t *testing.T) {
		home, root, repo := published(t)
		git(t, home, repo, "update-index", "--assume-unchanged", "evidence/run.json")
		mustWrite(t, filepath.Join(repo, "evidence", "run.json"), `{"edited":true}`+"\n")
		requireNameRefusal(t, collectPublishedNames(t, root, allow(t), repo), `"evidence"`)
	})
}

// publishedSecretsOf decodes the Git state's published_secrets by its JSON
// name, so this test also builds against code without the field.
func publishedSecretsOf(t *testing.T, state *core.GitState) []map[string]string {
	t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Secrets []map[string]string `json:"published_secrets"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded.Secrets
}

// Built-in secret names keep refusing even when tracked and pushed, and each
// one is reported with its repository, path and HEAD: a leak to rotate.
func TestPublishedSecretsStillRefuseAndAreReported(t *testing.T) {
	requireGit(t)
	home, root := t.TempDir(), t.TempDir()
	repo := publishedNamesRepo(t, home, root)
	mustWrite(t, filepath.Join(repo, ".env"), "FIXTURE=published\n")
	mustWrite(t, filepath.Join(repo, "certs", "server.pem"), "synthetic published fixture\n")
	git(t, home, repo, "add", ".env", "certs/server.pem")
	git(t, home, repo, "commit", "-m", "publish secrets")
	git(t, home, repo, "push", "origin", "main")
	head := git(t, home, repo, "rev-parse", "HEAD")
	remote := git(t, home, repo, "config", "--get", "remote.origin.url")
	entry := collectPublishedNames(t, root, publishedNamesPolicy(t, "allow"), repo)
	requireNameRefusal(t, entry, "secret published in Git")
	want := map[string]bool{".env": true, "certs/server.pem": true}
	for _, secret := range publishedSecretsOf(t, entry.Git) {
		if secret["repository"] == remote && secret["head"] == head {
			delete(want, secret["path"])
		}
	}
	if len(want) != 0 {
		t.Fatalf("published secrets %v not reported: %+v", want, publishedSecretsOf(t, entry.Git))
	}
}

// Replace refs and grafts must not make unpublished commits look published:
// the review's reproduction (HEAD reset to the published commit with an
// unpublished commit's index and files, and the published commit replaced by
// it), and a graft making the unpublished HEAD a parent of the published one.
func TestPublicationIgnoresReplaceRefsAndGrafts(t *testing.T) {
	requireGit(t)
	for _, scenario := range []string{"replace", "graft"} {
		t.Run(scenario, func(t *testing.T) {
			home, root := t.TempDir(), t.TempDir()
			repo := publishedNamesRepo(t, home, root)
			requirePublishedResolved(t, collectPublishedNames(t, root, publishedNamesPolicy(t, "allow"), repo))
			published := git(t, home, repo, "rev-parse", "HEAD")
			mustWrite(t, filepath.Join(repo, "private-token.txt"), "unpublished private fixture\n")
			git(t, home, repo, "add", "private-token.txt")
			git(t, home, repo, "commit", "-m", "unpublished")
			unpublished := git(t, home, repo, "rev-parse", "HEAD")
			switch scenario {
			case "replace":
				git(t, home, repo, "reset", "--soft", published)
				git(t, home, repo, "replace", published, unpublished)
				entry := collectPublishedNames(t, root, publishedNamesPolicy(t, "allow"), repo)
				// The index now differs from the real HEAD tree.
				requireDirty(t, entry)
			case "graft":
				mustWrite(t, filepath.Join(repo, ".git", "info", "grafts"), published+" "+unpublished+"\n")
				entry := collectPublishedNames(t, root, publishedNamesPolicy(t, "allow"), repo)
				if entry.Git == nil || entry.Git.UnpublishedCommits == 0 || !hasProtection(entry, core.ProtectUnpublishedCommits) {
					t.Fatalf("a graft made an unpublished commit look published: git=%+v protections=%+v", entry.Git, entry.Protections)
				}
			}
		})
	}
}
