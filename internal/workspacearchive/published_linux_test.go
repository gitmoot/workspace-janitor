//go:build linux

package workspacearchive

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/config"
)

// publishedScope is the policy scope for f with protect.name_patterns
// "*token*" and, when setting is not empty, protect.published_name_matches.
// The policy is decoded from its public shape.
func publishedScope(t *testing.T, f *fixture, setting string) Scope {
	t.Helper()
	protect := map[string]any{"name_patterns": []string{"*token*"}}
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
	scope := PolicyScope(policy, f.rule)
	scope.ProcRoot = f.scope.ProcRoot
	return scope
}

type publishedReport struct {
	Matches []string            `json:"published_name_matches"`
	Secrets []map[string]string `json:"published_secrets"`
}

// inspectPublished inspects f and decodes what the inspection reports, also
// alongside a refusal.
func inspectPublished(t *testing.T, f *fixture, scope Scope) (publishedReport, error) {
	t.Helper()
	inspection, err := Inspect(context.Background(), f.rule, scope)
	data, merr := json.Marshal(inspection)
	if merr != nil {
		t.Fatal(merr)
	}
	var reported publishedReport
	if merr := json.Unmarshal(data, &reported); merr != nil {
		t.Fatal(merr)
	}
	return reported, err
}

// publishedFixture is f.source as a repository whose published HEAD tracks
// api-token.txt and a tokens/ directory, all matching "*token*".
func publishedFixture(t *testing.T, f *fixture) {
	t.Helper()
	remote := filepath.Join(f.home, "remote.git")
	gitFixture(t, f.home, "init", "-q", "--bare", remote)
	if err := os.MkdirAll(filepath.Join(f.source, "tokens", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitFixture(t, f.source, "init", "-q")
	write(t, filepath.Join(f.source, "api-token.txt"), []byte("synthetic published fixture\n"), 0o600)
	write(t, filepath.Join(f.source, "tokens", "README.md"), []byte("published directory\n"), 0o600)
	write(t, filepath.Join(f.source, "tokens", "nested", "list.txt"), []byte("published nested file\n"), 0o600)
	gitFixture(t, f.source, "add", "api-token.txt", "tokens")
	gitFixture(t, f.source, "commit", "-q", "-m", "published")
	gitFixture(t, f.source, "remote", "add", "origin", remote)
	gitFixture(t, f.source, "push", "-q", "origin", "HEAD")
}

// The archive screen, unlike the collector, sees no Git status: it resolves a
// secret-like file or directory only when every file involved is tracked with
// its bytes the index blob at a published HEAD, and only when policy allows
// it. Each refusal case starts from a tree the setting resolves.
func TestSecretScreenResolvesOnlyPublishedTrackedFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is unavailable")
	}
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T, f *fixture)
		setting string
		refused string
	}{
		{name: "published", setting: "allow"},
		{name: "published_default_refuses", refused: "api-token.txt"},
		{name: "published_refuse_refuses", setting: "refuse", refused: "tokens"},
		{name: "untracked_env", setting: "allow", refused: ".env", setup: func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.source, ".env"), []byte("FIXTURE=untracked\n"), 0o600)
		}},
		{name: "unpushed", setting: "allow", refused: "local-token.txt", setup: func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.source, "local-token.txt"), []byte("local only\n"), 0o600)
			gitFixture(t, f.source, "add", "local-token.txt")
			gitFixture(t, f.source, "commit", "-q", "-m", "local only")
		}},
		{name: "modified", setting: "allow", refused: "api-token.txt", setup: func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.source, "api-token.txt"), []byte("locally edited\n"), 0o600)
		}},
		{name: "hard_linked", setting: "allow", refused: "api-token.txt", setup: func(t *testing.T, f *fixture) {
			if err := os.Link(filepath.Join(f.source, "api-token.txt"), filepath.Join(f.home, "token-link")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "directory_untracked_file", setting: "allow", refused: "tokens", setup: func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.source, "tokens", "nested", "new.txt"), []byte("untracked\n"), 0o600)
		}},
		{name: "directory_modified_file", setting: "allow", refused: "tokens", setup: func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.source, "tokens", "nested", "list.txt"), []byte("locally edited\n"), 0o600)
		}},
		{name: "directory_symlink", setting: "allow", refused: "tokens", setup: func(t *testing.T, f *fixture) {
			if err := os.Symlink("README.md", filepath.Join(f.source, "tokens", "link")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			publishedFixture(t, f)
			scope := publishedScope(t, f, tc.setting)
			if tc.setup != nil {
				if _, err := inspectPublished(t, f, scope); err != nil {
					t.Fatalf("Inspect refused the published tree before %s: %v", tc.name, err)
				}
				tc.setup(t, f)
			}
			reported, err := inspectPublished(t, f, scope)
			if tc.refused != "" {
				if err == nil || !strings.Contains(err.Error(), "secret-like") || !strings.Contains(err.Error(), tc.refused) {
					t.Fatalf("Inspect = %v, want a secret-like refusal naming %s", err, tc.refused)
				}
				return
			}
			if err != nil {
				t.Fatalf("Inspect refused published tracked content: %v", err)
			}
			for _, want := range []string{`published tracked file "api-token.txt"`, `published tracked directory "tokens"`} {
				if !slices.ContainsFunc(reported.Matches, func(match string) bool { return strings.Contains(match, want) }) {
					t.Fatalf("%s not reported: %+v", want, reported.Matches)
				}
			}
		})
	}
}

// Built-in secret names keep the tree local even when tracked and pushed,
// and the inspection reports each with its repository, path and HEAD.
func TestSecretScreenReportsPublishedSecrets(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is unavailable")
	}
	f := newFixture(t)
	publishedFixture(t, f)
	scope := publishedScope(t, f, "allow")
	if _, err := inspectPublished(t, f, scope); err != nil {
		t.Fatalf("Inspect refused the published tree: %v", err)
	}
	write(t, filepath.Join(f.source, ".env"), []byte("FIXTURE=published\n"), 0o600)
	write(t, filepath.Join(f.source, "server.pem"), []byte("synthetic published fixture\n"), 0o600)
	gitFixture(t, f.source, "add", ".env", "server.pem")
	gitFixture(t, f.source, "commit", "-q", "-m", "publish secrets")
	gitFixture(t, f.source, "push", "-q", "origin", "HEAD")
	head := gitFixture(t, f.source, "rev-parse", "HEAD")
	remote := gitFixture(t, f.source, "config", "--get", "remote.origin.url")
	reported, err := inspectPublished(t, f, scope)
	if err == nil || !strings.Contains(err.Error(), ".env") || !strings.Contains(err.Error(), "server.pem") {
		t.Fatalf("Inspect = %v, want a refusal naming .env and server.pem", err)
	}
	want := map[string]bool{".env": true, "server.pem": true}
	for _, secret := range reported.Secrets {
		if secret["repository"] == remote && secret["head"] == head {
			delete(want, secret["path"])
		}
	}
	if len(want) != 0 {
		t.Fatalf("published secrets %v not reported: %+v", want, reported.Secrets)
	}
}

// Replace refs and grafts must not make an unpublished blob look published.
// Each case starts from a tree the setting resolves, then checks out an
// unpublished commit U adding private-token.txt behind a published-looking
// HEAD: HEAD reset to the published commit P with U's index and files left
// in place and P replaced by U (the review's reproduction), or HEAD at U with
// a graft making U a parent of the published remote-tracking commit.
func TestSecretScreenIgnoresReplaceRefsAndGrafts(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is unavailable")
	}
	for _, scenario := range []string{"replace", "graft"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			publishedFixture(t, f)
			scope := publishedScope(t, f, "allow")
			if _, err := inspectPublished(t, f, scope); err != nil {
				t.Fatalf("Inspect refused the published tree: %v", err)
			}
			published := gitFixture(t, f.source, "rev-parse", "HEAD")
			write(t, filepath.Join(f.source, "private-token.txt"), []byte("unpublished private fixture\n"), 0o600)
			gitFixture(t, f.source, "add", "private-token.txt")
			gitFixture(t, f.source, "commit", "-q", "-m", "unpublished")
			unpublished := gitFixture(t, f.source, "rev-parse", "HEAD")
			switch scenario {
			case "replace":
				gitFixture(t, f.source, "reset", "-q", "--soft", published)
				gitFixture(t, f.source, "replace", published, unpublished)
			case "graft":
				graft := published + " " + unpublished + "\n"
				write(t, filepath.Join(f.source, ".git", "info", "grafts"), []byte(graft), 0o600)
			}
			_, err := inspectPublished(t, f, scope)
			if err == nil || !strings.Contains(err.Error(), "private-token.txt") {
				t.Fatalf("Inspect = %v, want the unpublished private-token.txt refused", err)
			}
		})
	}
}
