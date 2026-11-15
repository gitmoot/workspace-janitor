//go:build linux

package workspacearchive

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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

// inspectPublished inspects f and returns the reported published matches.
func inspectPublished(t *testing.T, f *fixture, scope Scope) ([]string, error) {
	t.Helper()
	inspection, err := Inspect(context.Background(), f.rule, scope)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(inspection)
	if err != nil {
		t.Fatal(err)
	}
	var reported struct {
		Matches []string `json:"published_name_matches"`
	}
	if err := json.Unmarshal(data, &reported); err != nil {
		t.Fatal(err)
	}
	return reported.Matches, nil
}

// The archive screen, unlike the collector, sees no Git status: it resolves a
// secret-like name only for a tracked file whose bytes are the index blob at
// a published HEAD, and only when policy allows it. Each refusal case starts
// from a tree the setting resolves.
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
		{name: "published_refuse_refuses", setting: "refuse", refused: "api-token.txt"},
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			remote := filepath.Join(f.home, "remote.git")
			gitFixture(t, f.home, "init", "-q", "--bare", remote)
			if err := os.MkdirAll(f.source, 0o755); err != nil {
				t.Fatal(err)
			}
			gitFixture(t, f.source, "init", "-q")
			write(t, filepath.Join(f.source, "api-token.txt"), []byte("synthetic published fixture\n"), 0o600)
			gitFixture(t, f.source, "add", "api-token.txt")
			gitFixture(t, f.source, "commit", "-q", "-m", "published")
			gitFixture(t, f.source, "remote", "add", "origin", remote)
			gitFixture(t, f.source, "push", "-q", "origin", "HEAD")
			scope := publishedScope(t, f, tc.setting)
			if tc.setup != nil {
				if _, err := inspectPublished(t, f, scope); err != nil {
					t.Fatalf("Inspect refused the published tree before %s: %v", tc.name, err)
				}
				tc.setup(t, f)
			}
			matches, err := inspectPublished(t, f, scope)
			if tc.refused != "" {
				if err == nil || !strings.Contains(err.Error(), "secret-like") || !strings.Contains(err.Error(), tc.refused) {
					t.Fatalf("Inspect = %v, want a secret-like refusal naming %s", err, tc.refused)
				}
				return
			}
			if err != nil {
				t.Fatalf("Inspect refused a published tracked file: %v", err)
			}
			if len(matches) != 1 || !strings.Contains(matches[0], `published tracked file "api-token.txt"`) {
				t.Fatalf("published match not reported: %+v", matches)
			}
		})
	}
}
