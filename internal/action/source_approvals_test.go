//go:build linux

package action

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

func reviewedSourceFixture(t *testing.T, linked bool) (*Engine, string, *time.Time, []byte) {
	t.Helper()
	e, source, clock := publishedContentsFixture(t, linked)
	payload := []byte("package example\n\n// Credentials describes a credential provider; it contains no credential values.\ntype Credentials interface { Available() bool }\n")
	if err := os.WriteFile(filepath.Join(source, "credentials.go"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	fixtureGit(t, source, source, "add", "credentials.go")
	fixtureGit(t, source, source, "commit", "-m", "published ordinary source")
	fixtureGit(t, source, source, "push", "origin", "HEAD")
	digest := sha256.Sum256(payload)
	approval := map[string]any{
		"repository": source, "remote": fixtureGit(t, source, source, "config", "--get", "remote.origin.url"),
		"path": "credentials.go", "commit": fixtureGit(t, source, source, "rev-parse", "HEAD"),
		"blob": fixtureGit(t, source, source, "rev-parse", "HEAD:credentials.go"), "sha256": hex.EncodeToString(digest[:]),
		"name_pattern": "*credentials*", "reviewer": "authorized-source-reviewer", "record": "review://fixture/ordinary-source-1",
		"generation": "reviewed-generation-1", "reviewed_at": clock.Add(-time.Hour), "expires_at": clock.Add(48 * time.Hour),
	}
	e.Collect.WorktreePolicy = sourcePolicyFromDocument(t, map[string]any{
		"protect":               map[string]any{"name_patterns": []string{"*credentials*", ".env", ".env.*", "*.key"}},
		"classification":        map[string]any{"evidence_names": []string{"evidence*"}},
		"source_name_approvals": map[string]any{"generation": approval["generation"], "reviewers": []string{approval["reviewer"].(string)}, "files": []any{approval}},
	})
	e.Collect.Now = e.Now
	return e, source, clock, payload
}

// Decode the public policy shape so these behavior tests also run against the
// old implementation, which ignores this unknown field rather than approving it.
func sourcePolicyFromDocument(t *testing.T, document map[string]any) *config.Policy {
	t.Helper()
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var policy config.Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatal(err)
	}
	return &policy
}

func sourcePolicyDocument(t *testing.T, policy *config.Policy) map[string]any {
	t.Helper()
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func TestReviewedSourceNameQuarantineAndExpiry(t *testing.T) {
	for _, linked := range []bool{false, true} {
		t.Run(map[bool]string{false: "standalone", true: "linked"}[linked], func(t *testing.T) {
			e, source, clock, payload := reviewedSourceFixture(t, linked)
			item := prepareFixture(t, e, source, core.RetentionNone)
			var err error
			item, err = e.Quarantine(context.Background(), item)
			if err != nil {
				t.Fatal(err)
			}
			if bytes, err := os.ReadFile(filepath.Join(item.Destination, "credentials.go")); err != nil || string(bytes) != string(payload) {
				t.Fatalf("quarantine did not preserve reviewed source: %v", err)
			}
			*clock = clock.Add(time.Hour)
			item, err = e.Delete(context.Background(), item)
			if err != nil || item.State != core.CleanupDeleted {
				t.Fatalf("eligible reviewed source did not expire: state=%s error=%v", item.State, err)
			}
			if _, err := os.Lstat(item.Destination); !os.IsNotExist(err) {
				t.Fatalf("expired worktree remains: %v", err)
			}
		})
	}
}

func TestReviewedSourceNameMissingApprovalIsPolicyRefusal(t *testing.T) {
	e, source, _, payload := reviewedSourceFixture(t, false)
	document := sourcePolicyDocument(t, e.Collect.WorktreePolicy)
	delete(document, "source_name_approvals")
	e.Collect.WorktreePolicy = sourcePolicyFromDocument(t, document)
	entry, err := e.recollect(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Git == nil || entry.Git.Degraded || entry.Git.ContentsKnown {
		t.Fatalf("protected source was not reported as a known policy refusal: %+v", entry.Git)
	}
	protected := false
	for _, protection := range entry.Protections {
		protected = protected || protection.Kind == core.ProtectPolicyProtected
		if protection.Kind == core.ProtectBrokenGitMetadata || protection.Kind == core.ProtectCollectorFailure {
			t.Fatalf("known name protection misreported as collection failure: %+v", protection)
		}
	}
	if !protected {
		t.Fatal("missing approval was not reported as policy protection")
	}
	item := prepareFixture(t, e, source, core.RetentionNone)
	if _, err := e.Quarantine(context.Background(), item); err == nil {
		t.Fatal("missing approval permitted quarantine")
	}
	if bytes, err := os.ReadFile(filepath.Join(source, "credentials.go")); err != nil || string(bytes) != string(payload) {
		t.Fatalf("refused source was not preserved: %v", err)
	}
}

func TestReviewedSourceNameExpiryRechecksApprovalAndRestores(t *testing.T) {
	for _, change := range []string{"revoke", "expire", "generation", "record", "reviewer", "repository", "remote", "bytes", "symlink", "explicit_protection"} {
		t.Run(change, func(t *testing.T) {
			e, source, clock, payload := reviewedSourceFixture(t, false)
			item := prepareFixture(t, e, source, core.RetentionNone)
			var err error
			item, err = e.Quarantine(context.Background(), item)
			if err != nil {
				t.Fatal(err)
			}
			document := sourcePolicyDocument(t, e.Collect.WorktreePolicy)
			policy := document["source_name_approvals"].(map[string]any)
			approval := policy["files"].([]any)[0].(map[string]any)
			path := filepath.Join(item.Destination, "credentials.go")
			switch change {
			case "revoke":
				delete(document, "source_name_approvals")
			case "expire":
				expiry, err := time.Parse(time.RFC3339Nano, approval["expires_at"].(string))
				if err != nil {
					t.Fatal(err)
				}
				*clock = expiry
			case "generation":
				policy["generation"] = "reviewed-generation-2"
				approval["generation"] = "reviewed-generation-2"
			case "record":
				approval["record"] = "review://fixture/replacement-review"
			case "reviewer":
				policy["reviewers"] = []string{"different-authority"}
			case "repository":
				approval["repository"] = filepath.Join(filepath.Dir(source), "different-checkout")
			case "remote":
				fixtureGit(t, source, item.Destination, "remote", "set-url", "origin", filepath.Join(t.TempDir(), "other.git"))
			case "bytes":
				payload = []byte("package example\nvar changedAfterApproval = true\n")
				if err := os.WriteFile(path, payload, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(".gitignore", path); err != nil {
					t.Fatal(err)
				}
			case "explicit_protection":
				document["protect"].(map[string]any)["paths"] = []string{filepath.Join(source, "credentials.go")}
			}
			e.Collect.WorktreePolicy = sourcePolicyFromDocument(t, document)
			*clock = clock.Add(time.Hour)
			if err := e.ExpiryPreview(context.Background(), item); err == nil {
				t.Fatal("changed approval or protected bytes were allowed to expire")
			}
			if item, err = e.Delete(context.Background(), item); err == nil {
				t.Fatal("changed approval or protected bytes were deleted")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("refused expiry lost source: %v", err)
			}
			item, err = e.Restore(context.Background(), item)
			if err != nil || item.State != core.CleanupRestored {
				t.Fatalf("refused receipt cannot restore: %v", err)
			}
			if change == "symlink" {
				if target, err := os.Readlink(filepath.Join(source, "credentials.go")); err != nil || target != ".gitignore" {
					t.Fatalf("restore did not preserve changed symlink: %q %v", target, err)
				}
			} else if bytes, err := os.ReadFile(filepath.Join(source, "credentials.go")); err != nil || string(bytes) != string(payload) {
				t.Fatalf("restore did not preserve exact source bytes: %v", err)
			}
		})
	}
}

func TestReviewedSourceNameDoesNotWaiveProtectedDescendants(t *testing.T) {
	for _, relative := range []string{".env", ".env.go", "credentials.json", "evidence.go", "live.db"} {
		t.Run(relative, func(t *testing.T) {
			e, source, clock, _ := reviewedSourceFixture(t, false)
			protected := []byte("synthetic protected fixture, not a real credential\n")
			if err := os.WriteFile(filepath.Join(source, relative), protected, 0600); err != nil {
				t.Fatal(err)
			}
			fixtureGit(t, source, source, "add", relative)
			fixtureGit(t, source, source, "commit", "-m", "tracked protected fixture")
			fixtureGit(t, source, source, "push", "origin", "HEAD")
			// Even a caller bypassing config validation cannot turn a record for
			// a secret container/database/evidence path into a source exception.
			document := sourcePolicyDocument(t, e.Collect.WorktreePolicy)
			if policy, ok := document["source_name_approvals"].(map[string]any); ok {
				files := policy["files"].([]any)
				attempt := make(map[string]any)
				for key, value := range files[0].(map[string]any) {
					attempt[key] = value
				}
				attempt["path"] = relative
				attempt["commit"] = fixtureGit(t, source, source, "rev-parse", "HEAD")
				attempt["blob"] = fixtureGit(t, source, source, "rev-parse", "HEAD:"+relative)
				digest := sha256.Sum256(protected)
				attempt["sha256"] = hex.EncodeToString(digest[:])
				attempt["name_pattern"] = relative
				attempt["reviewed_at"] = clock.Add(-time.Hour)
				policy["files"] = append(files, attempt)
			}
			e.Collect.WorktreePolicy = sourcePolicyFromDocument(t, document)
			e.Collect.WorktreePolicy.Protect.NamePatterns = append(e.Collect.WorktreePolicy.Protect.NamePatterns, relative)
			item := prepareFixture(t, e, source, core.RetentionNone)
			if _, err := e.Quarantine(context.Background(), item); err == nil {
				t.Fatal("source approval waived a genuine protected descendant")
			}
			if bytes, err := os.ReadFile(filepath.Join(source, relative)); err != nil || string(bytes) != string(protected) {
				t.Fatalf("protected descendant lost: %v", err)
			}
		})
	}
}
