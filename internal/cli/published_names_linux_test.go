//go:build linux

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// commitFiles writes files into the checkout at dir and commits them; push
// also publishes the commit to the fixture remote, on a branch named after
// dir so that checkouts cloned later do not inherit the files.
func (x *categoryFixture) commitFiles(t *testing.T, dir string, push bool, files map[string]string) {
	t.Helper()
	names := make([]string, 0, len(files))
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	slices.Sort(names)
	x.git(t, dir, append([]string{"add", "--"}, names...)...)
	x.git(t, dir, "commit", "-qm", "protected names")
	if push {
		x.git(t, dir, "push", "-q", "origin", "HEAD:refs/heads/"+filepath.Base(dir))
	}
}

const publishedNamesProtect = "  name_patterns: [\"*token*\"]\n"

// publishedNameMatches previews the category run and returns each item's
// reported published_name_matches, decoded from the JSON report.
func (x *categoryFixture) publishedNameMatches(t *testing.T) map[string][]string {
	t.Helper()
	out, stderr, code := x.runAgents(t, "--format", "json", "archive", "--categories")
	if code != ExitOK {
		t.Fatalf("archive --categories: exit=%d stderr=%s stdout=%s", code, stderr, out)
	}
	var doc struct {
		Data struct {
			Items []struct {
				Path    string   `json:"path"`
				Matches []string `json:"published_name_matches"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	matches := map[string][]string{}
	for _, item := range doc.Data.Items {
		matches[item.Path] = item.Matches
	}
	return matches
}

func publishedNameMatched(matches []string, name string) bool {
	return slices.ContainsFunc(matches, func(match string) bool {
		return strings.Contains(match, "published tracked file") && strings.Contains(match, `"`+name+`"`)
	})
}

// Under protect.published_name_matches: allow, a tracked, pushed file matching
// a protected name (policy or built-in) no longer refuses a pushed clone or a
// merged worktree, and the match is reported. Untracked, ignored, unpushed or
// modified matches still refuse, and without the setting nothing changes.
func TestCategoryArchivePublishedTrackedNameMatches(t *testing.T) {
	x := newCategoryFixture(t)
	x.protect = publishedNamesProtect + "  published_name_matches: allow\n"
	x.write(t)
	clone := x.clone(t, "published-clone")
	x.commitFiles(t, clone, true, map[string]string{".env": "FIXTURE=published\n", "api-token.txt": "synthetic published fixture\n"})
	linked := x.linked(t, "published-linked")
	x.commitFiles(t, linked, true, map[string]string{".env": "FIXTURE=published\n"})
	ignored := x.clone(t, "ignored-env-clone")
	x.commitFiles(t, ignored, true, map[string]string{".gitignore": ".env\n"})
	untracked := x.clone(t, "untracked-env-clone")
	unpushed := x.clone(t, "unpushed-token-clone")
	x.commitFiles(t, unpushed, false, map[string]string{"api-token.txt": "local only\n"})
	modified := x.clone(t, "modified-token-clone")
	x.commitFiles(t, modified, true, map[string]string{"api-token.txt": "synthetic published fixture\n"})
	for path, data := range map[string]string{
		filepath.Join(ignored, ".env"):           "FIXTURE=ignored\n",
		filepath.Join(untracked, ".env"):         "FIXTURE=untracked\n",
		filepath.Join(modified, "api-token.txt"): "locally edited\n",
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{clone, linked, ignored, untracked, unpushed, modified} {
		backdate(t, path, categoryIdleAge)
	}

	report := x.categories(t, true)
	matches := x.publishedNameMatches(t)
	for path, names := range map[string][]string{clone: {".env", "api-token.txt"}, linked: {".env"}} {
		item := categoryItem(t, report, path)
		if item.Status != categoryWouldArchive {
			t.Errorf("%s with published tracked protected names was refused: %+v", path, item)
		}
		for _, name := range names {
			if !publishedNameMatched(matches[path], name) {
				t.Errorf("%s: published match on %s not reported: %+v", path, name, matches[path])
			}
		}
	}
	for path, fragment := range map[string]string{
		ignored:   ".env",
		untracked: "uncommitted",
		unpushed:  "api-token.txt",
		modified:  "uncommitted",
	} {
		item := categoryItem(t, report, path)
		if reasons := strings.Join(item.Reasons, "\n"); item.Status != categoryRefused || !strings.Contains(reasons, fragment) {
			t.Errorf("%s not refused for %q: %+v", path, fragment, item)
		}
	}

	x.protect = publishedNamesProtect
	x.write(t)
	report = x.categories(t, true)
	for path, fragment := range map[string]string{clone: "protected name", linked: "protected name"} {
		item := categoryItem(t, report, path)
		if reasons := strings.Join(item.Reasons, "\n"); item.Status != categoryRefused || !strings.Contains(reasons, fragment) {
			t.Errorf("default policy: %s not refused for %q: %+v", path, fragment, item)
		}
	}
}

// The allowance holds through the whole cycle: the archived clone is bound,
// quarantined and expired with its published tracked .env, then restored.
func TestCategoryArchivePublishedTrackedNameExpires(t *testing.T) {
	x := newCategoryFixture(t)
	x.protect = publishedNamesProtect + "  published_name_matches: allow\n"
	x.write(t)
	clone := x.clone(t, "published-clone")
	x.commitFiles(t, clone, true, map[string]string{".env": "FIXTURE=published\n"})
	backdate(t, clone, categoryIdleAge)

	item := categoryItem(t, x.categories(t, false), clone)
	if item.Status != categoryArchived || item.Binding == nil {
		t.Fatalf("published clone not archived: %+v", item)
	}
	receipt := x.quarantineAt(t, clone)
	if receipt.Quarantined == nil || receipt.Quarantined.WorkspaceArchive == nil {
		t.Fatalf("quarantine snapshot lacks the category archive binding: %+v", receipt.Quarantined)
	}
	if _, _, code := x.run(t, "apply", "--expire", "--cleanup", receipt.CleanupID, "--dry-run=false", "--confirm"); code != ExitOK {
		t.Fatalf("expiry of the archived published clone failed: exit %d", code)
	}
	if _, err := os.Lstat(receipt.Destination); !os.IsNotExist(err) {
		t.Fatalf("expiry kept the quarantined clone: %v", err)
	}
	x.data(t, "archive", "--restore-category-item", clone, "--restore-to", clone, "--dry-run=false", "--confirm")
	if data, err := os.ReadFile(filepath.Join(clone, ".env")); err != nil || string(data) != "FIXTURE=published\n" {
		t.Fatalf("restored clone lost its tracked .env: %q %v", data, err)
	}
}
