//go:build linux

package cli

import (
	"encoding/json"
	"os"
	"os/exec"
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
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
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

func (x *categoryFixture) gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
	if err != nil {
		t.Fatalf("git -C %s %v: %v", dir, args, err)
	}
	return strings.TrimSpace(string(out))
}

const publishedNamesProtect = "  name_patterns: [\"*token*\"]\n"

// publishedFiles are tracked content matching "*token*": a file and a
// directory holding only ordinary files.
var publishedFiles = map[string]string{
	"api-token.txt":           "synthetic published fixture\n",
	"tokens/README.md":        "published directory\n",
	"tokens/nested/list.txt":  "published nested file\n",
	"tokens/nested/other.txt": "another published file\n",
}

type publishedItem struct {
	Matches []string            `json:"published_name_matches"`
	Secrets []map[string]string `json:"published_secrets"`
}

// publishedItems previews the category run and decodes each item's
// published_name_matches and published_secrets from the JSON report.
func (x *categoryFixture) publishedItems(t *testing.T) map[string]publishedItem {
	t.Helper()
	out, stderr, code := x.runAgents(t, "--format", "json", "archive", "--categories")
	if code != ExitOK {
		t.Fatalf("archive --categories: exit=%d stderr=%s stdout=%s", code, stderr, out)
	}
	var doc struct {
		Data struct {
			Items []struct {
				Path string `json:"path"`
				publishedItem
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	items := map[string]publishedItem{}
	for _, item := range doc.Data.Items {
		items[item.Path] = item.publishedItem
	}
	return items
}

func publishedNameMatched(matches []string, kind, name string) bool {
	return slices.ContainsFunc(matches, func(match string) bool {
		return strings.Contains(match, "published tracked "+kind+` "`+name+`"`)
	})
}

// Under protect.published_name_matches: allow, a tracked, pushed file and a
// directory of tracked, pushed files matching a protected name no longer
// refuse a pushed clone or a merged worktree, and the matches are reported.
// Untracked, ignored, unpushed or modified matches, also inside a matching
// directory, still refuse, and without the setting nothing changes.
func TestCategoryArchivePublishedTrackedNameMatches(t *testing.T) {
	x := newCategoryFixture(t)
	x.protect = publishedNamesProtect + "  published_name_matches: allow\n"
	x.write(t)
	clone := x.clone(t, "published-clone")
	x.commitFiles(t, clone, true, publishedFiles)
	linked := x.linked(t, "published-linked")
	x.commitFiles(t, linked, true, map[string]string{"tokens/README.md": "published directory\n"})
	ignored := x.clone(t, "ignored-env-clone")
	x.commitFiles(t, ignored, true, map[string]string{".gitignore": ".env\n"})
	untracked := x.clone(t, "untracked-env-clone")
	unpushed := x.clone(t, "unpushed-token-clone")
	x.commitFiles(t, unpushed, false, map[string]string{"api-token.txt": "local only\n"})
	modified := x.clone(t, "modified-token-clone")
	x.commitFiles(t, modified, true, map[string]string{"api-token.txt": "synthetic published fixture\n"})
	dirUntracked := x.clone(t, "dir-untracked-clone")
	x.commitFiles(t, dirUntracked, true, publishedFiles)
	dirModified := x.clone(t, "dir-modified-clone")
	x.commitFiles(t, dirModified, true, publishedFiles)
	for path, data := range map[string]string{
		filepath.Join(ignored, ".env"):                       "FIXTURE=ignored\n",
		filepath.Join(untracked, ".env"):                     "FIXTURE=untracked\n",
		filepath.Join(modified, "api-token.txt"):             "locally edited\n",
		filepath.Join(dirUntracked, "tokens", "new.txt"):     "untracked\n",
		filepath.Join(dirModified, "tokens/nested/list.txt"): "locally edited\n",
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{clone, linked, ignored, untracked, unpushed, modified, dirUntracked, dirModified} {
		backdate(t, path, categoryIdleAge)
	}

	report := x.categories(t, true)
	items := x.publishedItems(t)
	for path, names := range map[string]map[string]string{
		clone:  {"api-token.txt": "file", "tokens": "directory"},
		linked: {"tokens": "directory"},
	} {
		item := categoryItem(t, report, path)
		if item.Status != categoryWouldArchive {
			t.Errorf("%s with published tracked protected names was refused: %+v", path, item)
		}
		for name, kind := range names {
			if !publishedNameMatched(items[path].Matches, kind, name) {
				t.Errorf("%s: published match on %s %s not reported: %+v", path, kind, name, items[path].Matches)
			}
		}
	}
	for path, fragment := range map[string]string{
		ignored:      ".env",
		untracked:    "uncommitted",
		unpushed:     "api-token.txt",
		modified:     "uncommitted",
		dirUntracked: "uncommitted",
		dirModified:  "uncommitted",
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

// A tracked, pushed .env or server.pem still refuses its clone, and each is
// listed in published_secrets with the repository, path and HEAD: a leak to
// rotate and remove from Git, not something to archive quietly.
func TestCategoryArchivePublishedSecretsStillRefused(t *testing.T) {
	x := newCategoryFixture(t)
	x.protect = publishedNamesProtect + "  published_name_matches: allow\n"
	x.write(t)
	clone := x.clone(t, "secrets-clone")
	x.commitFiles(t, clone, true, map[string]string{".env": "FIXTURE=published\n", "certs/server.pem": "synthetic published fixture\n"})
	head := x.gitOutput(t, clone, "rev-parse", "HEAD")
	backdate(t, clone, categoryIdleAge)

	item := categoryItem(t, x.categories(t, true), clone)
	if item.Status != categoryRefused || !strings.Contains(strings.Join(item.Reasons, "\n"), "secret published in Git") {
		t.Fatalf("published secrets did not refuse the clone: %+v", item)
	}
	want := map[string]bool{".env": true, "certs/server.pem": true}
	for _, secret := range x.publishedItems(t)[clone].Secrets {
		if secret["repository"] == "file://"+x.remote && secret["head"] == head {
			delete(want, secret["path"])
		}
	}
	if len(want) != 0 {
		t.Fatalf("published secrets %v not reported: %+v", want, x.publishedItems(t)[clone].Secrets)
	}
}

// The allowance holds through the whole cycle: the archived clone is bound,
// quarantined and expired with its published protected names, then restored.
func TestCategoryArchivePublishedTrackedNameExpires(t *testing.T) {
	x := newCategoryFixture(t)
	x.protect = publishedNamesProtect + "  published_name_matches: allow\n"
	x.write(t)
	clone := x.clone(t, "published-clone")
	x.commitFiles(t, clone, true, publishedFiles)
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
	for name, want := range publishedFiles {
		if data, err := os.ReadFile(filepath.Join(clone, name)); err != nil || string(data) != want {
			t.Fatalf("restored clone lost %s: %q %v", name, data, err)
		}
	}
}
