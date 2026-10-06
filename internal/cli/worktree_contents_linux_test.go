//go:build linux

package cli

import (
	"database/sql"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCycleWholeWorktreeContentsPolicy(t *testing.T) {
	for _, scenario := range []string{"clean", "tracked_symlink", "approved", "approved_linked", "revoked", "revoked_linked", "unknown", "credential", "evidence", "database", "keep_overlap", "root_keep", "bounded_cache", "report_only", "protected", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			root := filepath.Join(f.home, "workspace")
			source := filepath.Join(root, "checkout")
			proc := filepath.Join(f.home, "proc")
			units := filepath.Join(f.home, "units")
			for _, path := range []string{source, proc, units} {
				if err := os.MkdirAll(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			git := func(args ...string) {
				t.Helper()
				cmd := exec.Command("git", append([]string{"-C", source}, args...)...)
				cmd.Env = append(os.Environ(), "HOME="+f.home, "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=Fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid", "GIT_COMMITTER_NAME=Fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid")
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git %v: %s %v", args, out, err)
				}
			}
			git("init", "-q")
			if err := os.WriteFile(filepath.Join(source, ".gitignore"), []byte("private/\n"), 0600); err != nil {
				t.Fatal(err)
			}
			git("add", ".gitignore")
			if scenario == "tracked_symlink" {
				if err := os.Symlink(f.home, filepath.Join(source, "tracked-link")); err != nil {
					t.Fatal(err)
				}
				git("add", "tracked-link")
			}
			git("commit", "-qm", "synthetic published tree")
			remote := filepath.Join(f.home, "remote.git")
			git("init", "--bare", "-q", remote)
			git("remote", "add", "origin", remote)
			git("push", "-u", "origin", "HEAD")
			if strings.HasSuffix(scenario, "_linked") {
				linked := source + "-linked"
				git("worktree", "add", "-b", "linked", linked)
				source = linked
				git("push", "-u", "origin", "HEAD")
			}
			cache := filepath.Join(source, "private")
			name := "artifact"
			if scenario == "credential" {
				name = "nested/.env"
			}
			if scenario == "database" {
				name = "nested/data.sqlite3"
			}
			if scenario == "evidence" {
				name = "nested/evidence/result"
			}
			if scenario != "clean" && scenario != "tracked_symlink" {
				path := filepath.Join(cache, name)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if scenario == "symlink" {
					if err := os.Symlink(f.home, path); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(path, []byte("synthetic payload"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			policy := "roots:\n  - path: " + root + "\n    max_depth: 1\ncollectors:\n  proc_root: " + proc + "\n  systemd_dirs: [" + units + "]\nretention:\n  default: none\n  delete_enabled: true\nprevention:\n  auto_quarantine: true\n  auto_expire: true\n  min_free_percent: 0\ncaches:\n  - name: whole-fixture\n    path: " + source + "\n    action: quarantine\n    retention: none\n"
			if scenario != "unknown" {
				policy += "  - name: explicitly-approved-fixture\n    path: " + cache + "\n    action: quarantine\n    retention: none\n"
			}
			if scenario == "bounded_cache" {
				policy += "    max_bytes: 9999999\n"
			}
			if scenario == "keep_overlap" {
				policy += "  - name: preserved-fixture\n    path: " + filepath.Join(cache, "artifact") + "\n    action: keep\n"
			}
			if scenario == "root_keep" {
				policy += "  - name: preserving-root\n    path: /\n    action: keep\n"
			}
			if scenario == "report_only" {
				policy = strings.Replace(policy, "collectors:\n", "  - path: "+cache+"\n    report_only: true\ncollectors:\n", 1)
			}
			if scenario == "protected" {
				policy += "protect:\n  paths: [" + filepath.Join(cache, "artifact") + "]\n"
			}
			revoked := strings.HasPrefix(scenario, "revoked")
			if revoked {
				policy = strings.Replace(policy, "auto_expire: true", "auto_expire: false", 1)
			}
			f.writePolicy(t, policy)
			out, stderr, code := f.run(t, "cycle")
			if code != ExitOK {
				t.Fatalf("cycle %s: %s %s", scenario, out, stderr)
			}
			_, err := os.Lstat(source)
			if revoked {
				if !os.IsNotExist(err) {
					t.Fatalf("approved receipt was not quarantined: %v\n%s", err, out)
				}
				var retained string
				if err := filepath.WalkDir(f.home, func(path string, entry fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if entry.Name() == "artifact" {
						retained = path
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if retained == "" {
					t.Fatal("quarantine lost payload")
				}
				// Reproduce the actual pre-fix receipt encoding, not only an
				// in-memory old-looking entry. Optimistic transitions compare JSON.
				db, err := sql.Open("sqlite", "file:"+filepath.Join(f.home, ".local", "state", "workspace-janitor", "janitor.db"))
				if err != nil {
					t.Fatal(err)
				}
				var cleanupID string
				if err := db.QueryRow("SELECT cleanup_id FROM cleanup_items WHERE source = ?", source).Scan(&cleanupID); err != nil {
					t.Fatal(err)
				}
				_, err = db.Exec(`UPDATE cleanup_items SET entry_json=json_remove(entry_json, '$.git.contents_known'),
					quarantined_json=json_remove(quarantined_json, '$.git.contents_known') WHERE cleanup_id=?`, cleanupID)
				db.Close()
				if err != nil {
					t.Fatal(err)
				}
				policy = strings.Replace(policy, "auto_expire: false", "auto_expire: true", 1)
				policy = strings.Replace(policy, "  - name: explicitly-approved-fixture\n    path: "+cache+"\n    action: quarantine\n    retention: none\n", "", 1)
				f.writePolicy(t, policy)
				out, stderr, code = f.run(t, "cycle")
				if code == ExitOK || !strings.Contains(stderr, "refused revalidation") {
					t.Fatalf("revoked expiry was not refused: %s %s", out, stderr)
				}
				if _, err := os.Stat(retained); err != nil {
					t.Fatalf("revoked receipt was deleted: %v\n%s", err, out)
				}
				out, stderr, code = f.run(t, "restore", "--confirm", cleanupID)
				if code != ExitOK {
					t.Fatalf("legacy receipt restore: %s %s", out, stderr)
				}
				if _, err := os.Stat(filepath.Join(source, "private", "artifact")); err != nil {
					t.Fatal(err)
				}
				return
			}
			if scenario == "clean" || scenario == "tracked_symlink" || strings.HasPrefix(scenario, "approved") {
				if !os.IsNotExist(err) {
					t.Fatalf("permitted cleanup did not remove source: %v\n%s", err, out)
				}
				if !strings.Contains(out, "deleted") {
					t.Fatalf("no deletion receipt: %s", out)
				}
			} else if err != nil {
				t.Fatalf("unsafe whole worktree not preserved: %v\n%s", err, out)
			}
		})
	}
}
