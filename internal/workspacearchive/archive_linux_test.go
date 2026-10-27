//go:build linux

package workspacearchive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
)

// fixture is an isolated home: a released workspace, an archive directory
// and an empty procfs stand-in, so no test observes real host processes
// unless it opts in.
type fixture struct {
	home, source, archive string
	rule                  config.WorkspaceArchiveRule
	scope                 Scope
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{home: home, source: filepath.Join(home, "work", "released"), archive: filepath.Join(home, "archive")}
	for _, dir := range []string{filepath.Join(home, "work"), f.archive, filepath.Join(home, "proc")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.rule = config.WorkspaceArchiveRule{Name: "released", Path: f.source, Owner: "seat-a", Release: "release-msg-1",
		DependentRoots: []string{home}, Archive: config.WorkspaceArchiveDestination{Directory: f.archive}}
	f.scope = Scope{ProcRoot: filepath.Join(home, "proc"), SearchRoots: []string{home}}
	return f
}

func write(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// populate writes files, an empty file, an empty directory and an internal
// symlink with nanosecond modification times, directories touched last.
func (f *fixture) populate(t *testing.T) {
	t.Helper()
	write(t, filepath.Join(f.source, "README.md"), []byte("released workspace\n"), 0o644)
	write(t, filepath.Join(f.source, "sub", "data.bin"), bytes.Repeat([]byte("0123456789abcdef"), 8192), 0o600)
	write(t, filepath.Join(f.source, "sub", "empty"), nil, 0o640)
	if err := os.MkdirAll(filepath.Join(f.source, "sub", "nested"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub/data.bin", filepath.Join(f.source, "link")); err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1700000000, 123456789)
	for _, rel := range []string{"README.md", "sub/data.bin", "sub/empty", "sub/nested", "sub", "."} {
		stamp = stamp.Add(time.Second + 7)
		if err := os.Chtimes(filepath.Join(f.source, rel), stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *fixture) archiveEntries(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(f.archive)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func allow() error { return nil }

// treeSnapshot captures what a faithful restore must reproduce.
func treeSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		detail := ""
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			detail, err = os.Readlink(path)
		case info.Mode().IsRegular():
			var data []byte
			data, err = os.ReadFile(path)
			sum := sha256.Sum256(data)
			detail = hex.EncodeToString(sum[:])
		}
		if err != nil {
			return err
		}
		mtime := info.ModTime().UnixNano()
		if info.Mode()&os.ModeSymlink != 0 {
			mtime = 0 // symlink times are best effort on some filesystems
		}
		out[rel] = fmt.Sprintf("%v %d %d %s", info.Mode(), info.Size()*boolInt(!info.IsDir()), mtime, detail)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func sameTree(t *testing.T, want, got map[string]string) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("tree has %d entries, want %d:\nwant %v\ngot  %v", len(got), len(want), want, got)
	}
	for path, value := range want {
		if got[path] != value {
			t.Fatalf("%s = %q, want %q", path, got[path], value)
		}
	}
}

func pin(rule config.WorkspaceArchiveRule, binding *Binding) config.WorkspaceArchiveRule {
	rule.Archive.Manifest, rule.Archive.ManifestSHA256 = binding.Manifest, binding.ManifestSHA256
	return rule
}

func TestCreateVerifyRestoreRoundTripIsCopyOnly(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.populate(t)
	before := treeSnapshot(t, f.source)

	inspection, err := Inspect(ctx, f.rule, f.scope)
	if err != nil || inspection.Members != 7 || inspection.LinkedWorktree {
		t.Fatalf("Inspect = %+v, %v", inspection, err)
	}
	if names := f.archiveEntries(t); len(names) != 0 {
		t.Fatalf("inspection wrote %v", names)
	}
	m, binding, err := Create(ctx, f.rule, f.scope, allow)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sameTree(t, before, treeSnapshot(t, f.source))
	if names := f.archiveEntries(t); strings.Join(names, ",") != "released.manifest.json,released.tar" {
		t.Fatalf("archive directory holds %v; want only the published tar and manifest", names)
	}
	if m.StreamSHA256 == "" || m.StreamSHA256 != m.ReadbackSHA256 || len(m.Members) != 7 || m.Bundle != nil {
		t.Fatalf("manifest lacks stream/readback proof or members: %+v", m)
	}
	data, err := os.ReadFile(binding.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(data); binding.Manifest != filepath.Join(f.archive, "released.manifest.json") || hex.EncodeToString(sum[:]) != binding.ManifestSHA256 {
		t.Fatalf("binding does not pin the published manifest: %+v", binding)
	}
	pinned := pin(f.rule, binding)
	if _, _, err := Check(ctx, pinned, true); err != nil {
		t.Fatalf("Check: %v", err)
	}
	// Outputs are exclusive: a rerun never replaces or reuses them.
	if _, _, err := Create(ctx, f.rule, f.scope, allow); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second Create = %v, want exclusive refusal", err)
	}
	if _, _, err := Create(ctx, pinned, f.scope, allow); err == nil {
		t.Fatal("Create with a pinned manifest must refuse")
	}

	restored := filepath.Join(f.home, "restored")
	if _, err := Restore(ctx, pinned, restored); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	sameTree(t, before, treeSnapshot(t, restored))
	if _, err := Restore(ctx, pinned, restored); err == nil {
		t.Fatal("Restore overwrote an existing destination")
	}
	if _, err := Restore(ctx, pinned, filepath.Join(f.archive, "inside")); err == nil {
		t.Fatal("Restore wrote into the archive directory")
	}
	sameTree(t, before, treeSnapshot(t, f.source))

	// Full verification reads every archived byte.
	tarPath := filepath.Join(f.archive, "released.tar")
	file, err := os.OpenFile(tarPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteAt([]byte("X"), 1024+20); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if _, _, err := Check(ctx, pinned, true); err == nil {
		t.Fatal("full Check accepted a corrupted archive")
	}
	if _, err := Restore(ctx, pinned, filepath.Join(f.home, "restored-corrupt")); err == nil {
		t.Fatal("Restore accepted a corrupted archive")
	}
	if _, err := os.Lstat(filepath.Join(f.home, "restored-corrupt")); !os.IsNotExist(err) {
		t.Fatalf("failed restore published a destination: %v", err)
	}
}

func TestCreateRefusesSecretLikeFile(t *testing.T) {
	f := newFixture(t)
	f.populate(t)
	write(t, filepath.Join(f.source, "config", ".env"), []byte("TOKEN=fixture\n"), 0o600)
	for name, run := range map[string]func() error{
		"inspect": func() error { _, err := Inspect(context.Background(), f.rule, f.scope); return err },
		"create":  func() error { _, _, err := Create(context.Background(), f.rule, f.scope, allow); return err },
	} {
		if err := run(); err == nil || !strings.Contains(err.Error(), "secret-like") || !strings.Contains(err.Error(), "config/.env") {
			t.Fatalf("%s = %v, want secret-like refusal naming config/.env", name, err)
		}
	}
	if names := f.archiveEntries(t); len(names) != 0 {
		t.Fatalf("refused archive left %v", names)
	}
}

func TestCreateRefusesExternalDependents(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, f *fixture){
		"absolute symlink": func(t *testing.T, f *fixture) {
			mustSymlink(t, filepath.Join(f.source, "sub"), filepath.Join(f.home, "other", "uses-sub"))
		},
		"relative symlink": func(t *testing.T, f *fixture) {
			mustSymlink(t, "../work/released/README.md", filepath.Join(f.home, "other", "readme"))
		},
		"worktree gitdir": func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.home, "other", "checkout", ".git"), []byte("gitdir: "+filepath.Join(f.source, ".git", "worktrees", "checkout")+"\n"), 0o644)
		},
		"object alternates": func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.home, "other", "repo", ".git", "objects", "info", "alternates"), []byte(filepath.Join(f.source, ".git", "objects")+"\n"), 0o644)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.populate(t)
			setup(t, f)
			_, _, err := Create(context.Background(), f.rule, f.scope, allow)
			if err == nil || !strings.Contains(err.Error(), "external dependents") {
				t.Fatalf("Create = %v, want external dependent refusal", err)
			}
			if names := f.archiveEntries(t); len(names) != 0 {
				t.Fatalf("refused archive left %v", names)
			}
		})
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func TestCreateRefusesLiveProcessWorkingDirectory(t *testing.T) {
	if _, err := exec.LookPath("sleep"); err != nil {
		t.Skip("sleep is unavailable")
	}
	f := newFixture(t)
	f.populate(t)
	cmd := exec.Command("sleep", "60")
	cmd.Dir = filepath.Join(f.source, "sub")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	f.scope.ProcRoot = "/proc"
	_, _, err := Create(context.Background(), f.rule, f.scope, allow)
	if want := fmt.Sprintf("pid %d cwd", cmd.Process.Pid); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Create = %v, want live reference %q", err, want)
	}
	if names := f.archiveEntries(t); len(names) != 0 {
		t.Fatalf("refused archive left %v", names)
	}
}

func TestExpectedMountMismatchRefusesCreateAndCheck(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.populate(t)
	wrong := f.rule
	wrong.Archive.ExpectFSType = "workspace-janitor-absent-fs"
	if _, _, err := Create(ctx, wrong, f.scope, allow); err == nil || !strings.Contains(err.Error(), `expected "workspace-janitor-absent-fs"`) {
		t.Fatalf("Create = %v, want mount mismatch refusal", err)
	}
	wrong = f.rule
	wrong.Archive.ExpectMountSource = "storage.invalid:/archive"
	if _, err := Inspect(ctx, wrong, f.scope); err == nil || !strings.Contains(err.Error(), "refusing to write anywhere else") {
		t.Fatalf("Inspect = %v, want mount source refusal", err)
	}
	if names := f.archiveEntries(t); len(names) != 0 {
		t.Fatalf("refused archive left %v", names)
	}

	m, binding, err := Create(ctx, f.rule, f.scope, allow)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	pinned := pin(f.rule, binding)
	pinned.Archive.ExpectFSType, pinned.Archive.ExpectMountSource = m.FSType, m.MountSource
	if _, _, err := Check(ctx, pinned, true); err != nil {
		t.Fatalf("Check with the actual mount facts: %v", err)
	}
	pinned.Archive.ExpectMountSource = "storage.invalid:/archive"
	if _, _, err := Check(ctx, pinned, false); err == nil {
		t.Fatal("Check accepted an archive directory on an unexpected mount")
	}
	if _, err := Restore(ctx, pinned, filepath.Join(f.home, "restored")); err == nil {
		t.Fatal("Restore read from an archive directory on an unexpected mount")
	}
}

func gitFixture(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid",
		"GIT_COMMITTER_NAME=fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestLinkedWorktreeGetsVerifiedHeadBundle(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is unavailable")
	}
	ctx := context.Background()
	f := newFixture(t)
	main := filepath.Join(f.home, "main")
	if err := os.MkdirAll(main, 0o755); err != nil {
		t.Fatal(err)
	}
	gitFixture(t, main, "init", "-q")
	write(t, filepath.Join(main, "base.txt"), []byte("base\n"), 0o644)
	gitFixture(t, main, "add", "base.txt")
	gitFixture(t, main, "commit", "-q", "-m", "base")
	gitFixture(t, main, "worktree", "add", "-q", "-b", "released", f.source)
	write(t, filepath.Join(f.source, "feature.txt"), []byte("feature\n"), 0o644)
	gitFixture(t, f.source, "add", "feature.txt")
	gitFixture(t, f.source, "commit", "-q", "-m", "feature")
	head := gitFixture(t, f.source, "rev-parse", "HEAD")

	m, binding, err := Create(ctx, f.rule, f.scope, allow)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if m.Bundle == nil || m.Bundle.Head != head || m.Bundle.File != "released.bundle" || m.Bundle.WorktreeAdmin != filepath.Join(main, ".git", "worktrees", "released") {
		t.Fatalf("linked worktree bundle record = %+v, want HEAD %s", m.Bundle, head)
	}
	bundlePath := filepath.Join(f.archive, "released.bundle")
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != m.Bundle.SHA256 || int64(len(data)) != m.Bundle.Bytes {
		t.Fatal("published bundle differs from its manifest record")
	}
	if _, _, err := Check(ctx, pin(f.rule, binding), true); err != nil {
		t.Fatalf("Check: %v", err)
	}
	// The bundle alone recovers the history: fetch it into an unrelated repo.
	clone := filepath.Join(f.home, "clone")
	if err := os.MkdirAll(clone, 0o755); err != nil {
		t.Fatal(err)
	}
	gitFixture(t, clone, "init", "-q")
	gitFixture(t, clone, "fetch", "-q", bundlePath, "HEAD")
	if got := gitFixture(t, clone, "rev-parse", "FETCH_HEAD"); got != head {
		t.Fatalf("bundle restores %s, want %s", got, head)
	}

	// A corrupted bundle fails full verification.
	if err := os.WriteFile(bundlePath, append(data[:len(data)-1], data[len(data)-1]^0xff), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Check(ctx, pin(f.rule, binding), true); err == nil {
		t.Fatal("full Check accepted a corrupted history bundle")
	}
}

// outsideDir is a directory outside the fixture home and so outside every
// dependent search root.
func outsideDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCreateRefusesOutboundGitSymlink(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(t *testing.T, f *fixture)
		want  string
	}{
		"root": {func(t *testing.T, f *fixture) {
			if err := os.MkdirAll(filepath.Join(f.home, "main", ".git"), 0o755); err != nil {
				t.Fatal(err)
			}
			mustSymlink(t, filepath.Join(f.home, "main", ".git"), filepath.Join(f.source, ".git"))
		}, ".git: Git history lives outside the archived tree"},
		"root through an internal link": {func(t *testing.T, f *fixture) {
			outside := outsideDir(t)
			mustSymlink(t, outside, filepath.Join(f.source, "history"))
			mustSymlink(t, "history", filepath.Join(f.source, ".git"))
		}, ".git: Git history lives outside the archived tree"},
		"nested": {func(t *testing.T, f *fixture) {
			if err := os.MkdirAll(filepath.Join(f.home, "main", ".git"), 0o755); err != nil {
				t.Fatal(err)
			}
			mustSymlink(t, filepath.Join(f.home, "main", ".git"), filepath.Join(f.source, "sub", "vendored", ".git"))
		}, "sub/vendored/.git: nested worktree history lives outside the archived tree"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.populate(t)
			tc.setup(t, f)
			if _, err := Inspect(context.Background(), f.rule, f.scope); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Inspect = %v, want refusal containing %q", err, tc.want)
			}
			if _, _, err := Create(context.Background(), f.rule, f.scope, allow); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Create = %v, want refusal containing %q", err, tc.want)
			}
			if names := f.archiveEntries(t); len(names) != 0 {
				t.Fatalf("refused archive left %v", names)
			}
		})
	}

	// A .git symlink to a directory inside the tree is archived verbatim.
	f := newFixture(t)
	f.populate(t)
	if err := os.MkdirAll(filepath.Join(f.source, "history"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, "history", filepath.Join(f.source, ".git"))
	if _, _, err := Create(context.Background(), f.rule, f.scope, allow); err != nil {
		t.Fatalf("Create with an inward .git symlink: %v", err)
	}
}

func TestRestoreRefusesDestinationOverlappingSource(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.populate(t)
	before := treeSnapshot(t, f.source)
	_, binding, err := Create(ctx, f.rule, f.scope, allow)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	pinned := pin(f.rule, binding)
	const want = "must not be inside or contain the released workspace path"

	inside := filepath.Join(f.source, "sub", "restored")
	if _, err := Restore(ctx, pinned, inside); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Restore(%s) = %v, want overlap refusal", inside, err)
	}
	if _, err := os.Lstat(inside); !os.IsNotExist(err) {
		t.Fatalf("refused restore wrote %s: %v", inside, err)
	}
	sameTree(t, before, treeSnapshot(t, f.source))

	// The original path itself is refused only while the source exists.
	if _, err := Restore(ctx, pinned, f.source); err == nil || !strings.Contains(err.Error(), "must not exist") {
		t.Fatalf("Restore(%s) = %v, want existing destination refusal", f.source, err)
	}
	sameTree(t, before, treeSnapshot(t, f.source))

	// With the source gone, a parent of it is still refused.
	work := filepath.Join(f.home, "work")
	if err := os.RemoveAll(work); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(ctx, pinned, work); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Restore(%s) = %v, want overlap refusal", work, err)
	}
	if _, err := os.Lstat(work); !os.IsNotExist(err) {
		t.Fatalf("refused restore wrote %s: %v", work, err)
	}

	// The vacated original path is the main recovery destination.
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(ctx, pinned, f.source); err != nil {
		t.Fatalf("Restore to the vacated original path: %v", err)
	}
	sameTree(t, before, treeSnapshot(t, f.source))
}

func TestCreateRefusesChainedSymlinkDependent(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(t *testing.T, f *fixture)
		want  string
	}{
		"chain through a link outside the search roots": {func(t *testing.T, f *fixture) {
			hop := filepath.Join(outsideDir(t), "hop")
			mustSymlink(t, f.source, hop)
			mustSymlink(t, hop, filepath.Join(f.home, "other", "uses"))
		}, "reaches"},
		"symlinked directory component": {func(t *testing.T, f *fixture) {
			workdir := filepath.Join(outsideDir(t), "workdir")
			mustSymlink(t, filepath.Join(f.home, "work"), workdir)
			mustSymlink(t, filepath.Join(workdir, "released", "README.md"), filepath.Join(f.home, "other", "readme"))
		}, "reaches"},
		"loop": {func(t *testing.T, f *fixture) {
			mustSymlink(t, "loop-b", filepath.Join(f.home, "other", "loop-a"))
			mustSymlink(t, "loop-a", filepath.Join(f.home, "other", "loop-b"))
		}, "cannot be resolved"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.populate(t)
			tc.setup(t, f)
			_, _, err := Create(context.Background(), f.rule, f.scope, allow)
			if err == nil || !strings.Contains(err.Error(), "external dependents") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Create = %v, want external dependent refusal containing %q", err, tc.want)
			}
			if names := f.archiveEntries(t); len(names) != 0 {
				t.Fatalf("refused archive left %v", names)
			}
		})
	}
}

func TestCreateRefusesOversizedDependentPointer(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, f *fixture){
		// The in-source target sits past the 64 KiB read bound.
		"object alternates": func(t *testing.T, f *fixture) {
			data := strings.Repeat("# padding\n", 7000) + filepath.Join(f.source, ".git", "objects") + "\n"
			write(t, filepath.Join(f.home, "other", "repo", ".git", "objects", "info", "alternates"), []byte(data), 0o644)
		},
		"worktree gitdir": func(t *testing.T, f *fixture) {
			data := "gitdir:" + strings.Repeat(" ", 70000) + filepath.Join(f.source, ".git", "worktrees", "checkout") + "\n"
			write(t, filepath.Join(f.home, "other", "checkout", ".git"), []byte(data), 0o644)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.populate(t)
			setup(t, f)
			_, _, err := Create(context.Background(), f.rule, f.scope, allow)
			if err == nil || !strings.Contains(err.Error(), "dependent scan") || !strings.Contains(err.Error(), "exceeds the 65536-byte bound") {
				t.Fatalf("Create = %v, want oversized pointer refusal", err)
			}
			if names := f.archiveEntries(t); len(names) != 0 {
				t.Fatalf("refused archive left %v", names)
			}
		})
	}
}
