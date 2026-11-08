//go:build linux

package workspacearchive

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"golang.org/x/sys/unix"
)

const sessionID = "0198f3c2-7d4e-session"

// sessionFixture is an OMP-style session unit: the directory <home>/work/stem
// and, when companion is set, its sibling log stem.jsonl. The rule names the
// companion either way.
func sessionFixture(t *testing.T, companion bool) *fixture {
	t.Helper()
	f := newFixture(t)
	f.source = filepath.Join(f.home, "work", "stem")
	f.rule.Name, f.rule.Path, f.rule.Companion = "stem", f.source, f.source+".jsonl"
	write(t, filepath.Join(f.source, "artifact.txt"), []byte("tool output\n"), 0o644)
	write(t, filepath.Join(f.source, "nested", "result.bin"), bytes.Repeat([]byte("r"), 5000), 0o600)
	paths := []string{filepath.Join(f.source, "artifact.txt"), filepath.Join(f.source, "nested", "result.bin"), filepath.Join(f.source, "nested"), f.source}
	if companion {
		write(t, f.rule.Companion, []byte(`{"type":"session","id":"`+sessionID+`"}`+"\n"), 0o640)
		paths = append(paths, f.rule.Companion)
	}
	stamp(t, paths...)
	return f
}

// stamp gives each path, in order, a distinct nanosecond modification time.
func stamp(t *testing.T, paths ...string) {
	t.Helper()
	at := time.Unix(1700000000, 987654321)
	for _, path := range paths {
		at = at.Add(time.Second + 13)
		if err := os.Chtimes(path, at, at); err != nil {
			t.Fatal(err)
		}
	}
}

func tarNames(t *testing.T, path string) []string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var names []string
	tr := tar.NewReader(file)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return names
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
}

func identity(t *testing.T, path string) core.FilesystemID {
	t.Helper()
	st, err := statxAt(unix.AT_FDCWD, path, 0)
	if err != nil {
		t.Fatal(err)
	}
	return st.id
}

func move(t *testing.T, from, to string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(from, to); err != nil {
		t.Fatal(err)
	}
}

func appendTo(t *testing.T, path, data string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString(data); err != nil {
		t.Fatal(err)
	}
}

func TestClassicDirectoryTarNamesAreUnchanged(t *testing.T) {
	f, m := archived(t)
	want := []string{"./", "README.md", "link", "sub/", "sub/data.bin", "sub/empty", "sub/nested/"}
	if got := tarNames(t, filepath.Join(f.archive, "released.tar")); !slices.Equal(got, want) {
		t.Fatalf("classic tar names = %q, want %q", got, want)
	}
	if m.Companion != nil {
		t.Fatalf("a rule without a companion recorded %+v", m.Companion)
	}
}

func TestFileUnitCreateCheckBindRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.source = filepath.Join(f.home, "work", "job-7.log")
	f.rule.Name, f.rule.Path = "job-7", f.source
	data := bytes.Repeat([]byte("log line\n"), 3000)
	write(t, f.source, data, 0o640)
	stamp(t, f.source)
	before := treeSnapshot(t, f.source)

	inspection, err := Inspect(ctx, f.rule, f.scope)
	if err != nil || inspection.Members != 1 || inspection.ContentBytes != int64(len(data)) {
		t.Fatalf("Inspect = %+v, %v", inspection, err)
	}
	m, binding, err := Create(ctx, f.rule, f.scope, allow)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(m.Members) != 1 || m.Members[0].Path != "." || m.Members[0].Type != TypeFile || m.Members[0].Size != int64(len(data)) || m.Companion != nil {
		t.Fatalf("manifest members = %+v, companion %+v", m.Members, m.Companion)
	}
	if got := tarNames(t, filepath.Join(f.archive, "job-7.tar")); !slices.Equal(got, []string{"job-7.log"}) {
		t.Fatalf("file unit tar names = %q, want the file's own name", got)
	}
	sameTree(t, before, treeSnapshot(t, f.source))
	f.rule = pin(f.rule, binding)
	if _, _, err := Check(ctx, f.rule, true); err != nil {
		t.Fatalf("Check: %v", err)
	}
	b, err := Bind(ctx, f.rule, f.scope, f.source, true)
	if err != nil || b.MemberCount != 1 || b.CompanionSuffix != "" || b.CompanionID != (core.FilesystemID{}) {
		t.Fatalf("Bind = %+v, %v", b, err)
	}
	// The quarantined copy binds under its own name.
	moved := filepath.Join(f.home, "quarantine", "receipt", "item")
	move(t, f.source, moved)
	if _, err := Bind(ctx, f.rule, f.scope, moved, true); err != nil {
		t.Fatalf("Bind(quarantined copy): %v", err)
	}
	// Restore recreates the file with its metadata, at a new name and at the
	// vacated original path.
	for _, destination := range []string{filepath.Join(f.home, "restored.log"), f.source} {
		if _, err := Restore(ctx, f.rule, destination); err != nil {
			t.Fatalf("Restore(%s): %v", destination, err)
		}
		sameTree(t, before, treeSnapshot(t, destination))
	}
	if _, err := Restore(ctx, f.rule, f.source); err == nil || !strings.Contains(err.Error(), "must not exist") {
		t.Fatalf("Restore over the restored file = %v, want existing destination refusal", err)
	}
	appendTo(t, moved, "late line\n")
	if _, err := Bind(ctx, f.rule, f.scope, moved, false); err == nil || !strings.Contains(err.Error(), "differs from the archive") {
		t.Fatalf("Bind(grown file) = %v, want local difference refusal", err)
	}
}

func TestFileUnitRefusesSymlinkAndSecretLikeRoots(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.home, "work", "real.log")
	write(t, target, []byte("x\n"), 0o644)
	f.rule.Path = filepath.Join(f.home, "work", "link.log")
	mustSymlink(t, target, f.rule.Path)
	if _, err := Inspect(context.Background(), f.rule, f.scope); err == nil || !strings.Contains(err.Error(), "must be a directory or a regular file") {
		t.Fatalf("Inspect(symlink) = %v, want type refusal", err)
	}
	f.rule.Path = filepath.Join(f.home, "work", "deploy.pem")
	write(t, f.rule.Path, []byte("-----BEGIN PRIVATE KEY-----\n"), 0o600)
	if _, err := Inspect(context.Background(), f.rule, f.scope); err == nil || !strings.Contains(err.Error(), "secret-like") {
		t.Fatalf("Inspect(secret-like file) = %v, want secret-like refusal", err)
	}
}

func TestCompanionUnitArchivesBindsAndRestoresAsOne(t *testing.T) {
	ctx := context.Background()
	f := sessionFixture(t, true)
	f.rule.Mentions = []string{f.source, sessionID}
	dirBefore, logBefore := treeSnapshot(t, f.source), treeSnapshot(t, f.rule.Companion)
	logInfo, err := os.Stat(f.rule.Companion)
	if err != nil {
		t.Fatal(err)
	}

	inspection, err := Inspect(ctx, f.rule, f.scope)
	if err != nil || inspection.Members != 5 || inspection.ContentBytes != 12+5000+logInfo.Size() {
		t.Fatalf("Inspect = %+v, %v; want the companion counted", inspection, err)
	}
	m, binding, err := Create(ctx, f.rule, f.scope, allow)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if c := m.Companion; c == nil || c.Path != "stem.jsonl" || c.Type != TypeFile || c.Size != logInfo.Size() || len(c.SHA256) != 64 {
		t.Fatalf("manifest companion = %+v", m.Companion)
	}
	if m.Rule.Companion != f.rule.Companion || m.Rule.Mentions != nil {
		t.Fatalf("manifest rule companion %q mentions %q; want the companion bound and live mentions omitted", m.Rule.Companion, m.Rule.Mentions)
	}
	tarPath := filepath.Join(f.archive, "stem.tar")
	want := []string{"stem/", "stem/artifact.txt", "stem/nested/", "stem/nested/result.bin", "stem.jsonl"}
	if got := tarNames(t, tarPath); !slices.Equal(got, want) {
		t.Fatalf("unit tar names = %q, want %q", got, want)
	}
	// Plain tar extracts the unit at its original names.
	if _, err := exec.LookPath("tar"); err == nil {
		extracted := filepath.Join(f.home, "extracted")
		if err := os.MkdirAll(extracted, 0o755); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("tar", "-xpf", tarPath, "-C", extracted).CombinedOutput(); err != nil {
			t.Fatalf("tar -x: %v\n%s", err, out)
		}
		sameTree(t, dirBefore, treeSnapshot(t, filepath.Join(extracted, "stem")))
		sameTree(t, logBefore, treeSnapshot(t, filepath.Join(extracted, "stem.jsonl")))
	}

	f.rule = pin(f.rule, binding)
	// Mentions are live and unhashed; the companion is bound by the hash.
	other := f.rule
	other.Mentions = []string{"another-session"}
	if _, _, err := Check(ctx, other, true); err != nil {
		t.Fatalf("Check with different live mentions: %v", err)
	}
	other = f.rule
	other.Companion = f.source + ".log"
	if _, _, err := Check(ctx, other, false); err == nil {
		t.Fatal("Check accepted a rule naming a different companion")
	}

	local, err := Bind(ctx, f.rule, f.scope, f.source, true)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if local.CompanionSuffix != ".jsonl" || local.CompanionID != identity(t, f.rule.Companion) || local.MemberCount != len(m.Members)+1 {
		t.Fatalf("binding = %+v; want suffix .jsonl, the companion's identity and %d members", local, len(m.Members)+1)
	}
	// Quarantine moves the unit as a pair: <base>/item and <base>/item.jsonl.
	item := filepath.Join(f.home, "quarantine", "receipt", "item")
	move(t, f.source, item)
	move(t, f.rule.Companion, item+".jsonl")
	moved, err := Bind(ctx, f.rule, f.scope, item, true)
	if err != nil {
		t.Fatalf("Bind(quarantined pair): %v", err)
	}
	if moved.CompanionID != local.CompanionID || moved.TreeDigest != local.TreeDigest || moved.MemberCount != local.MemberCount {
		t.Fatalf("quarantined binding %+v differs from the original %+v", moved, local)
	}

	// Restore recreates both names at a new destination.
	restored := filepath.Join(f.home, "restored", "copy")
	if err := os.MkdirAll(filepath.Dir(restored), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(ctx, f.rule, restored); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	sameTree(t, dirBefore, treeSnapshot(t, restored))
	sameTree(t, logBefore, treeSnapshot(t, restored+".jsonl"))
	if _, err := Restore(ctx, f.rule, restored); err == nil || !strings.Contains(err.Error(), "must not exist") {
		t.Fatalf("second Restore = %v, want existing destination refusal", err)
	}
	// An existing companion name alone refuses before anything is written.
	blocked := filepath.Join(f.home, "restored", "blocked")
	write(t, blocked+".jsonl", []byte("someone else's\n"), 0o600)
	if _, err := Restore(ctx, f.rule, blocked); err == nil || !strings.Contains(err.Error(), blocked+".jsonl must not exist") {
		t.Fatalf("Restore = %v, want refusal of the existing companion name", err)
	}
	entries, err := os.ReadDir(filepath.Dir(restored))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if !slices.Equal(names, []string{"blocked.jsonl", "copy", "copy.jsonl"}) {
		t.Fatalf("restore parent holds %q; want only the restored pair and the blocking file", names)
	}
}

func TestFullCheckAndRestoreVerifyTheCompanionContent(t *testing.T) {
	ctx := context.Background()
	f := sessionFixture(t, true)
	_, binding, err := Create(ctx, f.rule, f.scope, allow)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.rule = pin(f.rule, binding)
	tarPath := filepath.Join(f.archive, "stem.tar")
	data, err := os.ReadFile(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.Index(data, []byte(sessionID))
	if at < 0 {
		t.Fatal("companion content not found in the tar")
	}
	data[at] ^= 0x01
	if err := os.WriteFile(tarPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Check(ctx, f.rule, true); err == nil || !strings.Contains(err.Error(), "stem.jsonl") {
		t.Fatalf("full Check = %v, want the corrupted companion named", err)
	}
	restored := filepath.Join(f.home, "restored")
	if _, err := Restore(ctx, f.rule, restored); err == nil {
		t.Fatal("Restore accepted a corrupted companion")
	}
	for _, path := range []string{restored, restored + ".jsonl"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("failed restore published %s: %v", path, err)
		}
	}
}

func TestBindRefusesCompanionDifferences(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(t *testing.T, companion string)
		want   string
		// detectedWithoutContent is false only for a same-size, same-mtime
		// content change, which only a full binding can see.
		detectedWithoutContent bool
	}{
		"same-size content change with restored mtime": {func(t *testing.T, companion string) {
			info, err := os.Stat(companion)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(companion)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(companion, bytes.ToUpper(data), 0); err != nil {
				t.Fatal(err)
			}
			if err = os.Chtimes(companion, info.ModTime(), info.ModTime()); err != nil {
				t.Fatal(err)
			}
		}, "local companion %s differs from the archive", false},
		"appended entry": {func(t *testing.T, companion string) {
			appendTo(t, companion, `{"type":"message"}`+"\n")
		}, "local companion %s differs from the archive", true},
		"removed": {func(t *testing.T, companion string) {
			if err := os.Remove(companion); err != nil {
				t.Fatal(err)
			}
		}, "local companion %s is missing", true},
		"replaced by a symlink": {func(t *testing.T, companion string) {
			if err := os.Rename(companion, companion+".real"); err != nil {
				t.Fatal(err)
			}
			mustSymlink(t, filepath.Base(companion)+".real", companion)
		}, "%s must be a regular file", true},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			f := sessionFixture(t, true)
			_, binding, err := Create(ctx, f.rule, f.scope, allow)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			f.rule = pin(f.rule, binding)
			item := filepath.Join(f.home, "quarantine", "receipt", "item")
			move(t, f.source, item)
			move(t, f.rule.Companion, item+".jsonl")
			tc.change(t, item+".jsonl")
			want := strings.ReplaceAll(tc.want, "%s", item+".jsonl")
			if _, err := Bind(ctx, f.rule, f.scope, item, true); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("full Bind = %v, want %q", err, want)
			}
			_, err = Bind(ctx, f.rule, f.scope, item, false)
			if tc.detectedWithoutContent && (err == nil || !strings.Contains(err.Error(), want)) {
				t.Fatalf("metadata Bind = %v, want %q", err, want)
			}
			if !tc.detectedWithoutContent && err != nil {
				t.Fatalf("metadata Bind compares content it must not read: %v", err)
			}
		})
	}
}

func TestCompanionRecordedAbsentMustStayAbsent(t *testing.T) {
	ctx := context.Background()
	f := sessionFixture(t, false)
	dirBefore := treeSnapshot(t, f.source)
	m, binding, err := Create(ctx, f.rule, f.scope, allow)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if m.Companion != nil {
		t.Fatalf("absent companion recorded as %+v", m.Companion)
	}
	want := []string{"stem/", "stem/artifact.txt", "stem/nested/", "stem/nested/result.bin"}
	if got := tarNames(t, filepath.Join(f.archive, "stem.tar")); !slices.Equal(got, want) {
		t.Fatalf("unit tar names = %q, want %q", got, want)
	}
	f.rule = pin(f.rule, binding)
	b, err := Bind(ctx, f.rule, f.scope, f.source, true)
	if err != nil || b.CompanionSuffix != ".jsonl" || b.CompanionID != (core.FilesystemID{}) || b.MemberCount != len(m.Members) {
		t.Fatalf("Bind = %+v, %v; want the suffix with a zero companion identity", b, err)
	}
	restored := filepath.Join(f.home, "restored")
	if _, err := Restore(ctx, f.rule, restored); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	sameTree(t, dirBefore, treeSnapshot(t, restored))
	if _, err := os.Lstat(restored + ".jsonl"); !os.IsNotExist(err) {
		t.Fatalf("restore invented a companion: %v", err)
	}
	write(t, f.rule.Companion, []byte("{}\n"), 0o600)
	if _, err := Bind(ctx, f.rule, f.scope, f.source, false); err == nil || !strings.Contains(err.Error(), "companion appeared") {
		t.Fatalf("Bind = %v, want companion appeared refusal", err)
	}
}

func TestCreateRefusesCompanionChangedWhileArchiving(t *testing.T) {
	for name, tc := range map[string]struct {
		present bool
		change  func(t *testing.T, companion string)
		want    string
	}{
		"appeared": {false, func(t *testing.T, companion string) {
			write(t, companion, []byte("{}\n"), 0o600)
		}, "companion appeared"},
		"rewritten": {true, func(t *testing.T, companion string) {
			appendTo(t, companion, "{}\n")
		}, "changed after it was recorded"},
		"removed": {true, func(t *testing.T, companion string) {
			if err := os.Remove(companion); err != nil {
				t.Fatal(err)
			}
		}, "changed after it was recorded"},
	} {
		t.Run(name, func(t *testing.T) {
			f := sessionFixture(t, tc.present)
			calls := 0
			// The second preflight runs after the tar is written, before the
			// fresh checks that precede publication.
			preflight := func() error {
				if calls++; calls == 2 {
					tc.change(t, f.rule.Companion)
				}
				return nil
			}
			_, _, err := Create(context.Background(), f.rule, f.scope, preflight)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "original retained") {
				t.Fatalf("Create = %v, want %q", err, tc.want)
			}
			if names := f.archiveEntries(t); len(names) != 0 {
				t.Fatalf("refused archive left %v", names)
			}
		})
	}
}

func TestCompanionMustBeAPlainSibling(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(t *testing.T, f *fixture)
		want  string
	}{
		"not a sibling": {func(t *testing.T, f *fixture) {
			f.rule.Companion = filepath.Join(f.home, "elsewhere", "stem.jsonl")
		}, "must be a sibling"},
		"name does not extend the unit's": {func(t *testing.T, f *fixture) {
			f.rule.Companion = filepath.Join(f.home, "work", "other.jsonl")
		}, "must be a sibling"},
		"symlink": {func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.home, "logs", "real.jsonl"), []byte("{}\n"), 0o600)
			mustSymlink(t, filepath.Join(f.home, "logs", "real.jsonl"), f.rule.Companion)
		}, "must be a regular file"},
		"directory": {func(t *testing.T, f *fixture) {
			if err := os.Mkdir(f.rule.Companion, 0o755); err != nil {
				t.Fatal(err)
			}
		}, "must be a regular file"},
		"secret-like name": {func(t *testing.T, f *fixture) {
			write(t, f.rule.Companion, []byte("{}\n"), 0o600)
			f.scope.SensitiveNames = []string{"*.JSONL"}
		}, "secret-like files keep"},
		"external dependent": {func(t *testing.T, f *fixture) {
			write(t, f.rule.Companion, []byte("{}\n"), 0o600)
			mustSymlink(t, f.rule.Companion, filepath.Join(f.home, "other", "latest.jsonl"))
		}, "external dependents keep"},
	} {
		t.Run(name, func(t *testing.T) {
			f := sessionFixture(t, false)
			tc.setup(t, f)
			if _, err := Inspect(context.Background(), f.rule, f.scope); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Inspect = %v, want %q", err, tc.want)
			}
			if _, _, err := Create(context.Background(), f.rule, f.scope, allow); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Create = %v, want %q", err, tc.want)
			}
			if names := f.archiveEntries(t); len(names) != 0 {
				t.Fatalf("refused archive left %v", names)
			}
		})
	}
}

// fakeProcess adds a process to the fixture's procfs stand-in with the given
// files; a nil content makes that name a directory, which cannot be read.
func fakeProcess(t *testing.T, f *fixture, pid string, files map[string][]byte) {
	t.Helper()
	dir := filepath.Join(f.home, "proc", pid)
	for name, content := range files {
		if content == nil {
			if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		write(t, filepath.Join(dir, name), content, 0o400)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestLiveMentionsKeepTheUnitLocal(t *testing.T) {
	ctx := context.Background()
	f := sessionFixture(t, true)
	f.rule.Mentions = []string{f.source, sessionID}
	_, binding, err := Create(ctx, f.rule, f.scope, allow)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	pinned := pin(f.rule, binding)

	// A process naming the session only in its environment.
	fakeProcess(t, f, "99999999", map[string][]byte{"environ": []byte("HOME=/root\x00OMP_SESSION_ID=" + sessionID + "\x00")})
	want := "live process references keep " + f.source + " local: [pid 99999999 environ]"
	if _, err := Inspect(ctx, f.rule, f.scope); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Inspect = %v, want %q", err, want)
	}
	if _, err := Bind(ctx, pinned, f.scope, f.source, true); err == nil || !strings.Contains(err.Error(), "pid 99999999 environ") {
		t.Fatalf("Bind = %v, want the environment mention", err)
	}
	// Without mentions the environment is not read.
	plain := pinned
	plain.Mentions = nil
	if _, err := Bind(ctx, plain, f.scope, f.source, true); err != nil {
		t.Fatalf("Bind without mentions: %v", err)
	}
	if err := os.RemoveAll(filepath.Join(f.home, "proc", "99999999")); err != nil {
		t.Fatal(err)
	}

	// A mention in the command line that straddles the end of the first read
	// (64 KiB plus the carried tail of the longest mention).
	first := 64<<10 + max(len(f.source), len(sessionID)) - 1
	cmdline := append(bytes.Repeat([]byte("a"), first-5), "\x00"+sessionID+"\x00"...)
	fakeProcess(t, f, "99999998", map[string][]byte{"cmdline": cmdline})
	if _, err := Inspect(ctx, f.rule, f.scope); err == nil || !strings.Contains(err.Error(), "pid 99999998 cmdline") {
		t.Fatalf("Inspect = %v, want the command-line mention", err)
	}
}

func TestLiveReferencesCoverTheCompanion(t *testing.T) {
	ctx := context.Background()
	f := sessionFixture(t, true)
	_, binding, err := Create(ctx, f.rule, f.scope, allow)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.rule = pin(f.rule, binding)
	item := filepath.Join(f.home, "quarantine", "receipt", "item")
	move(t, f.source, item)
	move(t, f.rule.Companion, item+".jsonl")
	// A writer still holding the quarantined companion open.
	fd := filepath.Join(f.home, "proc", "99999995", "fd")
	mustSymlink(t, item+".jsonl", filepath.Join(fd, "3"))
	if _, err := Bind(ctx, f.rule, f.scope, item, true); err == nil || !strings.Contains(err.Error(), "pid 99999995 fd 3") {
		t.Fatalf("Bind = %v, want the open companion", err)
	}
	// One that reopened the original companion name.
	if err := os.Remove(filepath.Join(fd, "3")); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, f.rule.Companion, filepath.Join(fd, "4"))
	if _, err := Bind(ctx, f.rule, f.scope, item, true); err == nil || !strings.Contains(err.Error(), "pid 99999995 fd 4") {
		t.Fatalf("Bind = %v, want the original companion name held open", err)
	}
}

func TestUnreadableProcessEnvironmentFailsClosed(t *testing.T) {
	ctx := context.Background()
	f := sessionFixture(t, true)
	f.rule.Mentions = []string{sessionID}
	// procfs refuses another user's environ; a directory fails the same way.
	fakeProcess(t, f, "99999997", map[string][]byte{"environ": nil})
	if _, err := Inspect(ctx, f.rule, f.scope); err == nil || !strings.Contains(err.Error(), "[]; 1 process(es) could not be inspected") {
		t.Fatalf("Inspect = %v, want the uninspectable process to refuse", err)
	}
	// Files that vanished with an exiting process are not counted.
	if err := os.RemoveAll(filepath.Join(f.home, "proc", "99999997", "environ")); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(ctx, f.rule, f.scope); err != nil {
		t.Fatalf("Inspect with an exited process: %v", err)
	}
}

// A procfs that cannot be listed proves nothing about live use: archiving
// and binding both refuse rather than reading it as "no process".
func TestUnlistableProcfsFailsClosed(t *testing.T) {
	ctx := context.Background()
	f := sessionFixture(t, true)
	f.rule.Mentions = []string{sessionID}
	_, binding, err := Create(ctx, f.rule, f.scope, allow)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.rule = pin(f.rule, binding)
	f.scope.ProcRoot = filepath.Join(f.home, "no-procfs")
	if _, err := Inspect(ctx, f.rule, f.scope); err == nil || !strings.Contains(err.Error(), "live process check") {
		t.Fatalf("Inspect = %v, want an unlistable procfs to refuse", err)
	}
	if _, err := Bind(ctx, f.rule, f.scope, f.source, true); err == nil || !strings.Contains(err.Error(), "live process check") {
		t.Fatalf("Bind = %v, want an unlistable procfs to refuse", err)
	}
}
