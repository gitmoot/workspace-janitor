//go:build linux

package workspacearchive

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// archived returns a fixture whose populated workspace has a published,
// pinned archive.
func archived(t *testing.T) (*fixture, Manifest) {
	t.Helper()
	f := newFixture(t)
	f.populate(t)
	m, binding, err := Create(context.Background(), f.rule, f.scope, allow)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.rule = pin(f.rule, binding)
	return f, m
}

func TestBindMatchesUnchangedTreeAndItsQuarantinedCopy(t *testing.T) {
	ctx := context.Background()
	f, m := archived(t)
	for _, full := range []bool{false, true} {
		b, err := Bind(ctx, f.rule, f.scope, f.source, full)
		if err != nil {
			t.Fatalf("Bind(full=%t): %v", full, err)
		}
		if b.Manifest != f.rule.Archive.Manifest || b.ManifestSHA256 != f.rule.Archive.ManifestSHA256 ||
			b.MemberCount != len(m.Members) || len(b.TreeDigest) != 64 || !b.CreatedAt.Equal(m.CreatedAt) {
			t.Fatalf("binding = %+v, manifest created %s with %d members", b, m.CreatedAt, len(m.Members))
		}
	}
	// A quarantine move is a same-filesystem rename; the moved copy still
	// binds, and the original path's live checks still run.
	moved := filepath.Join(f.home, "quarantine", "receipt", "item")
	if err := os.MkdirAll(filepath.Dir(moved), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(f.source, moved); err != nil {
		t.Fatal(err)
	}
	if _, err := Bind(ctx, f.rule, f.scope, moved, true); err != nil {
		t.Fatalf("Bind(quarantined copy): %v", err)
	}
	// A dependent created on the original path after the move still holds it.
	mustSymlink(t, filepath.Join(f.source, "sub"), filepath.Join(f.home, "other", "waits-for-original"))
	if _, err := Bind(ctx, f.rule, f.scope, moved, true); err == nil || !strings.Contains(err.Error(), "external dependents") {
		t.Fatalf("Bind = %v, want external dependent of the original path", err)
	}
}

func TestBindRefusesEveryLocalDifference(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(t *testing.T, f *fixture)
		// detectedWithoutContent is false only for a same-size, same-mtime
		// content change, which only a full binding can see.
		detectedWithoutContent bool
	}{
		"added file": {func(t *testing.T, f *fixture) {
			write(t, filepath.Join(f.source, "sub", "nested", "new.txt"), []byte("new\n"), 0o644)
		}, true},
		"removed file": {func(t *testing.T, f *fixture) {
			if err := os.Remove(filepath.Join(f.source, "sub", "empty")); err != nil {
				t.Fatal(err)
			}
		}, true},
		"mode change": {func(t *testing.T, f *fixture) {
			if err := os.Chmod(filepath.Join(f.source, "README.md"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, true},
		"retargeted symlink": {func(t *testing.T, f *fixture) {
			link := filepath.Join(f.source, "link")
			root, err := os.Stat(f.source)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.Remove(link); err != nil {
				t.Fatal(err)
			}
			if err = os.Symlink("README.md", link); err != nil {
				t.Fatal(err)
			}
			// Keep the root directory's recorded mtime.
			if err = os.Chtimes(f.source, root.ModTime(), root.ModTime()); err != nil {
				t.Fatal(err)
			}
		}, true},
		"same-size content change with restored mtime": {func(t *testing.T, f *fixture) {
			path := filepath.Join(f.source, "sub", "data.bin")
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			file, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = file.WriteAt([]byte("X"), 100); err != nil {
				t.Fatal(err)
			}
			file.Close()
			if err = os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
				t.Fatal(err)
			}
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			f, _ := archived(t)
			tc.change(t, f)
			if _, err := Bind(context.Background(), f.rule, f.scope, f.source, true); err == nil {
				t.Fatal("full Bind accepted a local tree that differs from its archive")
			}
			_, err := Bind(context.Background(), f.rule, f.scope, f.source, false)
			if tc.detectedWithoutContent && err == nil {
				t.Fatal("metadata Bind accepted a local tree that differs from its archive")
			}
			if !tc.detectedWithoutContent && err != nil {
				t.Fatalf("metadata Bind compares content it must not read: %v", err)
			}
		})
	}
}

func TestBindRefusesUnavailableCorruptOrUnpinnedArchive(t *testing.T) {
	ctx := context.Background()
	f, _ := archived(t)
	unpinned := f.rule
	unpinned.Archive.Manifest, unpinned.Archive.ManifestSHA256 = "", ""
	if _, err := Bind(ctx, unpinned, f.scope, f.source, false); err == nil || !strings.Contains(err.Error(), "no exact verified workspace archive manifest is pinned") {
		t.Fatalf("Bind(unpinned) = %v", err)
	}
	wrongPin := f.rule
	wrongPin.Archive.ManifestSHA256 = strings.Repeat("0", 64)
	if _, err := Bind(ctx, wrongPin, f.scope, f.source, false); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("Bind(wrong pin) = %v", err)
	}
	tarPath := filepath.Join(f.archive, "released.tar")
	file, err := os.OpenFile(tarPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteAt([]byte("X"), 1024+20); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if _, err := Bind(ctx, f.rule, f.scope, f.source, true); err == nil {
		t.Fatal("full Bind accepted a corrupted archive")
	}
	if err := os.Rename(tarPath, tarPath+".offline"); err != nil {
		t.Fatal(err)
	}
	if _, err := Bind(ctx, f.rule, f.scope, f.source, false); err == nil {
		t.Fatal("Bind accepted a missing archive")
	}
}

func TestBindRepeatsSourceRefusals(t *testing.T) {
	ctx := context.Background()
	t.Run("external dependent", func(t *testing.T) {
		f, _ := archived(t)
		mustSymlink(t, filepath.Join(f.source, "README.md"), filepath.Join(f.home, "other", "readme"))
		if _, err := Bind(ctx, f.rule, f.scope, f.source, true); err == nil || !strings.Contains(err.Error(), "external dependents") {
			t.Fatalf("Bind = %v, want external dependent refusal", err)
		}
	})
	t.Run("secret-like name pattern", func(t *testing.T) {
		f, _ := archived(t)
		f.scope.SensitiveNames = []string{"data.bin"}
		if _, err := Bind(ctx, f.rule, f.scope, f.source, true); err == nil || !strings.Contains(err.Error(), "secret-like") {
			t.Fatalf("Bind = %v, want secret-like refusal", err)
		}
	})
	t.Run("live process", func(t *testing.T) {
		if _, err := exec.LookPath("sleep"); err != nil {
			t.Skip("sleep is unavailable")
		}
		f, _ := archived(t)
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
		if _, err := Bind(ctx, f.rule, f.scope, f.source, true); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("pid %d cwd", cmd.Process.Pid)) {
			t.Fatalf("Bind = %v, want live reference", err)
		}
	})
}
