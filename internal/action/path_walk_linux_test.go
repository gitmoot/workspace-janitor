//go:build linux

package action

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/safety"
)

func TestAnchoredMutationsRejectAncestorSymlink(t *testing.T) {
	for _, operation := range []struct {
		name string
		run  func(string, string, core.FilesystemID) error
	}{
		{"rename", renameNoReplace},
		{"delete", func(path, _ string, id core.FilesystemID) error { return deleteAnchored(path, id) }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			home := t.TempDir()
			outside := filepath.Join(home, "outside")
			if err := os.MkdirAll(filepath.Join(outside, "nested"), 0700); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(outside, "nested", "valuable")
			if err := os.WriteFile(source, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(home, "untrusted-parent")
			if err := os.Symlink(outside, alias); err != nil {
				t.Fatal(err)
			}
			handle, err := safety.Open(source)
			if err != nil {
				t.Fatal(err)
			}
			id := handle.Identity()
			_ = handle.Close()
			destination := filepath.Join(home, "destination")
			if err := operation.run(filepath.Join(alias, "nested", "valuable"), destination, id); err == nil {
				t.Fatal("mutation followed a symlinked ancestor into an unrelated tree")
			}
			if content, err := os.ReadFile(source); err != nil || string(content) != "keep" {
				t.Fatalf("escaped mutation changed original: %q %v", content, err)
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatalf("escaped mutation created destination: %v", err)
			}
		})
	}
}

func TestRenameRejectsDestinationAncestorSymlink(t *testing.T) {
	home := t.TempDir()
	outside := filepath.Join(home, "outside")
	if err := os.MkdirAll(filepath.Join(outside, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(home, "valuable")
	if err := os.WriteFile(source, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(home, "untrusted-parent")
	if err := os.Symlink(outside, alias); err != nil {
		t.Fatal(err)
	}
	handle, err := safety.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	id := handle.Identity()
	_ = handle.Close()
	destination := filepath.Join(alias, "nested", "valuable")
	if err := renameNoReplace(source, destination, id); err == nil {
		t.Fatal("rename followed a symlinked destination ancestor")
	}
	if content, err := os.ReadFile(source); err != nil || string(content) != "keep" {
		t.Fatalf("source changed: %q %v", content, err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "nested", "valuable")); !os.IsNotExist(err) {
		t.Fatalf("destination escaped into unrelated tree: %v", err)
	}
}

// Search-only ancestors are common for shared/private homes. A mutation
// needs read permission on its immediate parent, not every ancestor.
func TestRenameThroughSearchOnlyAncestor(t *testing.T) {
	home := t.TempDir()
	for _, dir := range []string{filepath.Dir(home), home} {
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	restricted := filepath.Join(home, "search-only")
	inner := filepath.Join(restricted, "inner")
	destinationDir := filepath.Join(home, "destination")
	for _, dir := range []string{inner, destinationDir} {
		if err := os.MkdirAll(dir, 0777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0777); err != nil {
			t.Fatal(err)
		}
	}
	source := filepath.Join(inner, "valuable")
	if err := os.WriteFile(source, []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(restricted, 0111); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(destinationDir, "valuable")
	if os.Geteuid() == 0 {
		// go test stores its binary under a private 0700 build directory,
		// inaccessible after dropping privileges. Copy it into the fixture.
		in, err := os.Open(os.Args[0])
		if err != nil {
			t.Fatal(err)
		}
		childPath := filepath.Join(home, "action-child")
		child, err := os.OpenFile(childPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
		if err != nil {
			_ = in.Close()
			t.Fatal(err)
		}
		_, copyErr := io.Copy(child, in)
		closeErr := child.Close()
		_ = in.Close()
		if copyErr != nil || closeErr != nil {
			t.Fatalf("copy child binary: %v, close: %v", copyErr, closeErr)
		}
		cmd := exec.Command(childPath, "-test.run=^TestSearchOnlyRenameChild$")
		cmd.Env = []string{"JANITOR_SEARCH_ONLY_SOURCE=" + source, "JANITOR_SEARCH_ONLY_DEST=" + destination}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("unprivileged rename through search-only ancestor: %v\n%s", err, out)
		}
	} else {
		renameSearchOnly(t, source, destination)
	}
	if _, err := os.Lstat(source); !os.IsNotExist(err) {
		t.Fatalf("source remained after authorized rename: %v", err)
	}
	if content, err := os.ReadFile(destination); err != nil || string(content) != "keep" {
		t.Fatalf("renamed content = %q, %v", content, err)
	}
}

func TestSearchOnlyRenameChild(t *testing.T) {
	source := os.Getenv("JANITOR_SEARCH_ONLY_SOURCE")
	if source == "" {
		return
	}
	renameSearchOnly(t, source, os.Getenv("JANITOR_SEARCH_ONLY_DEST"))
}

func renameSearchOnly(t *testing.T, source, destination string) {
	t.Helper()
	handle, err := safety.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	id := handle.Identity()
	_ = handle.Close()
	if err := renameNoReplace(source, destination, id); err != nil {
		t.Fatal(err)
	}
}
