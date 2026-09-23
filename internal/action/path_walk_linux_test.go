//go:build linux

package action

import (
	"os"
	"path/filepath"
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
