//go:build linux

package cli

import (
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdvisoryKeyRejectsUnsafeFilesAndAmbiguousCredentials(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "key.env")
	for _, tc := range []struct {
		name, contents string
		mode           os.FileMode
		want           bool
	}{
		{"isolated variable", "OPENROUTER_API_KEY_EXTRA=ignored\nOTHER=ignored\nOPENROUTER_API_KEY=synthetic-only\n", 0600, true},
		{"world-readable", "OPENROUTER_API_KEY=synthetic-only\n", 0644, false},
		{"duplicate", "OPENROUTER_API_KEY=synthetic-only\nOPENROUTER_API_KEY=another\n", 0600, false},
		{"malformed", "OPENROUTER_API_KEY =synthetic-only\nOPENROUTER_API_KEY=valid\n", 0600, false},
		{"shell value", "OPENROUTER_API_KEY=$(unsafe)\n", 0600, false},
		{"executable mode", "OPENROUTER_API_KEY=synthetic-only\n", 0700, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.contents), tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			key, err := readAdvisoryKey(path)
			if (err == nil) != tc.want {
				t.Fatalf("key accepted=%v, want %v", err == nil, tc.want)
			}
			if tc.want && key != "synthetic-only" {
				t.Fatal("read wrong variable")
			}
			if err != nil && (strings.Contains(err.Error(), "synthetic-only") || strings.Contains(err.Error(), path)) {
				t.Fatal("key or path leaked in error")
			}
		})
	}
	outside := filepath.Join(base, "outside.env")
	if err := os.WriteFile(outside, []byte("OPENROUTER_API_KEY=synthetic-only\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := readAdvisoryKey(path); err == nil {
		t.Fatal("symlinked key file admitted")
	}
	parent := filepath.Join(base, "link")
	if err := os.Symlink(base, parent); err != nil {
		t.Fatal(err)
	}
	if _, err := readAdvisoryKey(filepath.Join(parent, "outside.env")); err == nil {
		t.Fatal("symlinked parent admitted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAdvisoryKey(path); err == nil {
		t.Fatal("special key file admitted")
	}
}
