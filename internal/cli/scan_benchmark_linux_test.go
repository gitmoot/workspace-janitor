//go:build linux

package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gitmoot/workspace-janitor/internal/config"
)

// Each benchmark uses a warm, fixed tree: 64 top-level directories, 16
// subdirectories in each, and four 16-byte files in each subdirectory.
// Top-level scan inspects 64 entries; deep sizing additionally traverses
// 1,024 subdirectories and 4,096 files. Both use the public CLI without
// persistence, Git, process/service probes, network, or file-content reads.
func BenchmarkScanTopLevel(b *testing.B) { benchmarkScan(b, false) }
func BenchmarkScanDeep(b *testing.B)     { benchmarkScan(b, true) }

func benchmarkScan(b *testing.B, deep bool) {
	b.Helper()
	home := b.TempDir()
	root := filepath.Join(home, "workspace")
	for i := 0; i < 64; i++ {
		for j := 0; j < 16; j++ {
			dir := filepath.Join(root, benchName(i), benchName(j))
			if err := os.MkdirAll(dir, 0700); err != nil {
				b.Fatal(err)
			}
			for k := 0; k < 4; k++ {
				if err := os.WriteFile(filepath.Join(dir, benchName(k)), []byte("0123456789abcdef"), 0600); err != nil {
					b.Fatal(err)
				}
			}
		}
	}
	configDir := filepath.Join(home, ".config", config.AppName)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		b.Fatal(err)
	}
	policy := "roots:\n  - path: " + root + "\n    max_depth: 1\ncollectors:\n  git: false\n  processes: false\n  services: false\n"
	if err := os.WriteFile(filepath.Join(configDir, "policy.yaml"), []byte(policy), 0600); err != nil {
		b.Fatal(err)
	}
	args := []string{"scan", "--no-store", "--no-compare", "--no-git", "--no-processes", "--no-services"}
	if deep {
		args = append(args, "--deep-size")
	}
	opts := Options{Args: args, Stdout: io.Discard, Stderr: io.Discard, Lookup: config.MapLookup(map[string]string{config.EnvHome: home})}
	if code := Run(context.Background(), opts); code != ExitOK {
		b.Fatalf("warmup scan exited %d", code)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if code := Run(context.Background(), opts); code != ExitOK {
			b.Fatalf("scan exited %d", code)
		}
	}
}

func benchName(n int) string { return string([]byte{'n', byte('0' + n/10), byte('0' + n%10)}) }
