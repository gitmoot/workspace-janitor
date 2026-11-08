//go:build linux

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// kindResult decodes one entry of the public cycle report's cache_trims.
type kindResult struct {
	Status      string   `json:"status"`
	Kind        string   `json:"kind"`
	SizeBefore  *int64   `json:"size_before_bytes"`
	SizeAfter   *int64   `json:"size_after_bytes"`
	Reclaimed   *int64   `json:"reclaimed_bytes"`
	ActiveUsers []string `json:"active_users"`
	Error       string   `json:"error"`
}

// fakeTool writes an executable that logs `name|argv|GOMODCACHE=...` to the
// fixture's call log and then runs body.
func (x *trimFixture) fakeTool(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(x.home, "bin", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nprintf '%s|%s|GOMODCACHE=%s\\n' \"" + name + "\" \"$*\" \"$GOMODCACHE\" >> " + x.log + "\n" + body
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// cycleTrims runs `janitor cycle` with the given cache_trims entries and
// returns the reported trims and the exit code.
func (x *trimFixture) cycleTrims(t *testing.T, trims string) ([]kindResult, ExitCode) {
	t.Helper()
	x.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\ncollectors:\n  deep_size: false\n  git: false\n  processes: false\n  services: false\n  proc_root: %s\nprevention:\n  min_free_percent: 0\n  cache_trims:\n%s", x.root, x.proc, trims))
	out, stderr, code := x.run(t, "cycle")
	var report struct {
		CacheTrims []kindResult `json:"cache_trims"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil || len(report.CacheTrims) != 1 {
		t.Fatalf("cycle report without one cache trim (exit %d): %s %s", code, out, stderr)
	}
	return report.CacheTrims, code
}

// fakeDocker is a daemon whose reclaimable image bytes are read from a file;
// an image prune empties them.
func (x *trimFixture) fakeDocker(t *testing.T, reclaimable string) string {
	t.Helper()
	state := filepath.Join(x.home, "reclaimable")
	if err := os.WriteFile(state, []byte(reclaimable), 0o600); err != nil {
		t.Fatal(err)
	}
	return x.fakeTool(t, "docker", `case "$1 $2" in
"info --format") echo /var/lib/docker ;;
"system df")
  printf '{"Active":"1","Reclaimable":"%s (80%%)","Size":"24.16GB","TotalCount":"3","Type":"Images"}\n' "$(cat `+state+`)"
  printf '{"Active":"2","Reclaimable":"9GB (99%%)","Size":"9GB","TotalCount":"2","Type":"Containers"}\n'
  printf '{"Active":"0","Reclaimable":"7GB","Size":"7GB","TotalCount":"1","Type":"Build Cache"}\n' ;;
"image prune") echo 0B > `+state+`; echo "Total reclaimed space: 2.5GB" ;;
esac
`)
}

func dockerImagesTrim(binary, extra string) string {
	return fmt.Sprintf("    - kind: docker-images\n      binary: %s\n      min_age: 168h\n%s", binary, extra)
}

// docker-images prunes old unused images with exactly the official command,
// only while Docker reports more reclaimable image bytes than max_bytes, and
// reports what Docker reclaimed.
func TestDockerImagesTrimPrunesOnlyOldUnusedImagesOverItsBound(t *testing.T) {
	x := newTrimFixture(t)
	docker := x.fakeDocker(t, "2.5GB")
	trims, code := x.cycleTrims(t, dockerImagesTrim(docker, "      max_bytes: 1000000000\n"))
	trim := trims[0]
	if code != ExitOK || trim.Status != "trimmed" || trim.SizeBefore == nil || *trim.SizeBefore != 2500000000 ||
		trim.Reclaimed == nil || *trim.Reclaimed != 2500000000 {
		t.Fatalf("docker-images over its bound not pruned as reported: exit %d %+v", code, trim)
	}
	want := []string{
		"docker|info --format {{.DockerRootDir}}|GOMODCACHE=",
		"docker|system df --format json|GOMODCACHE=",
		"docker|image prune --all --force --filter until=168h|GOMODCACHE=",
		"docker|system df --format json|GOMODCACHE=",
	}
	if got := x.calls(t); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("docker commands:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// At or under its bound nothing is pruned.
	if err := os.WriteFile(filepath.Join(x.home, "reclaimable"), []byte("1GB"), 0o600); err != nil {
		t.Fatal(err)
	}
	if trims, _ := x.cycleTrims(t, dockerImagesTrim(docker, "      max_bytes: 1000000000\n")); trims[0].Status != "under_bound" {
		t.Fatalf("docker-images at its bound: %+v", trims[0])
	}
	for _, call := range x.calls(t)[len(want):] {
		if strings.Contains(call, "prune") {
			t.Fatalf("pruned at the bound: %s", call)
		}
	}
	// Without max_bytes every run prunes.
	if trims, _ := x.cycleTrims(t, dockerImagesTrim(docker, "")); trims[0].Status != "trimmed" {
		t.Fatalf("docker-images without max_bytes not pruned: %+v", trims[0])
	}
}

// An image build or pull postpones the image prune; other Docker clients do
// not.
func TestDockerImagesTrimWaitsForBuildsAndPulls(t *testing.T) {
	for name, tc := range map[string]struct {
		argv []string
		busy bool
	}{
		"docker pull":         {[]string{"/usr/bin/docker", "pull", "nginx:1.27"}, true},
		"docker image pull":   {[]string{"docker", "image", "pull", "nginx"}, true},
		"docker compose pull": {[]string{"/usr/bin/docker", "compose", "-f", "c.yml", "pull"}, true},
		"docker-compose pull": {[]string{"/usr/local/bin/docker-compose", "pull"}, true},
		"buildx build":        {[]string{"/usr/bin/docker", "buildx", "build", "-t", "app", "."}, true},
		"docker run":          {[]string{"/usr/bin/docker", "run", "--rm", "alpine"}, false},
		"docker compose up":   {[]string{"/usr/bin/docker", "compose", "up", "-d"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			x := newTrimFixture(t)
			docker := x.fakeDocker(t, "30GB")
			x.process(t, "200", tc.argv...)
			trim := func() kindResult { trims, _ := x.cycleTrims(t, dockerImagesTrim(docker, "")); return trims[0] }()
			pruned := false
			for _, call := range x.calls(t) {
				pruned = pruned || strings.Contains(call, "image prune")
			}
			if tc.busy && (trim.Status != "skipped_in_use" || len(trim.ActiveUsers) == 0 || pruned) {
				t.Fatalf("images pruned during %s: %+v %v", name, trim, x.calls(t))
			}
			if !tc.busy && (trim.Status != "trimmed" || !pruned) {
				t.Fatalf("%s blocked the image prune: %+v", name, trim)
			}
		})
	}
}

// A docker-images trim is checked against the data root the daemon
// reports, like docker-builder.
func TestDockerImagesTrimRefusedWhenItsDataRootIsArchiveOnly(t *testing.T) {
	x := newTrimFixture(t)
	relocated := filepath.Join(x.root, "docker-data")
	if err := os.MkdirAll(relocated, 0o700); err != nil {
		t.Fatal(err)
	}
	docker := x.fakeTool(t, "docker", "if [ \"$1\" = info ]; then echo "+relocated+"; fi\n")
	x.writePolicy(t, fmt.Sprintf("roots:\n  - path: %s\n    archive_only: true\ncollectors:\n  deep_size: false\n  git: false\n  processes: false\n  services: false\n  proc_root: %s\nprevention:\n  min_free_percent: 0\n  cache_trims:\n%s", x.root, x.proc, dockerImagesTrim(docker, "")))
	_, _, _ = x.run(t, "cycle")
	for _, call := range x.calls(t) {
		if !strings.HasPrefix(call, "docker|info ") {
			t.Fatalf("docker ran more than its data-root query for an archive_only data root: %v", x.calls(t))
		}
	}
}

// containerd's root is its config file's top-level `root`, else the default;
// an unreadable config fails closed.
func TestContainerdRootFollowsItsConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		path := filepath.Join(dir, "config.toml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for body, want := range map[string]string{
		"version = 2\nroot = \"/srv/containerd\" # moved\n":        "/srv/containerd",
		"disabled_plugins = [\"cri\"]\n":                           "/var/lib/containerd",
		"[plugins.\"io.containerd.grpc.v1.cri\"]\nroot = \"/x\"\n": "/var/lib/containerd",
	} {
		if got, err := containerdRoot(write(body)); err != nil || got != want {
			t.Errorf("containerdRoot(%q) = %q, %v; want %q", body, got, err, want)
		}
	}
	if got, err := containerdRoot(filepath.Join(dir, "absent.toml")); err != nil || got != "/var/lib/containerd" {
		t.Errorf("missing config: %q, %v", got, err)
	}
	if _, err := containerdRoot(write("root = \"relative\"\n")); err == nil {
		t.Error("relative containerd root accepted")
	}
	if _, err := containerdRoot(dir); err == nil {
		t.Error("unreadable containerd config accepted")
	}
}

// goModFixture is a trim fixture whose module cache is <home>/modhome/go/pkg/mod,
// the default for HOME=<home>/modhome, filled over its bound.
func goModFixture(t *testing.T) (*trimFixture, string, string) {
	t.Helper()
	x := newTrimFixture(t)
	modcache := filepath.Join(x.home, "modhome", "go", "pkg", "mod")
	if err := os.MkdirAll(filepath.Join(modcache, "example.com", "m@v1.0.0"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modcache, "example.com", "m@v1.0.0", "big.go"), make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	gobin := x.fakeTool(t, "go", "rm -rf \"$GOMODCACHE\"\n")
	trim := fmt.Sprintf("    - kind: go-mod\n      path: %s\n      binary: %s\n      max_bytes: 65536\n", modcache, gobin)
	return x, modcache, trim
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Without users the module cache is cleaned with the official command for
// exactly that GOMODCACHE.
func TestGoModTrimCleansAnUnusedModuleCache(t *testing.T) {
	x, modcache, trim := goModFixture(t)
	trims, code := x.cycleTrims(t, trim)
	if code != ExitOK || trims[0].Status != "trimmed" || trims[0].Reclaimed == nil || *trims[0].Reclaimed < 1<<20 {
		t.Fatalf("go-mod not trimmed: exit %d %+v", code, trims[0])
	}
	if got, want := strings.Join(x.calls(t), "\n"), "go|clean -modcache|GOMODCACHE="+modcache; got != want {
		t.Fatalf("go commands %q, want %q", got, want)
	}
}

// A go command or gopls whose module cache resolves to the trimmed one, by
// any of Go's sources, blocks the trim; so does one whose cache cannot be
// determined.
func TestGoModTrimWaitsForProcessesUsingThisModCache(t *testing.T) {
	for _, name := range []string{"explicit GOMODCACHE", "first GOPATH entry", "default HOME/go", "env file GOMODCACHE",
		"env file GOPATH", "GOROOT go.env GOPATH", "env-file GOMODCACHE over process GOPATH", "no HOME", "relative GOENV",
		"empty GOPATH entry", "toolchain run from the cache"} {
		t.Run(name, func(t *testing.T) {
			x, modcache, trim := goModFixture(t)
			gopath := filepath.Dir(filepath.Dir(modcache))
			user := filepath.Join(x.home, "user")
			env := []string{"HOME=" + user}
			argv := []string{"/usr/local/bin/gopls", "serve"}
			switch name {
			case "explicit GOMODCACHE":
				env = append(env, "GOMODCACHE="+modcache)
			case "first GOPATH entry":
				env = append(env, "GOPATH="+gopath+":"+filepath.Join(x.home, "second"))
				argv = []string{"/usr/bin/go", "build", "./..."}
			case "default HOME/go":
				env = []string{"HOME=" + filepath.Join(x.home, "modhome")}
			case "env file GOMODCACHE":
				writeFile(t, filepath.Join(user, ".config", "go", "env"), "GOMODCACHE="+modcache+"\n")
			case "env file GOPATH":
				writeFile(t, filepath.Join(user, ".config", "go", "env"), "GOPATH="+gopath+"\n")
			case "GOROOT go.env GOPATH":
				writeFile(t, filepath.Join(x.home, "goroot", "go.env"), "GOPATH="+gopath+"\n")
				argv = []string{"/usr/bin/go", "mod", "download"}
			case "env-file GOMODCACHE over process GOPATH":
				// GOMODCACHE from any source wins over a GOPATH-derived default.
				other := filepath.Join(x.home, "other")
				writeFile(t, filepath.Join(user, ".config", "go", "env"), "GOMODCACHE="+modcache+"\n")
				env = append(env, "GOPATH="+other)
			case "no HOME":
				env = []string{"PATH=/usr/bin"}
			case "relative GOENV":
				env = append(env, "GOENV=goenv")
			case "empty GOPATH entry":
				env = append(env, "GOPATH=:"+gopath)
			case "toolchain run from the cache":
				// A process with another module cache that executes a
				// toolchain Go downloaded into this one.
				env = append(env, "GOMODCACHE="+filepath.Join(x.home, "other"))
				argv = []string{"/usr/bin/sleep", "60"}
			}
			x.processEnv(t, "100", env, argv...)
			if name == "toolchain run from the cache" {
				exe := filepath.Join(x.proc, "100", "exe")
				if err := os.Remove(exe); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(modcache, "golang.org", "toolchain@v0.0.1-go1.25.0.linux-amd64", "bin", "go"), exe); err != nil {
					t.Fatal(err)
				}
			}
			trims, _ := x.cycleTrims(t, trim)
			if trims[0].Status != "skipped_in_use" || len(trims[0].ActiveUsers) == 0 {
				t.Fatalf("module cache trimmed although %s uses it: %+v", name, trims[0])
			}
			if calls := x.calls(t); len(calls) != 0 {
				t.Fatalf("go clean ran: %v", calls)
			}
		})
	}
}

// Go processes and gopls whose module cache is elsewhere do not block it.
func TestGoModTrimIgnoresProcessesWithAnotherModCache(t *testing.T) {
	x, modcache, trim := goModFixture(t)
	other := filepath.Join(x.home, "other")
	user := filepath.Join(x.home, "user")
	writeFile(t, filepath.Join(user, ".config", "go", "env"), "GOMODCACHE="+modcache+"\n")
	// The process GOMODCACHE wins over the env file naming this cache.
	x.processEnv(t, "100", []string{"HOME=" + user, "GOMODCACHE=" + other}, "/usr/local/bin/gopls")
	// GOPATH elsewhere moves the default module cache with it.
	x.processEnv(t, "101", []string{"HOME=" + filepath.Join(x.home, "h101"), "GOPATH=" + other}, "/usr/bin/go", "build", "./...")
	// Another HOME's default module cache.
	x.processEnv(t, "102", []string{"HOME=" + other}, "/usr/bin/go", "test", "./...")
	// The env file's GOMODCACHE wins over HOME's default.
	writeFile(t, filepath.Join(x.home, ".config", "go", "env"), "GOMODCACHE="+other+"\n")
	x.processEnv(t, "103", []string{"HOME=" + x.home}, "/usr/bin/go", "run", ".")
	trims, code := x.cycleTrims(t, trim)
	if code != ExitOK || trims[0].Status != "trimmed" {
		t.Fatalf("go-mod blocked by processes using other module caches: %+v", trims[0])
	}
}

// pnpm-store prunes the store with pnpm's own command and waits while any
// pnpm runs, however pnpm was installed.
func TestPnpmStoreTrimWaitsForPnpm(t *testing.T) {
	for name, argv := range map[string][]string{
		"none":            nil,
		"pnpm executable": {"/root/.local/share/pnpm/pnpm", "install"},
		"node script":     {"node", "/root/.nvm/versions/node/v22.23.2/bin/pnpm", "run", "build"},
		"corepack":        {"/usr/bin/node", "/usr/lib/node_modules/corepack/dist/pnpm.js", "add", "x"},
		"pnpx":            {"node", "/usr/local/bin/pnpx", "create-vite"},
	} {
		t.Run(name, func(t *testing.T) {
			x := newTrimFixture(t)
			store := filepath.Join(x.home, "pnpm-store", "v11")
			writeFile(t, filepath.Join(store, "files", "ab", "blob"), string(make([]byte, 1<<20)))
			pnpm := x.fakeTool(t, "pnpm", "if [ \"$2\" = path ]; then echo \"$4\"; fi\nif [ \"$2\" = prune ]; then rm -rf \"$4\"/files; fi\n")
			if argv != nil {
				x.process(t, "300", argv...)
			}
			trims, code := x.cycleTrims(t, fmt.Sprintf("    - kind: pnpm-store\n      path: %s\n      binary: %s\n      max_bytes: 65536\n", store, pnpm))
			var pruned bool
			for _, call := range x.calls(t) {
				pruned = pruned || strings.HasPrefix(call, "pnpm|store prune")
			}
			if argv != nil {
				if trims[0].Status != "skipped_in_use" || pruned {
					t.Fatalf("store pruned while %s runs: %+v %v", name, trims[0], x.calls(t))
				}
				return
			}
			if code != ExitOK || trims[0].Status != "trimmed" || trims[0].Reclaimed == nil || *trims[0].Reclaimed < 1<<20 {
				t.Fatalf("unused store not pruned: exit %d %+v", code, trims[0])
			}
			if got := x.calls(t); got[len(got)-1] != "pnpm|store prune --store-dir "+store+"|GOMODCACHE=" {
				t.Fatalf("pnpm commands: %v", got)
			}
		})
	}
}

// pnpm appends its layout version to a --store-dir that lacks it; a path
// pnpm would not prune itself fails instead of being measured forever.
func TestPnpmStoreTrimRefusesAStoreDirPnpmWouldNotPrune(t *testing.T) {
	x := newTrimFixture(t)
	store := filepath.Join(x.home, "pnpm-store")
	writeFile(t, filepath.Join(store, "v10", "files", "ab", "blob"), string(make([]byte, 1<<20)))
	pnpm := x.fakeTool(t, "pnpm", "if [ \"$2\" = path ]; then echo \"$4/v11\"; fi\n")
	trims, code := x.cycleTrims(t, fmt.Sprintf("    - kind: pnpm-store\n      path: %s\n      binary: %s\n      max_bytes: 65536\n", store, pnpm))
	if code == ExitOK || trims[0].Status != "failed" || !strings.Contains(trims[0].Error, "v11") {
		t.Fatalf("mismatched pnpm store accepted: exit %d %+v", code, trims[0])
	}
	for _, call := range x.calls(t) {
		if strings.Contains(call, "prune") {
			t.Fatalf("pnpm pruned another store: %v", x.calls(t))
		}
	}
}
