package plan

import (
	"path/filepath"
	"strings"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

// Adapter describes a recognized cache or generated output root. Commands are
// display-only guidance, never authorization to run a process or remove a path.
type Adapter struct {
	Provider        string
	Class           core.ArtifactClass
	Rebuild         string
	OfficialCommand []string
}

// DescribeAdapter recognizes the selected root of a provider store, not an
// arbitrary descendant whose basename happens to look like a cache. Root is
// the inventory boundary; no filesystem lookups or process execution occur.
func DescribeAdapter(entry core.Entry, _ config.Policy) (Adapter, bool) {
	if entry.Kind != core.EntryKindDirectory || !core.IsCanonicalPath(entry.Path) ||
		!core.IsCanonicalPath(entry.Root) || !core.PathWithin(entry.Path, entry.Root) {
		return Adapter{}, false
	}
	rel, err := filepath.Rel(entry.Root, entry.Path)
	if err != nil {
		return Adapter{}, false
	}
	if rel == "." {
		// A scan can select the store itself as its inventory root. In that
		// case its anchored path still has to match a known complete layout.
		rel = selectedStoreLayout(entry.Path)
	}
	// Only complete store roots have a known owner. A nested name in a
	// different cache, or a package within a store, is not a store root.
	cache := func(provider, rebuild string, command ...string) (Adapter, bool) {
		return Adapter{Provider: provider, Class: core.ClassCache, Rebuild: rebuild,
			OfficialCommand: command}, true
	}
	switch rel {
	case ".cache/uv", ".uv-cache":
		return cache("uv", "cached distributions may need to be downloaded or rebuilt", "uv", "cache", "prune", "--cache-dir", entry.Path, "--offline")
	case ".npm":
		return cache("npm", "packages may need to be fetched again", "npm", "cache", "verify", "--cache", entry.Path)
	case ".local/share/pnpm/store", ".pnpm-store":
		return cache("pnpm", "unreferenced packages may need to be fetched again", "pnpm", "--store-dir", entry.Path, "store", "prune")
	case ".bun/install/cache", ".cache/bun":
		return cache("bun", "cached packages may need to be fetched again")
	case ".gradle/caches":
		return cache("gradle", "dependencies and build artifacts may need to be fetched or rebuilt")
	case ".cache/go-build":
		return cache("go-build", "Go build outputs will be rebuilt")
	case "go/pkg/mod", "pkg/mod":
		return cache("go-module", "Go modules may need to be fetched again")
	case ".cache/ms-playwright":
		return cache("playwright", "browser binaries may need to be installed again")
	case ".cache/puppeteer":
		return cache("puppeteer", "browser binaries may need to be installed again")
	}

	// Project-local stores can be beneath a workspace's repos/<project>.
	// Do not promote similarly named trees inside an unrelated cache.
	parts := strings.Split(rel, string(filepath.Separator))
	projectPrefix := func(prefix []string) bool {
		switch len(prefix) {
		case 1:
			return prefix[0] != "" && !strings.HasPrefix(prefix[0], ".") && prefix[0] != "node_modules"
		case 2:
			switch prefix[0] {
			case "repos", "projects", "workspaces":
				return prefix[1] != "" && !strings.HasPrefix(prefix[1], ".")
			}
		}
		return false
	}
	if len(parts) >= 2 && projectPrefix(parts[:len(parts)-1]) {
		switch parts[len(parts)-1] {
		case ".uv-cache":
			return cache("uv", "cached distributions may need to be downloaded or rebuilt", "uv", "cache", "prune", "--cache-dir", entry.Path, "--offline")
		case ".pnpm-store":
			return cache("pnpm", "unreferenced packages may need to be fetched again", "pnpm", "--store-dir", entry.Path, "store", "prune")
		}
	}
	if len(parts) >= 3 && parts[len(parts)-2] == ".gradle" && parts[len(parts)-1] == "caches" &&
		projectPrefix(parts[:len(parts)-2]) {
		return cache("gradle", "dependencies and build artifacts may need to be fetched or rebuilt")
	}

	// Generated names are meaningful only at the output root of a selected
	// project, not inside an existing cache or another generated directory.
	provider := filepath.Base(rel)
	adapter := Adapter{Provider: provider, Class: core.ClassGeneratedArtifact}
	switch provider {
	case "node_modules":
		adapter.Provider = "node-modules"
		adapter.Rebuild = "project dependencies must be installed again"
	case ".venv", "venv":
		adapter.Provider = "python-venv"
		adapter.Rebuild = "the Python environment and its dependencies must be recreated"
	case "dist", "build", "coverage":
		adapter.Rebuild = "generated output must be rebuilt or tests rerun"
	default:
		return Adapter{}, false
	}
	parts = strings.Split(rel, string(filepath.Separator))
	if len(parts) > 3 {
		return Adapter{}, false
	}
	for _, part := range parts[:len(parts)-1] {
		switch part {
		case "node_modules", "dist", "build", "coverage", ".venv", "venv", ".cache", ".gradle", ".npm", ".bun", ".gitmoot":
			return Adapter{}, false
		}
	}
	// Two levels below the inventory root represent a project under a
	// workspace collection (for example repos/app/dist), not a free-form
	// descendant tree.
	if len(parts) == 3 {
		switch parts[0] {
		case "repos", "projects", "workspaces", "src", "code":
		default:
			return Adapter{}, false
		}
	}
	return adapter, true
}

func selectedStoreLayout(path string) string {
	for _, layout := range []string{
		".cache/uv", ".uv-cache", ".npm", ".local/share/pnpm/store",
		".pnpm-store", ".bun/install/cache", ".cache/bun", ".gradle/caches",
		".cache/go-build", "go/pkg/mod", "pkg/mod", ".cache/ms-playwright",
		".cache/puppeteer",
	} {
		if strings.HasSuffix(path, string(filepath.Separator)+filepath.FromSlash(layout)) {
			return filepath.FromSlash(layout)
		}
	}
	switch filepath.Base(path) {
	case "node_modules", ".venv", "venv", "dist", "build", "coverage":
		return filepath.Base(path)
	}
	return "."
}
