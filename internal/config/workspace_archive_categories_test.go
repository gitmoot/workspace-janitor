package config

import (
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

const categoryBase = `roots:
  - path: /srv/work
  - path: /srv/observed
    report_only: true
  - path: /srv/scratch
protect:
  paths: [/srv/archive, /srv/work/protected]
`

func categoryEntry(name, kind, root string) string {
	return "  - name: " + name + "\n    kind: " + kind + "\n    roots: [" + root + "]\n    archive:\n      directory: /srv/archive/" + name + "\n"
}

func TestWorkspaceArchiveCategoriesAreOptInAndDefaultBounded(t *testing.T) {
	policy, err := parse(t, fixturePaths(t), categoryBase)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if policy.WorkspaceArchiveCategories == nil || len(policy.WorkspaceArchiveCategories) != 0 {
		t.Fatalf("categories must default to an empty list: %+v", policy.WorkspaceArchiveCategories)
	}
	if len(DefaultPolicy(fixturePaths(t)).WorkspaceArchiveCategories) != 0 {
		t.Fatal("built-in defaults enable an archive category")
	}
	doc := categoryBase + "workspace_archive_categories:\n" +
		categoryEntry("merged", "merged_worktrees", "/srv/work") +
		categoryEntry("clones", "pushed_clones", "/srv/work") + "    idle: 45d\n    local_retention: 90d\n" +
		categoryEntry("scratch", "root_scratch", "/srv/scratch") + "    local_retention: none\n    max_items_per_cycle: 200\n    max_bytes_per_item: 1024\n"
	policy, err = parse(t, fixturePaths(t), doc)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	merged, clones, scratch := policy.WorkspaceArchiveCategories[0], policy.WorkspaceArchiveCategories[1], policy.WorkspaceArchiveCategories[2]
	if merged.Idle.Duration() != 14*24*time.Hour || merged.LocalRetention != core.Retention30Days ||
		merged.MaxItemsPerCycle != DefaultCategoryMaxItemsPerCycle || merged.MaxBytesPerItem != DefaultCategoryMaxBytesPerItem {
		t.Fatalf("merged_worktrees defaults not applied: %+v", merged)
	}
	if clones.Idle.Duration() != 45*24*time.Hour || clones.LocalRetention != core.Retention90Days || clones.Idle.String() != "45d" {
		t.Fatalf("pushed_clones settings not decoded: %+v", clones)
	}
	if scratch.Idle.Duration() != 30*24*time.Hour || scratch.LocalRetention != core.RetentionNone || scratch.MaxItemsPerCycle != 200 || scratch.MaxBytesPerItem != 1024 {
		t.Fatalf("root_scratch settings not decoded: %+v", scratch)
	}
}

func TestWorkspaceArchiveCategoriesRefuseUnsafeSettings(t *testing.T) {
	for _, tc := range []struct {
		name, doc, field, fragment string
	}{
		{"short merged idle", categoryEntry("m", "merged_worktrees", "/srv/work") + "    idle: 13d\n", "workspace_archive_categories[0].idle", "at least"},
		{"short clone idle", categoryEntry("c", "pushed_clones", "/srv/work") + "    idle: 29d\n", "workspace_archive_categories[0].idle", "at least"},
		{"short scratch idle", categoryEntry("s", "root_scratch", "/srv/scratch") + "    idle: 336h\n", "workspace_archive_categories[0].idle", "at least"},
		{"unknown kind", categoryEntry("x", "everything", "/srv/work"), "workspace_archive_categories[0].kind", "must be"},
		{"unconfigured root", categoryEntry("s", "root_scratch", "/srv/elsewhere"), "workspace_archive_categories[0].roots[0]", "configured inventory root"},
		{"nested non-root", categoryEntry("s", "root_scratch", "/srv/work/sub"), "workspace_archive_categories[0].roots[0]", "configured inventory root"},
		{"report only root", categoryEntry("s", "root_scratch", "/srv/observed"), "workspace_archive_categories[0].roots[0]", "report_only"},
		{"unprotected archive", strings.Replace(categoryEntry("s", "root_scratch", "/srv/scratch"), "/srv/archive/s", "/srv/unprotected", 1), "workspace_archive_categories[0].archive.directory", "protect.paths"},
		{"archive inside root", strings.Replace(categoryEntry("s", "root_scratch", "/srv/scratch"), "/srv/archive/s", "/srv/work/protected/archive", 1), "workspace_archive_categories[0].archive.directory", "outside every inventory root"},
		{"retention 7d", categoryEntry("s", "root_scratch", "/srv/scratch") + "    local_retention: 7d\n", "workspace_archive_categories[0].local_retention", "none, 30d or 90d"},
		{"permanent retention", categoryEntry("s", "root_scratch", "/srv/scratch") + "    local_retention: permanent\n", "workspace_archive_categories[0].local_retention", "none, 30d or 90d"},
		{"too many items", categoryEntry("s", "root_scratch", "/srv/scratch") + "    max_items_per_cycle: 201\n", "workspace_archive_categories[0].max_items_per_cycle", "between 1 and 200"},
		{"negative bytes", categoryEntry("s", "root_scratch", "/srv/scratch") + "    max_bytes_per_item: -1\n", "workspace_archive_categories[0].max_bytes_per_item", "greater than zero"},
		{"duplicate name", categoryEntry("s", "root_scratch", "/srv/scratch") + categoryEntry("s", "pushed_clones", "/srv/work"), "workspace_archive_categories[1].name", "duplicates"},
		{"duplicate kind and root", categoryEntry("a", "root_scratch", "/srv/scratch") + categoryEntry("b", "root_scratch", "/srv/scratch"), "workspace_archive_categories[1].roots[0]", "one root_scratch category per root"},
		{"bad name", categoryEntry("-bad", "root_scratch", "/srv/scratch"), "workspace_archive_categories[0].name", "letters"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(t, fixturePaths(t), categoryBase+"workspace_archive_categories:\n"+tc.doc)
			requireFieldError(t, err, tc.field, tc.fragment)
		})
	}
	t.Run("collectors required", func(t *testing.T) {
		_, err := parse(t, fixturePaths(t), categoryBase+"collectors:\n  git: false\nworkspace_archive_categories:\n"+categoryEntry("s", "root_scratch", "/srv/scratch"))
		requireFieldError(t, err, "workspace_archive_categories", "Git, process and service collectors")
	})
	t.Run("kept root", func(t *testing.T) {
		_, err := parse(t, fixturePaths(t), categoryBase+"workspace_archive_keep:\n  - path: /srv/scratch\n    owner: seat-b\n    reference: keep-1\nworkspace_archive_categories:\n"+categoryEntry("s", "root_scratch", "/srv/scratch"))
		requireFieldError(t, err, "workspace_archive_categories[0].roots[0]", "workspace_archive_keep")
	})
	t.Run("reserved owner prefix", func(t *testing.T) {
		doc := workspaceArchiveBase + "workspace_archives:\n" + strings.Replace(workspaceArchiveEntry("released-a", "/srv/work/released-a"), "owner: seat-a", "owner: category:scratch", 1)
		_, err := parse(t, fixturePaths(t), doc)
		requireFieldError(t, err, "workspace_archives[0].owner", "reserved")
	})
}

func TestCategoryArchiveRefusalsKeepPolicyScopesLocal(t *testing.T) {
	doc := categoryBase + "workspace_archive_keep:\n  - path: /srv/scratch/kept\n    owner: seat-b\n    reference: keep-1\n" +
		"workspace_archive_categories:\n" + categoryEntry("s", "root_scratch", "/srv/scratch")
	policy, err := parse(t, fixturePaths(t), doc)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if refusals := policy.CategoryArchiveRefusals("/srv/scratch/idle"); len(refusals) != 0 {
		t.Fatalf("plain scratch directory refused: %v", refusals)
	}
	for path, fragment := range map[string]string{
		"/srv/scratch/kept":    "KEEP",
		"/srv/scratch/.config": "dot-named",
		"/srv/scratch/.ssh":    "credential",
		"/srv/work/protected":  "protect.paths",
		"/srv/observed/x":      "report_only",
	} {
		refusals := strings.Join(policy.CategoryArchiveRefusals(path), "\n")
		if !strings.Contains(refusals, fragment) {
			t.Errorf("%s: refusals %q lack %q", path, refusals, fragment)
		}
	}
}
