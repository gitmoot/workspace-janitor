package config

import (
	"strings"
	"testing"
	"time"
)

const reportBase = categoryBase + "report:\n  enabled: true\n  roots: [/srv/work]\n  coordinator_role: coordinator\n"

// Existing installs must not change: without a report section the report is
// off and a release can never archive anything.
func TestStaleReportDefaultsChangeNothing(t *testing.T) {
	for name, policy := range map[string]Policy{"built-in": DefaultPolicy(fixturePaths(t))} {
		if policy.Report.Enabled || policy.Report.ReleaseAction != StaleReleaseNone || policy.Report.ArchivesReleases() || policy.HasArchiveCategories() {
			t.Fatalf("%s defaults enable the report or release archiving: %+v", name, policy.Report)
		}
	}
	policy, err := parse(t, fixturePaths(t), categoryBase)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if policy.Report.Enabled || policy.Report.ReleaseAction != StaleReleaseNone || policy.HasArchiveCategories() {
		t.Fatalf("a policy without a report section enables it: %+v", policy.Report)
	}
	policy, err = parse(t, fixturePaths(t), reportBase)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if !policy.Report.Enabled || policy.Report.Idle.Duration() != 14*24*time.Hour || policy.Report.ReleaseAction != StaleReleaseNone || policy.Report.ArchivesReleases() {
		t.Fatalf("enabled report defaults = %+v, want idle 14d and release_action none", policy.Report)
	}
	if _, ok := policy.ArchiveCategory(ReportReleaseCategory, string(CategoryRootScratch)); ok {
		t.Fatal("release_action none still yields a release archive category")
	}
}

func TestStaleReportRefusesUnsafeSettings(t *testing.T) {
	archive := "  release_action: archive\n  archive:\n    directory: /srv/archive/released\n"
	for _, tc := range []struct {
		name, doc, field, fragment string
	}{
		{"no coordinator", strings.Replace(reportBase, "  coordinator_role: coordinator\n", "", 1), "report.coordinator_role", "unknown-owner"},
		{"coordinator named unknown", strings.Replace(reportBase, "coordinator_role: coordinator", "coordinator_role: unknown", 1), "report.coordinator_role", "unknown"},
		{"unconfigured root", strings.Replace(reportBase, "roots: [/srv/work]", "roots: [/srv/elsewhere]", 1), "report.roots[0]", "configured inventory root"},
		{"short idle", reportBase + "  idle: 12h\n", "report.idle", "at least"},
		{"unknown action", reportBase + "  release_action: delete\n", "report.release_action", "none or archive"},
		{"archive while off", categoryBase + "report:\n  release_action: archive\n", "report.release_action", "requires report.enabled"},
		{"archive without destination", reportBase + "  release_action: archive\n", "report.archive.directory", "canonical"},
		{"unprotected archive", reportBase + strings.Replace(archive, "/srv/archive/released", "/srv/unprotected", 1), "report.archive.directory", "protect.paths"},
		{"report_only root archived", strings.Replace(reportBase, "roots: [/srv/work]", "roots: [/srv/observed]", 1) + archive, "report.roots[0]", "report_only"},
		{"zero max items", reportBase + archive + "  max_items_per_cycle: 0\n", "report.max_items_per_cycle", "between"},
		{"reserved category name", reportBase + "workspace_archive_categories:\n" + categoryEntry(ReportReleaseCategory, "root_scratch", "/srv/scratch"), "workspace_archive_categories[0].name", "reserved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(t, fixturePaths(t), tc.doc)
			cfgErr, ok := err.(*Error)
			if !ok {
				t.Fatalf("err = %v, want a field error on %s", err, tc.field)
			}
			for _, fieldErr := range cfgErr.Errors {
				if fieldErr.Field == tc.field && strings.Contains(fieldErr.Message, tc.fragment) {
					return
				}
			}
			t.Fatalf("no %s error containing %q: %v", tc.field, tc.fragment, cfgErr)
		})
	}
}

// With release_action archive, receipts of released items resolve to a
// category built from the report settings; the report roots and archive
// directory are then out of every category's reach.
func TestStaleReportReleaseCategoryFollowsReportSettings(t *testing.T) {
	doc := reportBase + "  release_action: archive\n  local_retention: none\n  max_items_per_cycle: 3\n  archive:\n    directory: /srv/archive/released\n"
	policy, err := parse(t, fixturePaths(t), doc)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	category, ok := policy.ArchiveCategory(ReportReleaseCategory, string(CategoryPushedClones))
	if !ok || category.Kind != CategoryPushedClones || category.Archive.Directory != "/srv/archive/released" || category.MaxItemsPerCycle != 3 ||
		len(category.Roots) != 1 || category.Roots[0] != "/srv/work" || !policy.HasArchiveCategories() {
		t.Fatalf("release category = %+v, %v", category, ok)
	}
	if _, ok := policy.ArchiveCategory(ReportReleaseCategory, "bare"); ok {
		t.Fatal("an invalid kind resolved to a release category")
	}
	if refusals := strings.Join(policy.CategoryArchiveRefusals("/srv/archive/released/x"), "; "); !strings.Contains(refusals, "report archive directory") {
		t.Fatalf("report archive directory not refused: %q", refusals)
	}
}
