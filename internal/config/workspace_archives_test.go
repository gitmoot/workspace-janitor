package config

import (
	"errors"
	"strings"
	"testing"
)

const workspaceArchiveBase = `roots:
  - path: /srv/work
  - path: /srv/observed
    report_only: true
protect:
  paths: [/srv/archive, /srv/work/protected]
`

func workspaceArchiveEntry(name, path string) string {
	return "  - name: " + name + "\n    path: " + path + "\n    owner: seat-a\n    release: release-msg-1\n    archive:\n      directory: /srv/archive\n"
}

// fieldMessages renders every field failure of a rejected policy.
func fieldMessages(t *testing.T, err error) []string {
	t.Helper()
	var cfgErr *Error
	if !errors.As(err, &cfgErr) {
		t.Fatalf("expected a field-level policy error, got %v", err)
	}
	var out []string
	for _, fe := range cfgErr.Fields() {
		out = append(out, fe.Field+": "+fe.Message)
	}
	return out
}

func requireFieldError(t *testing.T, err error, field, fragment string) {
	t.Helper()
	for _, message := range fieldMessages(t, err) {
		if strings.HasPrefix(message, field+": ") && strings.Contains(message, fragment) {
			return
		}
	}
	t.Fatalf("no %s error containing %q in:\n%v", field, fragment, err)
}

func TestWorkspaceArchivesAreOptInAndEmptyByDefault(t *testing.T) {
	policy, err := parse(t, fixturePaths(t), workspaceArchiveBase)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if policy.WorkspaceArchives == nil || len(policy.WorkspaceArchives) != 0 || policy.WorkspaceArchiveKeep == nil || len(policy.WorkspaceArchiveKeep) != 0 {
		t.Fatalf("workspace archives must default to empty lists: %+v %+v", policy.WorkspaceArchives, policy.WorkspaceArchiveKeep)
	}
	if defaults := DefaultPolicy(fixturePaths(t)); len(defaults.WorkspaceArchives) != 0 || len(defaults.WorkspaceArchiveKeep) != 0 {
		t.Fatal("built-in defaults enable a workspace archive")
	}
}

func TestWorkspaceArchiveValidRuleParsesAndPinsOnlyItsOwnManifest(t *testing.T) {
	doc := workspaceArchiveBase + "workspace_archives:\n" + workspaceArchiveEntry("released-a", "/srv/work/released-a") +
		"      expect_mount_source: storage:/archive\n      expect_fstype: fuse.sshfs\n"
	policy, err := parse(t, fixturePaths(t), doc)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	rule := policy.WorkspaceArchives[0]
	if rule.Path != "/srv/work/released-a" || rule.Archive.ExpectFSType != "fuse.sshfs" || rule.DependentRoots == nil {
		t.Fatalf("rule not decoded and normalized: %+v", rule)
	}
	if got := WorkspaceArchiveManifestPath(rule); got != "/srv/archive/released-a.manifest.json" {
		t.Fatalf("manifest path = %q", got)
	}
	sha := strings.Repeat("a", 64)
	pinned := doc + "      manifest: /srv/archive/released-a.manifest.json\n      manifest_sha256: " + sha + "\n"
	if _, err := parse(t, fixturePaths(t), pinned); err != nil {
		t.Fatalf("pinned manifest rejected: %v", err)
	}
	foreign := doc + "      manifest: /srv/archive/other.manifest.json\n      manifest_sha256: " + sha + "\n"
	_, err = parse(t, fixturePaths(t), foreign)
	requireFieldError(t, err, "workspace_archives[0].archive.manifest", "released-a.manifest.json")
	unbound := doc + "      manifest_sha256: " + sha + "\n"
	_, err = parse(t, fixturePaths(t), unbound)
	requireFieldError(t, err, "workspace_archives[0].archive.manifest_sha256", "requires an exact manifest path")
}

// The 2026-10-27 incident: one seat released a path its owner had marked
// KEEP. Any keep record at, above or below a released path is an unresolved
// conflict that refuses the whole policy before any archive work.
func TestWorkspaceArchiveRefusesKeepReleaseConflict(t *testing.T) {
	for name, keepPath := range map[string]string{
		"same path":       "/srv/work/released-a",
		"kept parent":     "/srv/work",
		"kept descendant": "/srv/work/released-a/state",
	} {
		t.Run(name, func(t *testing.T) {
			doc := workspaceArchiveBase + "workspace_archives:\n" + workspaceArchiveEntry("released-a", "/srv/work/released-a") +
				"workspace_archive_keep:\n  - path: " + keepPath + "\n    owner: seat-b\n    reference: keep-msg-7\n"
			_, err := parse(t, fixturePaths(t), doc)
			requireFieldError(t, err, "workspace_archives[0].path", "unresolved KEEP/release conflict")
		})
	}
	unrelated := workspaceArchiveBase + "workspace_archives:\n" + workspaceArchiveEntry("released-a", "/srv/work/released-a") +
		"workspace_archive_keep:\n  - path: /srv/work/released-b\n    owner: seat-b\n    reference: keep-msg-7\n"
	if _, err := parse(t, fixturePaths(t), unrelated); err != nil {
		t.Fatalf("a keep on a disjoint path must not block: %v", err)
	}
	anonymous := workspaceArchiveBase + "workspace_archive_keep:\n  - path: /srv/work/x\n"
	_, err := parse(t, fixturePaths(t), anonymous)
	requireFieldError(t, err, "workspace_archive_keep[0]", "owner and a reference")
}

func TestWorkspaceArchiveRefusesDuplicateAndOverlappingReleases(t *testing.T) {
	duplicate := workspaceArchiveBase + "workspace_archives:\n" + workspaceArchiveEntry("released-a", "/srv/work/a") + workspaceArchiveEntry("released-a", "/srv/work/b")
	_, err := parse(t, fixturePaths(t), duplicate)
	requireFieldError(t, err, "workspace_archives[1].name", "duplicates workspace_archives[0].name")

	samePath := workspaceArchiveBase + "workspace_archives:\n" + workspaceArchiveEntry("seat-a", "/srv/work/a") + workspaceArchiveEntry("seat-b", "/srv/work/a")
	_, err = parse(t, fixturePaths(t), samePath)
	requireFieldError(t, err, "workspace_archives[1].path", "overlaps workspace_archives[0].path")

	nested := workspaceArchiveBase + "workspace_archives:\n" + workspaceArchiveEntry("outer", "/srv/work/a") + workspaceArchiveEntry("inner", "/srv/work/a/b")
	_, err = parse(t, fixturePaths(t), nested)
	requireFieldError(t, err, "workspace_archives[1].path", "overlaps workspace_archives[0].path")
}

func TestWorkspaceArchiveRefusesProtectedReportOnlyAndUnscopedPaths(t *testing.T) {
	for _, tc := range []struct{ path, fragment string }{
		{"/srv/work/protected/x", "overlaps protect.paths"},
		{"/srv/observed/x", "overlaps report_only root"},
		{"/elsewhere/x", "inside a configured inventory root"},
		{"/srv/work", "inside a configured inventory root"},
	} {
		doc := workspaceArchiveBase + "workspace_archives:\n" + workspaceArchiveEntry("released", tc.path)
		_, err := parse(t, fixturePaths(t), doc)
		requireFieldError(t, err, "workspace_archives[0].path", tc.fragment)
	}
	unprotected := strings.Replace(workspaceArchiveBase+"workspace_archives:\n"+workspaceArchiveEntry("released", "/srv/work/a"), "directory: /srv/archive", "directory: /srv/other-archive", 1)
	_, err := parse(t, fixturePaths(t), unprotected)
	requireFieldError(t, err, "workspace_archives[0].archive.directory", "protect.paths")
	inside := strings.Replace(workspaceArchiveBase+"workspace_archives:\n"+workspaceArchiveEntry("released", "/srv/work/a"), "directory: /srv/archive", "directory: /srv/work/a/archive", 1)
	_, err = parse(t, fixturePaths(t), inside)
	requireFieldError(t, err, "workspace_archives[0].archive.directory", "overlaps workspace archive source")
	badName := workspaceArchiveBase + "workspace_archives:\n" + workspaceArchiveEntry("../escape", "/srv/work/a")
	_, err = parse(t, fixturePaths(t), badName)
	requireFieldError(t, err, "workspace_archives[0].name", "must be")
}

func TestPolicyCloneDeepCopiesWorkspaceArchives(t *testing.T) {
	original := Policy{
		WorkspaceArchives:    []WorkspaceArchiveRule{{Name: "a", DependentRoots: []string{"/srv/a"}}},
		WorkspaceArchiveKeep: []WorkspaceArchiveKeep{{Path: "/srv/k"}},
	}
	copied := original.clone()
	copied.WorkspaceArchives[0].Name = "changed"
	copied.WorkspaceArchives[0].DependentRoots[0] = "/changed"
	copied.WorkspaceArchiveKeep[0].Path = "/changed"
	if original.WorkspaceArchives[0].Name != "a" || original.WorkspaceArchives[0].DependentRoots[0] != "/srv/a" || original.WorkspaceArchiveKeep[0].Path != "/srv/k" {
		t.Fatalf("clone shares workspace archive state: %+v", original)
	}
}

func TestWorkspaceArchiveLocalExpiryRequiresPinnedManifestAndRetention(t *testing.T) {
	doc := workspaceArchiveBase + "workspace_archives:\n" + workspaceArchiveEntry("released-a", "/srv/work/released-a")
	policy, err := parse(t, fixturePaths(t), doc)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if rule := policy.WorkspaceArchives[0]; rule.LocalExpiryEnabled || rule.LocalRetention != "30d" {
		t.Fatalf("local expiry must default off with 30d retention: %+v", rule)
	}
	pin := "      manifest: /srv/archive/released-a.manifest.json\n      manifest_sha256: " + strings.Repeat("a", 64) + "\n"
	enabled := doc + pin + "    local_expiry_enabled: true\n"
	policy, err = parse(t, fixturePaths(t), enabled)
	if err != nil {
		t.Fatalf("pinned local expiry rejected: %v", err)
	}
	if rule := policy.WorkspaceArchives[0]; !rule.LocalExpiryEnabled || rule.LocalRetention != "30d" {
		t.Fatalf("local expiry not decoded: %+v", rule)
	}
	if _, err = parse(t, fixturePaths(t), enabled+"    local_retention: 90d\n"); err != nil {
		t.Fatalf("90d local retention rejected: %v", err)
	}

	_, err = parse(t, fixturePaths(t), doc+"    local_expiry_enabled: true\n")
	requireFieldError(t, err, "workspace_archives[0].local_expiry_enabled", "requires a pinned archive manifest")
	_, err = parse(t, fixturePaths(t), enabled+"    local_retention: permanent\n")
	requireFieldError(t, err, "workspace_archives[0].local_expiry_enabled", "cannot expire permanent local retention")
	_, err = parse(t, fixturePaths(t), enabled+"    local_retention: 7d\n")
	requireFieldError(t, err, "workspace_archives[0].local_retention", "at least 30d")
	_, err = parse(t, fixturePaths(t), enabled+"collectors:\n  services: false\n")
	requireFieldError(t, err, "workspace_archives[0].local_expiry_enabled", "requires Git, process, and service collectors")
	if _, err = parse(t, fixturePaths(t), doc+pin+"    local_retention: permanent\n"); err != nil {
		t.Fatalf("permanent retention without expiry rejected: %v", err)
	}
}
