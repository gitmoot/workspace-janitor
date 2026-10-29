package config

import (
	"strings"
	"testing"
	"time"
)

const scratchBase = `roots:
  - path: /srv/work
protect:
  paths: [/srv/archive]
`

func scratchEntry(extra string) string {
	return "scratch_cleanup:\n  - path: /srv/tmp\n    archive:\n      directory: /srv/archive/tmp\n" + extra
}

// Existing installs must not change: no scratch directory is cleaned unless
// the policy names one, and the defaults of a named one are the reviewed 72h
// idle and 48h interval.
func TestScratchCleanupDefaults(t *testing.T) {
	policy := DefaultPolicy(fixturePaths(t))
	if len(policy.ScratchCleanup) != 0 {
		t.Fatalf("built-in policy cleans scratch directories: %+v", policy.ScratchCleanup)
	}
	parsed, err := parse(t, fixturePaths(t), scratchBase)
	if err != nil || len(parsed.ScratchCleanup) != 0 {
		t.Fatalf("policy without scratch_cleanup = %+v, %v", parsed.ScratchCleanup, err)
	}
	parsed, err = parse(t, fixturePaths(t), scratchBase+scratchEntry(""))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	got := parsed.ScratchCleanup[0]
	if got.Idle.Duration() != 72*time.Hour || got.Every.Duration() != 48*time.Hour || got.MaxBytesPerRun != 0 || got.MaxEntries != 100000 || got.Skip == nil || got.Regenerable == nil {
		t.Fatalf("defaults = %+v", got)
	}
}

func TestScratchCleanupRefusesUnsafeSettings(t *testing.T) {
	for _, tc := range []struct{ name, doc, field, fragment string }{
		{"short idle", scratchBase + scratchEntry("    idle: 12h\n"), "scratch_cleanup[0].idle", "at least"},
		{"short every", scratchBase + scratchEntry("    every: 1h\n"), "scratch_cleanup[0].every", "at least"},
		{"bad glob", scratchBase + scratchEntry("    skip: [\"[\"]\n"), "scratch_cleanup[0].skip[0]", "glob"},
		{"inside a root", scratchBase + strings.Replace(scratchEntry(""), "/srv/tmp", "/srv/work/tmp", 1), "scratch_cleanup[0].path", "inventory root"},
		{"unprotected archive", scratchBase + strings.Replace(scratchEntry(""), "/srv/archive/tmp", "/srv/elsewhere", 1), "scratch_cleanup[0].archive.directory", "protect.paths"},
		{"archive inside scratch", "roots:\n  - path: /srv/work\nprotect:\n  paths: [/srv/tmp/archive]\n" + strings.Replace(scratchEntry(""), "/srv/archive/tmp", "/srv/tmp/archive", 1), "scratch_cleanup[0].archive.directory", "scratch directory"},
		{"protected scratch", "roots:\n  - path: /srv/work\nprotect:\n  paths: [/srv/archive, /srv]\n" + scratchEntry(""), "scratch_cleanup[0].path", "protect.paths"},
		{"processes off", scratchBase + "collectors:\n  processes: false\n" + scratchEntry(""), "scratch_cleanup", "process collector"},
		{"negative max entries", scratchBase + scratchEntry("    max_entries: -1\n"), "scratch_cleanup[0].max_entries", "at least 1"},
		{"negative bound", scratchBase + scratchEntry("    max_bytes_per_run: -1\n"), "scratch_cleanup[0].max_bytes_per_run", "positive"},
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

// Two scratch directories may never claim the same entry: a nested,
// enclosing or identical path is refused, a sibling is accepted.
func TestScratchCleanupRefusesOverlappingPaths(t *testing.T) {
	second := func(path string) string {
		return "  - path: " + path + "\n    archive:\n      directory: /srv/archive/other\n"
	}
	for _, path := range []string{"/srv/tmp/build", "/srv/tmp", "/srv"} {
		_, err := parse(t, fixturePaths(t), scratchBase+scratchEntry(second(path)))
		cfgErr, ok := err.(*Error)
		if !ok {
			t.Errorf("scratch path %s overlapping /srv/tmp was accepted: %v", path, err)
			continue
		}
		found := false
		for _, fieldErr := range cfgErr.Errors {
			found = found || fieldErr.Field == "scratch_cleanup[1].path" && strings.Contains(fieldErr.Message, "overlaps scratch_cleanup[0].path")
		}
		if !found {
			t.Errorf("scratch path %s: no overlap error in %v", path, cfgErr)
		}
	}
	if _, err := parse(t, fixturePaths(t), scratchBase+scratchEntry(second("/srv/tmp2"))); err != nil {
		t.Fatalf("sibling scratch directories refused: %v", err)
	}
}
