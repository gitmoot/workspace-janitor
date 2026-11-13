package config

import (
	"strings"
	"testing"
)

const ownersBase = "roots:\n  - path: /srv/work\n"

// Nested entries are allowed; the longest covering path wins, and a path
// that merely shares a name prefix is not covered.
func TestPolicyOwnerLongestPrefixWins(t *testing.T) {
	policy, err := parse(t, fixturePaths(t), ownersBase+`owners:
  - path: /srv/work
    owner: platform
  - path: /srv/work/adspower2/api
    owner: api-team
  - path: /srv/work/adspower2
    owner: adspower
    note: live fleet API + dashboard
`)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	for path, want := range map[string]string{
		"/srv/work":                         "platform",
		"/srv/work/other":                   "platform",
		"/srv/work/adspower2":               "adspower",
		"/srv/work/adspower2/dashboard/x":   "adspower",
		"/srv/work/adspower2/api":           "api-team",
		"/srv/work/adspower2/api/v1":        "api-team",
		"/srv/work/adspower2-old/whatever":  "platform",
		"/srv/work/adspower2/apiary/hidden": "adspower",
	} {
		if rule, _, ok := policy.PolicyOwner(path); !ok || rule.Owner != want {
			t.Errorf("PolicyOwner(%s) = %+v %v, want %s", path, rule, ok, want)
		}
	}
	if rule, i, ok := policy.PolicyOwner("/srv/elsewhere"); ok || i != -1 {
		t.Errorf("PolicyOwner outside every entry = %+v %d %v, want none", rule, i, ok)
	}
	if rule, i, _ := policy.PolicyOwner("/srv/work/adspower2/x"); i != 2 || rule.Note != "live fleet API + dashboard" {
		t.Errorf("PolicyOwner index/note = %d %+v, want entry 2 with its note", i, rule)
	}
}

// "~" expands like every other policy path, and no owners section means no
// policy owner anywhere.
func TestPolicyOwnersDefaultEmptyAndExpandHome(t *testing.T) {
	paths := fixturePaths(t)
	policy, err := parse(t, paths, ownersBase)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if len(policy.Owners) != 0 {
		t.Fatalf("owners without a section = %+v", policy.Owners)
	}
	policy, err = parse(t, paths, ownersBase+"owners:\n  - path: ~/adspower2\n    owner: adspower\n")
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if want := paths.Home + "/adspower2"; policy.Owners[0].Path != want {
		t.Fatalf("owners[0].path = %q, want %q", policy.Owners[0].Path, want)
	}
}

func TestPolicyOwnersValidation(t *testing.T) {
	for _, tc := range []struct {
		name, owners, field, fragment string
	}{
		{"relative path", "  - path: srv/work\n    owner: adspower\n", "owners[0].path", "canonical absolute"},
		{"empty path", "  - path: \"\"\n    owner: adspower\n", "owners[0].path", "must not be empty"},
		{"empty owner", "  - path: /srv/work/x\n    owner: \"\"\n", "owners[0].owner", "decision owner role"},
		{"missing owner", "  - path: /srv/work/x\n", "owners[0].owner", "decision owner role"},
		{"owner unknown", "  - path: /srv/work/x\n    owner: unknown\n", "owners[0].owner", "decision owner role"},
		{"owner not a role", "  - path: /srv/work/x\n    owner: two words\n", "owners[0].owner", "decision owner role"},
		{"duplicate path", "  - path: /srv/work/x\n    owner: a\n  - path: /srv/work/x\n    owner: b\n", "owners[1].path", "duplicates owners[0].path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(t, fixturePaths(t), ownersBase+"owners:\n"+tc.owners)
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
