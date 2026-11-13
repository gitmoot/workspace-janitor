package config

import (
	"fmt"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// OwnerRule names the role that decides about Path and everything under it.
// It is information, never authority: it approves, releases, protects or
// unprotects nothing. Protection stays in protect.paths and KEEP records, and
// a release stays a reply from the role itself.
type OwnerRule struct {
	Path  string `yaml:"path" json:"path"`
	Owner string `yaml:"owner" json:"owner"`
	Note  string `yaml:"note,omitempty" json:"note,omitempty"`
}

// PolicyOwner is the owners entry covering path: the one whose path is the
// longest prefix of path (entries may nest). The index locates the entry in
// the policy for provenance.
func (p *Policy) PolicyOwner(path string) (OwnerRule, int, bool) {
	best := -1
	for i, rule := range p.Owners {
		if core.PathWithin(path, rule.Path) && (best < 0 || len(rule.Path) > len(p.Owners[best].Path)) {
			best = i
		}
	}
	if best < 0 {
		return OwnerRule{}, -1, false
	}
	return p.Owners[best], best, true
}

func (p *Policy) normalizeOwners(expand func(string, string) string) {
	for i := range p.Owners {
		p.Owners[i].Path = expand(fmt.Sprintf("owners[%d].path", i), p.Owners[i].Path)
	}
}

func (p *Policy) validateOwners(errs *core.FieldErrors) {
	seen := make(map[string]int, len(p.Owners))
	for i, rule := range p.Owners {
		field := fmt.Sprintf("owners[%d]", i)
		if !core.IsCanonicalPath(rule.Path) {
			errs.Add(field+".path", "must be a canonical absolute path, got %q", rule.Path)
		} else if first, dup := seen[rule.Path]; dup {
			errs.Add(field+".path", "duplicates owners[%d].path %q", first, rule.Path)
		} else {
			seen[rule.Path] = i
		}
		if !ValidRole(rule.Owner) {
			errs.Add(field+".owner", "must name the decision owner role: 1-64 letters, digits, '.', '_' or '-' (not %q), got %q", UnknownOwner, rule.Owner)
		}
	}
}
