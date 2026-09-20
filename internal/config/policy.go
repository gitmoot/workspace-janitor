package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
	"gopkg.in/yaml.v3"
)

// PolicyVersion is the only policy document version this build understands.
// A document with a different version is rejected rather than guessed at.
const PolicyVersion = 1

// Duration is a YAML/JSON duration written in Go syntax, for example "5s".
type Duration time.Duration

// Duration returns the underlying duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// String renders the duration in Go syntax.
func (d Duration) String() string { return time.Duration(d).String() }

// UnmarshalYAML decodes a duration string, rejecting non-scalar nodes.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: duration must be a string such as \"5s\"", value.Line)
	}
	parsed, err := time.ParseDuration(value.Value)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q: use Go syntax such as \"5s\" or \"2m\"", value.Line, value.Value)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML renders the duration as a string.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// MarshalJSON renders the duration as a string, keeping JSON output readable
// and stable instead of emitting raw nanoseconds.
func (d Duration) MarshalJSON() ([]byte, error) { return core.MarshalJSON(d.String()) }

// UnmarshalJSON decodes a duration string.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := yaml.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q", s)
	}
	*d = Duration(parsed)
	return nil
}

// Root is one discovery root.
type Root struct {
	Path            string `yaml:"path" json:"path"`
	MaxDepth        int    `yaml:"max_depth" json:"max_depth"`
	FollowSymlinks  bool   `yaml:"follow_symlinks" json:"follow_symlinks"`
	CrossFilesystem bool   `yaml:"cross_filesystem" json:"cross_filesystem"`
	ReportOnly      bool   `yaml:"report_only" json:"report_only"`
}

// Protect lists paths and name patterns that may never be mutated.
type Protect struct {
	Paths        []string `yaml:"paths" json:"paths"`
	NamePatterns []string `yaml:"name_patterns" json:"name_patterns"`
}

// RetentionPolicy configures quarantine retention.
type RetentionPolicy struct {
	Default       core.Retention `yaml:"default" json:"default"`
	QuarantineDir string         `yaml:"quarantine_dir" json:"quarantine_dir"`
}

// CacheRule declares a known regenerable cache location.
type CacheRule struct {
	Name      string          `yaml:"name" json:"name"`
	Path      string          `yaml:"path" json:"path"`
	Action    core.ActionKind `yaml:"action" json:"action"`
	Retention core.Retention  `yaml:"retention" json:"retention"`
}

// JevPolicy configures the optional model classifier. It is disabled by
// default: the tool must be fully useful with no credentials and no network.
type JevPolicy struct {
	Enabled        bool     `yaml:"enabled" json:"enabled"`
	Model          string   `yaml:"model" json:"model"`
	MaxBatch       int      `yaml:"max_batch" json:"max_batch"`
	RedactSegments []string `yaml:"redact_segments" json:"redact_segments"`
}

// Limits bounds collection work so one slow repository cannot stall a scan.
type Limits struct {
	GitTimeout     Duration `yaml:"git_timeout" json:"git_timeout"`
	CommandTimeout Duration `yaml:"command_timeout" json:"command_timeout"`
	MaxEntries     int      `yaml:"max_entries" json:"max_entries"`
}

// Policy is the validated policy document.
type Policy struct {
	Version   int             `yaml:"version" json:"version"`
	Roots     []Root          `yaml:"roots" json:"roots"`
	Protect   Protect         `yaml:"protect" json:"protect"`
	Retention RetentionPolicy `yaml:"retention" json:"retention"`
	Caches    []CacheRule     `yaml:"caches" json:"caches"`
	Jev       JevPolicy       `yaml:"jev" json:"jev"`
	Limits    Limits          `yaml:"limits" json:"limits"`

	// Source is where the policy came from: a file path, or "built-in
	// defaults". It is never settable from YAML.
	Source string `yaml:"-" json:"source"`
	// FromFile reports whether a policy file was found and parsed.
	FromFile bool `yaml:"-" json:"from_file"`
}

// DefaultPolicy returns the built-in policy for the given paths. It protects
// credential-bearing locations, enables no cache deletion rules, and leaves
// the model classifier off.
func DefaultPolicy(p Paths) Policy {
	policy := Policy{
		Version: PolicyVersion,
		Protect: Protect{
			NamePatterns: []string{
				"*.pem", "*.key", "*.kdbx", "id_rsa*", "id_ed25519*",
				".env", ".env.*", "*credentials*", "*.sqlite", "*.db",
			},
		},
		Retention: RetentionPolicy{
			Default:       core.Retention30Days,
			QuarantineDir: p.QuarantineDir,
		},
		Caches: []CacheRule{},
		Jev: JevPolicy{
			Enabled:        false,
			MaxBatch:       20,
			RedactSegments: []string{},
		},
		Limits: Limits{
			GitTimeout:     Duration(5 * time.Second),
			CommandTimeout: Duration(10 * time.Second),
			MaxEntries:     20000,
		},
		Source:   "built-in defaults",
		FromFile: false,
	}
	if p.Home != "" {
		policy.Roots = []Root{{Path: p.Home, MaxDepth: 1}}
		for _, rel := range []string{".ssh", ".gnupg", ".aws", ".kube", ".config"} {
			policy.Protect.Paths = append(policy.Protect.Paths, filepath.Join(p.Home, rel))
		}
	} else {
		policy.Roots = []Root{}
		policy.Protect.Paths = []string{}
	}
	// The tool's own state and quarantine are mutation boundaries: whatever a
	// scan root turns out to cover, they may never be acted on.
	for _, path := range []string{p.StateDir, p.QuarantineDir} {
		if path != "" {
			policy.Protect.Paths = append(policy.Protect.Paths, path)
		}
	}
	return policy
}

// clone deep-copies the policy so a decode over a defaults value can never
// mutate the defaults it started from.
func (p Policy) clone() Policy {
	out := p
	out.Roots = append([]Root(nil), p.Roots...)
	out.Protect.Paths = append([]string(nil), p.Protect.Paths...)
	out.Protect.NamePatterns = append([]string(nil), p.Protect.NamePatterns...)
	out.Caches = append([]CacheRule(nil), p.Caches...)
	out.Jev.RedactSegments = append([]string(nil), p.Jev.RedactSegments...)
	return out
}

// normalize expands "~" prefixes, fills the per-rule fields a cache entry may
// omit, and re-adds the built-in protections.
//
// It never replaces a value the document set explicitly: defaults are applied
// by decoding over DefaultPolicy, so "max_batch: 0" stays zero and fails
// validation instead of being silently corrected to the default.
func (p *Policy) normalize(paths Paths, defaults Policy) core.FieldErrors {
	var errs core.FieldErrors
	expand := func(field, value string) string {
		expanded, err := ExpandPath(value, paths.Home)
		if err != nil {
			errs.Add(field, "%s", err.Error())
			return value
		}
		return expanded
	}
	for i := range p.Roots {
		p.Roots[i].Path = expand(fmt.Sprintf("roots[%d].path", i), p.Roots[i].Path)
	}
	for i := range p.Protect.Paths {
		p.Protect.Paths[i] = expand(fmt.Sprintf("protect.paths[%d]", i), p.Protect.Paths[i])
	}
	for i := range p.Caches {
		p.Caches[i].Path = expand(fmt.Sprintf("caches[%d].path", i), p.Caches[i].Path)
		if p.Caches[i].Action == "" {
			p.Caches[i].Action = core.ActionInvestigate
		}
		if p.Caches[i].Retention == "" {
			p.Caches[i].Retention = p.Retention.Default
		}
	}
	if p.Retention.QuarantineDir != "" {
		p.Retention.QuarantineDir = expand("retention.quarantine_dir", p.Retention.QuarantineDir)
	}
	// Built-in protections are additive. A document that lists its own
	// protected paths must not silently drop the credential locations the
	// tool protects by default.
	p.Protect.Paths = mergeUnique(p.Protect.Paths, defaults.Protect.Paths)
	p.Protect.NamePatterns = mergeUnique(p.Protect.NamePatterns, defaults.Protect.NamePatterns)
	// A relocated quarantine directory is still a mutation boundary. The
	// default protections only cover the default location, so protect
	// whatever location the document actually configured.
	if p.Retention.QuarantineDir != "" {
		p.Protect.Paths = mergeUnique(p.Protect.Paths, []string{p.Retention.QuarantineDir})
	}
	if p.Caches == nil {
		p.Caches = []CacheRule{}
	}
	if p.Roots == nil {
		p.Roots = []Root{}
	}
	if p.Jev.RedactSegments == nil {
		p.Jev.RedactSegments = []string{}
	}
	return errs
}

// mergeUnique appends the values of extra that base does not already hold,
// preserving base order and then extra order.
func mergeUnique(base, extra []string) []string {
	seen := make(map[string]struct{}, len(base)+len(extra))
	out := make([]string, 0, len(base)+len(extra))
	for _, values := range [][]string{base, extra} {
		for _, v := range values {
			if _, dup := seen[v]; dup {
				continue
			}
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}

// Validate reports every field-level problem with the policy.
func (p *Policy) Validate() core.FieldErrors {
	var errs core.FieldErrors
	if p.Version != PolicyVersion {
		errs.Add("version", "must be %d, got %d", PolicyVersion, p.Version)
	}
	if len(p.Roots) == 0 {
		errs.Add("roots", "must declare at least one discovery root")
	}
	seenRoot := make(map[string]int, len(p.Roots))
	for i, root := range p.Roots {
		field := fmt.Sprintf("roots[%d]", i)
		if !core.IsCanonicalPath(root.Path) {
			errs.Add(field+".path", "must be an absolute path, got %q", root.Path)
		} else if first, dup := seenRoot[root.Path]; dup {
			errs.Add(field+".path", "duplicates roots[%d].path %q", first, root.Path)
		} else {
			seenRoot[root.Path] = i
		}
		if root.MaxDepth < 0 {
			errs.Add(field+".max_depth", "must not be negative, got %d", root.MaxDepth)
		}
		if root.MaxDepth > 64 {
			errs.Add(field+".max_depth", "must be at most 64, got %d", root.MaxDepth)
		}
	}
	for i, path := range p.Protect.Paths {
		if !core.IsCanonicalPath(path) {
			errs.Add(fmt.Sprintf("protect.paths[%d]", i), "must be an absolute path, got %q", path)
		}
	}
	for i, pattern := range p.Protect.NamePatterns {
		if pattern == "" {
			errs.Add(fmt.Sprintf("protect.name_patterns[%d]", i), "must not be empty")
			continue
		}
		if _, err := filepath.Match(pattern, "probe"); err != nil {
			errs.Add(fmt.Sprintf("protect.name_patterns[%d]", i), "invalid pattern %q: %v", pattern, err)
		}
	}
	if !p.Retention.Default.Valid() {
		errs.Add("retention.default", "unknown retention %q (allowed: %s)", string(p.Retention.Default), joinRetentions())
	}
	if p.Retention.QuarantineDir != "" && !core.IsCanonicalPath(p.Retention.QuarantineDir) {
		errs.Add("retention.quarantine_dir", "must be an absolute path, got %q", p.Retention.QuarantineDir)
	}
	seenCache := make(map[string]int, len(p.Caches))
	for i, cache := range p.Caches {
		field := fmt.Sprintf("caches[%d]", i)
		if cache.Name == "" {
			errs.Add(field+".name", "must not be empty")
		} else if first, dup := seenCache[cache.Name]; dup {
			errs.Add(field+".name", "duplicates caches[%d].name %q", first, cache.Name)
		} else {
			seenCache[cache.Name] = i
		}
		if !core.IsCanonicalPath(cache.Path) {
			errs.Add(field+".path", "must be an absolute path, got %q", cache.Path)
		}
		if !cache.Action.Valid() {
			errs.Add(field+".action", "unknown action kind %q", string(cache.Action))
		} else if cache.Action == core.ActionRelocate {
			errs.Add(field+".action", "relocate is not a valid cache action")
		}
		if !cache.Retention.Valid() {
			errs.Add(field+".retention", "unknown retention %q (allowed: %s)", string(cache.Retention), joinRetentions())
		}
	}
	if p.Jev.Enabled && p.Jev.Model == "" {
		errs.Add("jev.model", "must be set when jev.enabled is true")
	}
	if p.Jev.MaxBatch <= 0 {
		errs.Add("jev.max_batch", "must be greater than zero, got %d", p.Jev.MaxBatch)
	}
	for i, segment := range p.Jev.RedactSegments {
		if segment == "" {
			errs.Add(fmt.Sprintf("jev.redact_segments[%d]", i), "must not be empty")
		}
	}
	if p.Limits.GitTimeout.Duration() <= 0 {
		errs.Add("limits.git_timeout", "must be greater than zero, got %s", p.Limits.GitTimeout)
	}
	if p.Limits.CommandTimeout.Duration() <= 0 {
		errs.Add("limits.command_timeout", "must be greater than zero, got %s", p.Limits.CommandTimeout)
	}
	if p.Limits.MaxEntries <= 0 {
		errs.Add("limits.max_entries", "must be greater than zero, got %d", p.Limits.MaxEntries)
	}
	return errs
}

func joinRetentions() string {
	values := core.Retentions()
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = string(v)
	}
	return strings.Join(out, ", ")
}
