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

// Limits bounds collection work so one slow repository, one enormous
// directory, or one hung command cannot stall or unbound a scan.
type Limits struct {
	GitTimeout         Duration `yaml:"git_timeout" json:"git_timeout"`
	CommandTimeout     Duration `yaml:"command_timeout" json:"command_timeout"`
	MaxEntries         int      `yaml:"max_entries" json:"max_entries"`
	MaxDirEntries      int      `yaml:"max_dir_entries" json:"max_dir_entries"`
	DeepSizeMaxEntries int      `yaml:"deep_size_max_entries" json:"deep_size_max_entries"`
	DeepSizeMaxDepth   int      `yaml:"deep_size_max_depth" json:"deep_size_max_depth"`
}

// Collectors selects which evidence collectors run and where the reference
// collectors look. Every location is explicit so a scan can be pointed at a
// fixture tree instead of the real system.
type Collectors struct {
	DeepSize    bool     `yaml:"deep_size" json:"deep_size"`
	Git         bool     `yaml:"git" json:"git"`
	Processes   bool     `yaml:"processes" json:"processes"`
	Services    bool     `yaml:"services" json:"services"`
	ProcRoot    string   `yaml:"proc_root" json:"proc_root"`
	SystemdDirs []string `yaml:"systemd_dirs" json:"systemd_dirs"`
	CronPaths   []string `yaml:"cron_paths" json:"cron_paths"`
	PM2Dumps    []string `yaml:"pm2_dumps" json:"pm2_dumps"`
}

// Safety configures the destination checks of the safety engine.
//
// Nothing here can disable a core invariant: the engine's protections are
// not configurable, and switching them off would require a separately named
// unsafe build mode, which this release does not provide.
type Safety struct {
	// MinFreeBytes is the headroom that must remain on the destination
	// filesystem after a quarantine.
	MinFreeBytes int64 `yaml:"min_free_bytes" json:"min_free_bytes"`
	// AllowCrossFilesystemQuarantine permits a destination on another
	// filesystem, which turns an atomic rename into a copy and delete.
	AllowCrossFilesystemQuarantine bool `yaml:"allow_cross_filesystem_quarantine" json:"allow_cross_filesystem_quarantine"`
}

// Policy is the validated policy document.
type Policy struct {
	Version    int             `yaml:"version" json:"version"`
	Roots      []Root          `yaml:"roots" json:"roots"`
	Protect    Protect         `yaml:"protect" json:"protect"`
	Retention  RetentionPolicy `yaml:"retention" json:"retention"`
	Caches     []CacheRule     `yaml:"caches" json:"caches"`
	Collectors Collectors      `yaml:"collectors" json:"collectors"`
	Safety     Safety          `yaml:"safety" json:"safety"`
	Jev        JevPolicy       `yaml:"jev" json:"jev"`
	Limits     Limits          `yaml:"limits" json:"limits"`

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
		Collectors: Collectors{
			// Deep sizing is opt-in: a default scan must stay a top-level,
			// metadata-only pass.
			DeepSize:  false,
			Git:       true,
			Processes: true,
			Services:  true,
			ProcRoot:  "/proc",
			SystemdDirs: []string{
				"/etc/systemd/system",
				"/usr/lib/systemd/system",
			},
			CronPaths: []string{"/etc/crontab", "/etc/cron.d"},
			PM2Dumps:  []string{},
		},
		Safety: Safety{
			// One gibibyte of headroom: enough that a quarantine cannot be
			// the thing that fills the disk it is protecting.
			MinFreeBytes:                   1 << 30,
			AllowCrossFilesystemQuarantine: false,
		},
		Limits: Limits{
			GitTimeout:         Duration(5 * time.Second),
			CommandTimeout:     Duration(10 * time.Second),
			MaxEntries:         20000,
			MaxDirEntries:      5000,
			DeepSizeMaxEntries: 200000,
			DeepSizeMaxDepth:   16,
		},
		Source:   "built-in defaults",
		FromFile: false,
	}
	if p.Home != "" {
		policy.Roots = []Root{{Path: p.Home, MaxDepth: 1}}
		for _, rel := range []string{".ssh", ".gnupg", ".aws", ".kube", ".config"} {
			policy.Protect.Paths = append(policy.Protect.Paths, filepath.Join(p.Home, rel))
		}
		policy.Collectors.SystemdDirs = append(policy.Collectors.SystemdDirs, filepath.Join(p.Home, ".config", "systemd", "user"))
		policy.Collectors.PM2Dumps = append(policy.Collectors.PM2Dumps, filepath.Join(p.Home, ".pm2", "dump.pm2"))
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
	out.Collectors.SystemdDirs = append([]string(nil), p.Collectors.SystemdDirs...)
	out.Collectors.CronPaths = append([]string(nil), p.Collectors.CronPaths...)
	out.Collectors.PM2Dumps = append([]string(nil), p.Collectors.PM2Dumps...)
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
	if p.Collectors.ProcRoot != "" {
		p.Collectors.ProcRoot = expand("collectors.proc_root", p.Collectors.ProcRoot)
	}
	for i := range p.Collectors.SystemdDirs {
		p.Collectors.SystemdDirs[i] = expand(fmt.Sprintf("collectors.systemd_dirs[%d]", i), p.Collectors.SystemdDirs[i])
	}
	for i := range p.Collectors.CronPaths {
		p.Collectors.CronPaths[i] = expand(fmt.Sprintf("collectors.cron_paths[%d]", i), p.Collectors.CronPaths[i])
	}
	for i := range p.Collectors.PM2Dumps {
		p.Collectors.PM2Dumps[i] = expand(fmt.Sprintf("collectors.pm2_dumps[%d]", i), p.Collectors.PM2Dumps[i])
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
	if p.Collectors.SystemdDirs == nil {
		p.Collectors.SystemdDirs = []string{}
	}
	if p.Collectors.CronPaths == nil {
		p.Collectors.CronPaths = []string{}
	}
	if p.Collectors.PM2Dumps == nil {
		p.Collectors.PM2Dumps = []string{}
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
	for _, bound := range []struct {
		field string
		value int
	}{
		{"limits.max_entries", p.Limits.MaxEntries},
		{"limits.max_dir_entries", p.Limits.MaxDirEntries},
		{"limits.deep_size_max_entries", p.Limits.DeepSizeMaxEntries},
		{"limits.deep_size_max_depth", p.Limits.DeepSizeMaxDepth},
	} {
		if bound.value <= 0 {
			errs.Add(bound.field, "must be greater than zero, got %d", bound.value)
		}
	}
	if p.Safety.MinFreeBytes < 0 {
		errs.Add("safety.min_free_bytes", "must not be negative, got %d", p.Safety.MinFreeBytes)
	}
	if p.Collectors.Processes && !core.IsCanonicalPath(p.Collectors.ProcRoot) {
		errs.Add("collectors.proc_root", "must be an absolute path while collectors.processes is true, got %q", p.Collectors.ProcRoot)
	}
	for _, group := range []struct {
		field  string
		values []string
	}{
		{"collectors.systemd_dirs", p.Collectors.SystemdDirs},
		{"collectors.cron_paths", p.Collectors.CronPaths},
		{"collectors.pm2_dumps", p.Collectors.PM2Dumps},
	} {
		for i, value := range group.values {
			if !core.IsCanonicalPath(value) {
				errs.Add(fmt.Sprintf("%s[%d]", group.field, i), "must be an absolute path, got %q", value)
			}
		}
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
