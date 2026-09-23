package config

import (
	"fmt"
	"net"
	"net/url"
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
//
// Credentials are bring-your-own and never live in the policy document: the
// policy names the environment variable that holds the key, and the key is
// read at run time. A policy file can therefore be shared, committed, or
// shown in full without exposing a secret.
type JevPolicy struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Model is sent as the request's model field. An alias such as
	// "jev-latest" can move to a new version; pin a versioned id to keep
	// cached decisions and confidence thresholds tied to one model.
	Model string `yaml:"model" json:"model"`
	// Endpoint is the TypeSafe evaluation endpoint.
	Endpoint string `yaml:"endpoint" json:"endpoint"`
	// APIKeyEnv names the environment variable holding the API key.
	APIKeyEnv string `yaml:"api_key_env" json:"api_key_env"`
	// MaxBatch caps how many entries share one request.
	MaxBatch int `yaml:"max_batch" json:"max_batch"`
	// MaxStateTokens caps the estimated size of one request's state,
	// kept below the model's per-request limit with room for questions.
	MaxStateTokens int `yaml:"max_state_tokens" json:"max_state_tokens"`
	// Timeout bounds one HTTP attempt.
	Timeout Duration `yaml:"timeout" json:"timeout"`
	// MaxRetries bounds retries of a retryable failure (429, 529, 5xx,
	// timeout). Other failures are not retried.
	MaxRetries int `yaml:"max_retries" json:"max_retries"`
	// MinInterval spaces consecutive requests, a client-side rate limit.
	MinInterval Duration `yaml:"min_interval" json:"min_interval"`
	// BreakerFailures is how many consecutive failed requests open the
	// circuit breaker for the rest of the run.
	BreakerFailures int `yaml:"breaker_failures" json:"breaker_failures"`
	// MinConfidence is the lowest answer confidence acted on; anything
	// less becomes investigate.
	MinConfidence float64 `yaml:"min_confidence" json:"min_confidence"`
	// MaxUnsafe is the highest unsafe-to-remove probability tolerated;
	// anything more becomes investigate.
	MaxUnsafe float64 `yaml:"max_unsafe" json:"max_unsafe"`
	// PricePerMTokUSD estimates cost from reported input tokens. The API
	// reports tokens, not money, so cost is always an estimate.
	PricePerMTokUSD float64 `yaml:"price_per_mtok_usd" json:"price_per_mtok_usd"`
	// CacheTTL bounds how long a cached decision is reused.
	CacheTTL Duration `yaml:"cache_ttl" json:"cache_ttl"`
	// RedactSegments are path segments replaced before anything is sent.
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

// CanonicalRoot declares where entries of a class are supposed to live.
// An entry of that class found elsewhere is a relocation candidate, never a
// deletion candidate.
type CanonicalRoot struct {
	Class core.ArtifactClass `yaml:"class" json:"class"`
	Path  string             `yaml:"path" json:"path"`
}

// Classification supplies the name-based signals the planner uses to sort
// paths into the built-in classes. Every list is matched against the base
// name with filepath.Match semantics.
type Classification struct {
	// ProjectMarkers are entries that mark a directory as a real project,
	// for example "go.mod" or ".git".
	//
	// Unlike every other list here these are literal file names, not
	// patterns: the collector detects them with one lstat each, which is
	// what keeps a default scan a metadata-only pass. A glob is rejected
	// rather than accepted and silently ignored.
	ProjectMarkers []string `yaml:"project_markers" json:"project_markers"`
	// WorktreeMarkers name directories that are task worktrees rather than
	// primary checkouts.
	WorktreeMarkers []string `yaml:"worktree_markers" json:"worktree_markers"`
	// GeneratedNames are regenerable build outputs.
	GeneratedNames []string `yaml:"generated_names" json:"generated_names"`
	// CacheNames are tool caches.
	CacheNames []string `yaml:"cache_names" json:"cache_names"`
	// BackupNames are archives and backups, which are kept by default.
	BackupNames []string `yaml:"backup_names" json:"backup_names"`
	// OperationalNames are the operator's own tooling, which is kept.
	OperationalNames []string `yaml:"operational_names" json:"operational_names"`
	// EvidenceNames are durable records that must never be cleaned up.
	EvidenceNames []string `yaml:"evidence_names" json:"evidence_names"`
}

// Ownership configures how foreign-owned entries are treated.
type Ownership struct {
	// InvestigateForeignOwner sends entries owned by another user to
	// investigate rather than proposing any mutation.
	InvestigateForeignOwner bool `yaml:"investigate_foreign_owner" json:"investigate_foreign_owner"`
	// ExpectedUID is the owner the planner expects. Zero disables the
	// check: root owns uid 0, so treating it as "unset" and as "expect
	// root" cannot both be true, and disabling is the honest reading of an
	// absent field.
	ExpectedUID uint32 `yaml:"expected_uid" json:"expected_uid"`
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

	CanonicalRoots []CanonicalRoot `yaml:"canonical_roots" json:"canonical_roots"`
	Classification Classification  `yaml:"classification" json:"classification"`
	Ownership      Ownership       `yaml:"ownership" json:"ownership"`
	Jev            JevPolicy       `yaml:"jev" json:"jev"`
	Limits         Limits          `yaml:"limits" json:"limits"`

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
			Enabled:   false,
			Model:     "jev-latest",
			Endpoint:  "https://api.typesafe.ai/v1/systemone",
			APIKeyEnv: "TYPESAFE_API_KEY",
			MaxBatch:  20,
			// Documented limits: 64k tokens per request, 32k for the state
			// plus the longest question. 24k leaves room for both.
			MaxStateTokens:  24000,
			Timeout:         Duration(20 * time.Second),
			MaxRetries:      2,
			MinInterval:     Duration(100 * time.Millisecond),
			BreakerFailures: 3,
			MinConfidence:   0.7,
			MaxUnsafe:       0.2,
			// Published price for jev-1.13.0: $0.042 per million input
			// tokens; output tokens are free.
			PricePerMTokUSD: 0.042,
			CacheTTL:        Duration(30 * 24 * time.Hour),
			RedactSegments:  []string{},
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
		Classification: Classification{
			ProjectMarkers:   []string{".git", "go.mod", "package.json", "Cargo.toml", "pyproject.toml"},
			WorktreeMarkers:  []string{"*-wt-*", "*.worktree", "worktrees"},
			GeneratedNames:   []string{"node_modules", "dist", "build", "target", ".venv", "__pycache__", ".next"},
			CacheNames:       []string{".cache", "*-cache", ".uv-cache", ".gradle", ".pytest_cache"},
			BackupNames:      []string{"*.bak", "*-backup", "backup", "backups", "*.tar.gz", "*.zip"},
			OperationalNames: []string{".gitmoot", "fleet-tools", ".ssh", ".config"},
			EvidenceNames:    []string{"evidence", "receipts", "incidents", "*-evidence"},
		},
		Ownership: Ownership{InvestigateForeignOwner: true},
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
	out.CanonicalRoots = append([]CanonicalRoot(nil), p.CanonicalRoots...)
	out.Classification = p.Classification.clone()
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
	for i := range p.CanonicalRoots {
		p.CanonicalRoots[i].Path = expand(fmt.Sprintf("canonical_roots[%d].path", i), p.CanonicalRoots[i].Path)
	}
	if p.CanonicalRoots == nil {
		p.CanonicalRoots = []CanonicalRoot{}
	}
	p.Classification = p.Classification.normalized()
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
	errs = append(errs, validateJev(p.Jev)...)
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
	seenClass := make(map[core.ArtifactClass]int, len(p.CanonicalRoots))
	for i, root := range p.CanonicalRoots {
		field := fmt.Sprintf("canonical_roots[%d]", i)
		if !root.Class.Valid() {
			errs.Add(field+".class", "unknown artifact class %q", string(root.Class))
		} else if first, dup := seenClass[root.Class]; dup {
			errs.Add(field+".class", "duplicates canonical_roots[%d].class %q", first, string(root.Class))
		} else {
			seenClass[root.Class] = i
		}
		if !core.IsCanonicalPath(root.Path) {
			errs.Add(field+".path", "must be an absolute path, got %q", root.Path)
		}
	}
	for i, marker := range p.Classification.ProjectMarkers {
		field := fmt.Sprintf("classification.project_markers[%d]", i)
		switch {
		case marker == "":
			errs.Add(field, "must not be empty")
		case strings.ContainsAny(marker, "*?["):
			errs.Add(field, "must be a literal file name, got the pattern %q: "+
				"markers are detected with a single lstat, so a glob would never match", marker)
		case marker == "." || marker == ".." || marker == "/":
			// These resolve to the directory itself, its parent, or the
			// filesystem root, so one such entry would mark every scanned
			// directory as a project.
			errs.Add(field, "must be a plain file name inside the directory, got %q, which would match every directory", marker)
		case !validMarkerName(marker):
			// A nested path does not match everything; it simply is not a
			// marker. Markers are detected with one lstat of a name inside
			// the directory.
			errs.Add(field, "must be a plain file name inside the directory, got %q", marker)
		}
	}
	for _, group := range []struct {
		field    string
		patterns []string
	}{
		{"classification.worktree_markers", p.Classification.WorktreeMarkers},
		{"classification.generated_names", p.Classification.GeneratedNames},
		{"classification.cache_names", p.Classification.CacheNames},
		{"classification.backup_names", p.Classification.BackupNames},
		{"classification.operational_names", p.Classification.OperationalNames},
		{"classification.evidence_names", p.Classification.EvidenceNames},
	} {
		for i, pattern := range group.patterns {
			if pattern == "" {
				errs.Add(fmt.Sprintf("%s[%d]", group.field, i), "must not be empty")
				continue
			}
			if _, err := filepath.Match(pattern, "probe"); err != nil {
				errs.Add(fmt.Sprintf("%s[%d]", group.field, i), "invalid pattern %q: %v", pattern, err)
			}
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

// validMarkerName reports whether a project marker names a single file
// inside a directory.
//
// Rejected: "", "." and ".." (always resolve), anything containing a path
// separator, and anything filepath.Base does not return unchanged. Callers
// distinguish the always-matching values from merely nested ones so the
// diagnostic does not overclaim.
func validMarkerName(marker string) bool {
	switch marker {
	case "", ".", "..":
		return false
	}
	if strings.ContainsRune(marker, '/') || strings.ContainsRune(marker, filepath.Separator) {
		return false
	}
	return filepath.Base(marker) == marker
}

// clone deep-copies every pattern list.
func (c Classification) clone() Classification {
	out := c
	for _, pair := range []struct {
		src *[]string
		dst *[]string
	}{
		{&c.ProjectMarkers, &out.ProjectMarkers},
		{&c.WorktreeMarkers, &out.WorktreeMarkers},
		{&c.GeneratedNames, &out.GeneratedNames},
		{&c.CacheNames, &out.CacheNames},
		{&c.BackupNames, &out.BackupNames},
		{&c.OperationalNames, &out.OperationalNames},
		{&c.EvidenceNames, &out.EvidenceNames},
	} {
		*pair.dst = append([]string(nil), *pair.src...)
	}
	return out
}

// normalized replaces nil lists with empty ones so the effective policy
// renders identically however it was written.
func (c Classification) normalized() Classification {
	out := c
	for _, list := range []*[]string{
		&out.ProjectMarkers, &out.WorktreeMarkers, &out.GeneratedNames,
		&out.CacheNames, &out.BackupNames, &out.OperationalNames, &out.EvidenceNames,
	} {
		if *list == nil {
			*list = []string{}
		}
	}
	return out
}

// validateJev checks the provider settings. They are validated whether or
// not the provider is enabled, so turning it on later cannot expose a
// configuration nobody checked.
func validateJev(j JevPolicy) core.FieldErrors {
	var errs core.FieldErrors
	if err := validateEndpoint(j.Endpoint); err != nil {
		errs.Add("jev.endpoint", "%v", err)
	}
	if !isEnvName(j.APIKeyEnv) {
		errs.Add("jev.api_key_env", "must name an environment variable, got %q", j.APIKeyEnv)
	}
	if j.MaxStateTokens <= 0 || j.MaxStateTokens > 32000 {
		errs.Add("jev.max_state_tokens", "must be within (0, 32000], the per-request state limit; got %d", j.MaxStateTokens)
	}
	if j.Timeout.Duration() <= 0 {
		errs.Add("jev.timeout", "must be greater than zero, got %s", j.Timeout)
	}
	if j.MaxRetries < 0 || j.MaxRetries > 5 {
		errs.Add("jev.max_retries", "must be within [0, 5], got %d", j.MaxRetries)
	}
	if j.MinInterval.Duration() < 0 {
		errs.Add("jev.min_interval", "must not be negative, got %s", j.MinInterval)
	}
	if j.BreakerFailures <= 0 {
		errs.Add("jev.breaker_failures", "must be greater than zero, got %d", j.BreakerFailures)
	}
	if j.MinConfidence < 0 || j.MinConfidence > 1 {
		errs.Add("jev.min_confidence", "must be within [0, 1], got %v", j.MinConfidence)
	}
	if j.MaxUnsafe < 0 || j.MaxUnsafe > 1 {
		errs.Add("jev.max_unsafe", "must be within [0, 1], got %v", j.MaxUnsafe)
	}
	if j.PricePerMTokUSD < 0 {
		errs.Add("jev.price_per_mtok_usd", "must not be negative, got %v", j.PricePerMTokUSD)
	}
	if j.CacheTTL.Duration() <= 0 {
		errs.Add("jev.cache_ttl", "must be greater than zero, got %s", j.CacheTTL)
	}
	return errs
}

// validateEndpoint requires HTTPS, allowing plain HTTP only to a loopback
// address. The API key travels in a header, so sending it in the clear to
// anything but this machine is refused.
func validateEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("must be an absolute URL, got %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("must use https unless it is a loopback address, got %q", raw)
	default:
		return fmt.Errorf("must use https, got %q", raw)
	}
}

// isEnvName reports whether s is a valid environment variable name.
func isEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r == '_':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
