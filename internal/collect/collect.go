// Package collect turns a set of roots into evidence-backed inventory
// entries.
//
// Three rules govern every collector here:
//
//   - Bounded. Directory entries, walk depth, file bytes read, and command
//     duration all have explicit limits. Hitting a limit is reported, never
//     hidden.
//   - Fail closed. A collector that cannot observe something records unknown
//     evidence and, where the safety contract requires it, a blocking
//     protection. A failed collector never produces a clean result.
//   - Read-only and local. No file contents are interpreted beyond the small
//     service-definition files the reference collectors must parse, no
//     environment values are read, and no Git command may touch the network.
package collect

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// Collector names as they appear in scan reports.
const (
	CollectorFilesystem = "filesystem"
	CollectorDeepSize   = "deep_size"
	CollectorGit        = "git"
	CollectorProcesses  = "processes"
	CollectorAgents     = "agents"
	CollectorServices   = "services"
	CollectorGitmoot    = "gitmoot"
)

// RootSpec is one discovery root and the bounds that apply inside it.
type RootSpec struct {
	Path            string
	MaxDepth        int
	FollowSymlinks  bool
	CrossFilesystem bool
	ReportOnly      bool
}

// Limits bounds every collector.
type Limits struct {
	GitTimeout         time.Duration
	CommandTimeout     time.Duration
	MaxEntries         int
	MaxDirEntries      int
	DeepSizeMaxEntries int
	DeepSizeMaxDepth   int
}

// ServiceSources lists where the service and scheduler collectors look.
// Paths are explicit so a scan can be pointed at a fixture tree.
type ServiceSources struct {
	SystemdDirs []string
	CronPaths   []string
	PM2Dumps    []string
}

// AgentRef is one directory a registered agent is using.
type AgentRef struct {
	Agent  string
	Path   string
	Detail string
}

// AgentSource adapts an agent registry — Gitmoot, a fleet manager, or a test
// fixture — into directory references. Implementations must be read-only and
// must return promptly; the scan bounds them with the command timeout.
type AgentSource interface {
	// Name identifies the registry in evidence and reports.
	Name() string
	// ActiveDirectories returns the directories registered agents occupy.
	ActiveDirectories(ctx context.Context) ([]AgentRef, error)
}

// Options configures one collection run.
type Options struct {
	Roots  []RootSpec
	Limits Limits

	DeepSize  bool
	Git       bool
	Processes bool
	Services  bool
	// GitmootHome is the protected Gitmoot-managed tree. GitmootDatabase is
	// observed read-only; it never grants the generic janitor mutation rights.
	GitmootHome     string
	GitmootDatabase string

	// ProcRoot is the procfs mount to read process references from.
	ProcRoot string
	// Services holds the service and scheduler definition locations.
	ServiceSources ServiceSources
	// AgentSources are the registered-agent adapters to consult.
	AgentSources []AgentSource
	// GitBinary is the git executable to run. Empty means "git" on PATH.
	GitBinary string
	// ProjectMarkers are file names whose presence inside a directory
	// marks it as a real project, for example "go.mod". Each is checked
	// with a single lstat, so the cost is bounded by the list length.
	ProjectMarkers []string

	// Prior is the inventory of the previous scan, used for fingerprint
	// comparison. PriorScanID names it in evidence.
	Prior       []core.Entry
	PriorScanID string

	// Now supplies observation timestamps. Tests inject a fixed clock.
	Now func() time.Time
}

// Result is the outcome of one collection run.
type Result struct {
	// Entries are the discovered entries, ordered by path.
	Entries []core.Entry
	// Reports say which collectors ran, failed, or were skipped.
	Reports []core.CollectorReport
}

// Validate reports option problems that would make a run meaningless.
func (o *Options) Validate() error {
	var errs core.FieldErrors
	if len(o.Roots) == 0 {
		errs.Add("roots", "must contain at least one root")
	}
	for i, root := range o.Roots {
		if !core.IsCanonicalPath(root.Path) {
			errs.Add(fmt.Sprintf("roots[%d].path", i), "must be an absolute, cleaned path, got %q", root.Path)
		}
		if root.MaxDepth < 1 {
			errs.Add(fmt.Sprintf("roots[%d].max_depth", i), "must be at least 1, got %d", root.MaxDepth)
		}
	}
	for _, bound := range []struct {
		field string
		value int
	}{
		{"limits.max_entries", o.Limits.MaxEntries},
		{"limits.max_dir_entries", o.Limits.MaxDirEntries},
	} {
		if bound.value <= 0 {
			errs.Add(bound.field, "must be greater than zero, got %d", bound.value)
		}
	}
	if o.DeepSize {
		if o.Limits.DeepSizeMaxEntries <= 0 {
			errs.Add("limits.deep_size_max_entries", "must be greater than zero while deep sizing is enabled")
		}
		if o.Limits.DeepSizeMaxDepth <= 0 {
			errs.Add("limits.deep_size_max_depth", "must be greater than zero while deep sizing is enabled")
		}
	}
	if o.Git && o.Limits.GitTimeout <= 0 {
		errs.Add("limits.git_timeout", "must be greater than zero while the git collector is enabled")
	}
	if o.Limits.CommandTimeout <= 0 {
		errs.Add("limits.command_timeout", "must be greater than zero, got %s", o.Limits.CommandTimeout)
	}
	if o.Processes && !core.IsCanonicalPath(o.ProcRoot) {
		errs.Add("proc_root", "must be an absolute path while the process collector is enabled, got %q", o.ProcRoot)
	}
	return errs.ErrorOrNil()
}

func (o *Options) now() time.Time {
	if o.Now == nil {
		return time.Now().UTC()
	}
	return o.Now().UTC()
}

// Run executes every enabled collector and returns the inventory.
//
// A collector failure is reported, not returned: the caller still receives
// the entries that were observed, each carrying the unknowns that apply to
// it. Run returns an error only when the options themselves are unusable.
func Run(ctx context.Context, opts Options) (Result, error) {
	if err := opts.Validate(); err != nil {
		return Result{}, fmt.Errorf("collect: invalid options: %w", err)
	}
	now := opts.now()

	entries, fsReports := collectFilesystem(ctx, &opts, now)

	result := Result{Entries: entries, Reports: fsReports}
	if opts.DeepSize {
		result.Reports = append(result.Reports, collectDeepSize(ctx, &opts, entries, now))
	} else {
		result.Reports = append(result.Reports, core.CollectorReport{
			Name:   CollectorDeepSize,
			Status: core.CollectorSkipped,
			Detail: "deep sizing is opt-in; sizes are lstat metadata only",
		})
	}

	if opts.Git {
		result.Reports = append(result.Reports, collectGit(ctx, &opts, entries, now))
	} else {
		result.Reports = append(result.Reports, core.CollectorReport{
			Name:   CollectorGit,
			Status: core.CollectorSkipped,
			Detail: "git collection disabled",
		})
	}

	// Each reference collector runs under its own deadline, enforced by the
	// caller rather than by the collector's cooperation. A context alone is
	// not enough: these collectors sit on blocking syscalls — procfs reads,
	// readlink, open on a stalled filesystem — that no cancellation
	// interrupts. Enforcing the bound here means the scan finishes on time
	// and says what it could not observe.
	for _, collector := range []struct {
		name   string
		gather func(context.Context, *Options) ([]Reference, core.CollectorReport)
	}{
		{CollectorProcesses, gatherProcessReferences},
		{CollectorAgents, gatherAgentReferences},
		{CollectorServices, gatherServiceReferences},
	} {
		refs, report := runBounded(ctx, &opts, collector.name, collector.gather)
		report.Recorded = attachReferences(entries, refs, now)
		result.Reports = append(result.Reports, report)
	}
	result.Reports = append(result.Reports, collectGitmoot(ctx, &opts, entries, now))

	// Overlapping roots are valid policy input, so the same path can be
	// reached twice. Merging keeps one entry per path with the union of its
	// evidence and protections, which also keeps the reported entry count
	// equal to the count the store will hold.
	result.Entries = mergeDuplicatePaths(entries)
	entries = result.Entries
	applyFingerprints(entries, opts.Prior, opts.PriorScanID, now)

	sort.SliceStable(result.Entries, func(i, j int) bool {
		return result.Entries[i].Path < result.Entries[j].Path
	})
	for i := range result.Entries {
		result.Entries[i].Normalize()
	}
	sort.SliceStable(result.Reports, func(i, j int) bool {
		return result.Reports[i].Name < result.Reports[j].Name
	})
	return result, nil
}

// Reference is a path that something outside the filesystem points at.
type Reference struct {
	Path       string
	Source     core.EvidenceSource
	Protection core.ProtectionKind
	Signal     string
	Detail     string
}

// attachReferences records each reference on every entry that contains it,
// as evidence and as a blocking protection. It returns how many references
// matched an entry.
func attachReferences(entries []core.Entry, refs []Reference, now time.Time) int {
	matched := 0
	for _, ref := range refs {
		if !core.IsCanonicalPath(ref.Path) {
			continue
		}
		hit := false
		for i := range entries {
			if !pathWithin(ref.Path, entries[i].Path) {
				continue
			}
			hit = true
			addEvidence(&entries[i], core.Evidence{
				Source:     ref.Source,
				Signal:     ref.Signal,
				Detail:     ref.Detail,
				ObservedAt: now,
			})
			addProtection(&entries[i], core.Protection{
				Kind:     ref.Protection,
				Reason:   ref.Detail,
				Source:   ref.Source,
				Blocking: true,
			})
		}
		if hit {
			matched++
		}
	}
	return matched
}

// pathWithin reports whether path is entry or lives inside it. The shared
// implementation handles the root directory, which naive prefix matching
// gets wrong.
func pathWithin(path, entry string) bool { return core.PathWithin(path, entry) }

// addEvidence appends an observation, skipping exact duplicates so repeated
// collectors do not inflate the record.
func addEvidence(entry *core.Entry, evidence core.Evidence) {
	for _, existing := range entry.Evidence {
		if existing.Source == evidence.Source && existing.Signal == evidence.Signal && existing.Detail == evidence.Detail {
			return
		}
	}
	entry.Evidence = append(entry.Evidence, evidence)
}

// addProtection appends a protection, skipping exact duplicates.
func addProtection(entry *core.Entry, protection core.Protection) {
	for _, existing := range entry.Protections {
		if existing.Kind == protection.Kind && existing.Reason == protection.Reason {
			return
		}
	}
	entry.Protections = append(entry.Protections, protection)
}

// addUnknown records something a collector could not observe. Unknown state
// is never silently dropped: it becomes evidence, and when it hides
// information the safety contract depends on, a blocking protection too.
func addUnknown(entry *core.Entry, source core.EvidenceSource, kind core.ProtectionKind, signal, detail string, now time.Time) {
	addEvidence(entry, core.Evidence{
		Source:     source,
		Signal:     "unknown:" + signal,
		Detail:     detail,
		ObservedAt: now,
	})
	addProtection(entry, core.Protection{
		Kind:     kind,
		Reason:   detail,
		Source:   source,
		Blocking: true,
	})
}

// errBounded marks a bound being reached, which is reported rather than
// treated as a failure.
var errBounded = errors.New("collect: bound reached")

// runBounded runs one reference collector and enforces its deadline from the
// outside.
//
// The deadline is a wall: when it fires the caller takes whatever the
// collector has already published and otherwise reports a partial result
// with one unknown. It never waits for a collector, and it never blocks on
// one that is mid-publication.
//
// Lateness is decided by comparing the completion time against the
// effective deadline — the earlier of this collector's own and any the
// caller imposed — and additionally by whether the caller has cancelled.
// The clock comparison is needed because context cancellation is
// asynchronous: collectorCtx.Err() only becomes non-nil once the timer
// goroutine runs, so a late collector could otherwise observe a nil error
// and publish. The context check is needed because a caller may cancel with
// no deadline at all.
//
// The residual case is a collector that finished just before the deadline
// and had not yet published: it is reported as an unknown. That is the
// fail-closed direction — an unobserved reference is treated as unobserved,
// never as absence.
func runBounded(
	ctx context.Context,
	opts *Options,
	name string,
	gather func(context.Context, *Options) ([]Reference, core.CollectorReport),
) ([]Reference, core.CollectorReport) {
	timeout := opts.Limits.CommandTimeout
	deadline := nowFunc().Add(timeout)
	collectorCtx, cancel := context.WithDeadline(ctx, deadline)
	// The caller may impose an earlier deadline than this collector's own.
	// Honour whichever comes first, so the guard below matches the context
	// the collector actually runs under.
	if inherited, ok := collectorCtx.Deadline(); ok && inherited.Before(deadline) {
		deadline = inherited
	}
	// Cancelled by the caller, not by the collector goroutine: cancelling
	// after a publication would make the deadline look expired for a
	// collector that finished in time.
	defer cancel()

	type outcome struct {
		refs   []Reference
		report core.CollectorReport
	}
	// Buffered so a collector that publishes after the caller has moved on
	// never blocks on the send and never leaks.
	done := make(chan outcome, 1)
	go func() {
		refs, report := gather(collectorCtx, opts)
		if !nowFunc().Before(deadline) || collectorCtx.Err() != nil {
			// Finished at or after the deadline, or after the caller gave
			// up: the scan reports this source as unknown, so the result is
			// dropped. Both tests are needed — the clock catches the
			// cancellation lag, and the context catches a caller that
			// cancelled without a deadline at all.
			return
		}
		done <- outcome{refs: refs, report: report}
	}()

	// Test seam: lets a test hold the caller here until a chosen
	// interleaving has occurred. Nil outside tests.
	if beforeSettle != nil {
		beforeSettle()
	}

	select {
	case result := <-done:
		return result.refs, result.report
	case <-collectorCtx.Done():
		select {
		case result := <-done:
			// Published before the deadline; both outcomes were ready and a
			// plain select would have discarded this by coin flip.
			return result.refs, result.report
		default:
		}
		return nil, core.CollectorReport{
			Name:     name,
			Status:   core.CollectorPartial,
			Unknowns: 1,
			Detail: fmt.Sprintf("did not finish within the %s command timeout; references from this source are unknown",
				timeout),
		}
	}
}

// beforeSettle is nil outside tests. See runBounded.
var beforeSettle func()

// nowFunc is time.Now outside tests. It exists so a test can place a
// collector's completion on either side of the deadline without depending
// on real timing.
var nowFunc = time.Now

// appendDetail joins report details without losing the earlier one.
func appendDetail(existing, addition string) string {
	if existing == "" {
		return addition
	}
	if strings.Contains(existing, addition) {
		return existing
	}
	return existing + "; " + addition
}

// mergeDuplicatePaths collapses entries that two overlapping roots both
// produced.
//
// The surviving entry keeps the most specific root — the longest root prefix
// — so the choice does not depend on traversal order, and it takes the union
// of evidence and protections so a protection recorded under either root
// cannot be lost.
func mergeDuplicatePaths(entries []core.Entry) []core.Entry {
	index := make(map[string]int, len(entries))
	merged := make([]core.Entry, 0, len(entries))
	for _, entry := range entries {
		position, seen := index[entry.Path]
		if !seen {
			index[entry.Path] = len(merged)
			merged = append(merged, entry)
			continue
		}
		existing := &merged[position]
		if len(entry.Root) > len(existing.Root) {
			// Keep the more specific root, but not at the cost of the
			// evidence already gathered under the broader one.
			evidence, protections := existing.Evidence, existing.Protections
			*existing = entry
			existing.Evidence = evidence
			existing.Protections = protections
			for _, e := range entry.Evidence {
				addEvidence(existing, e)
			}
			for _, p := range entry.Protections {
				addProtection(existing, p)
			}
			continue
		}
		for _, e := range entry.Evidence {
			addEvidence(existing, e)
		}
		for _, p := range entry.Protections {
			addProtection(existing, p)
		}
		if entry.SizeIsDeep && !existing.SizeIsDeep {
			existing.SizeBytes = entry.SizeBytes
			existing.SizeIsDeep = true
		}
	}
	return merged
}
