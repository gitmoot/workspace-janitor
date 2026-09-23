package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/output"
	"github.com/gitmoot/workspace-janitor/internal/safety"
	"github.com/gitmoot/workspace-janitor/internal/store"
)

// scanOptions are the command-line overrides for one scan.
type scanOptions struct {
	maxDepth     int
	deepSize     bool
	noGit        bool
	noDeepSize   bool
	noProcesses  bool
	noServices   bool
	noPersist    bool
	noPriorScan  bool
	entriesLimit int
	recordScanID *string
}

// scanReport is the `scan` result contract.
type scanReport struct {
	Scan      core.Scan `json:"scan"`
	Persisted bool      `json:"persisted"`
	PriorScan string    `json:"prior_scan_id,omitempty"`
	// PriorComparison explains why no prior scan was compared, when that
	// happened for a reason other than "this is the first scan".
	PriorComparison string       `json:"prior_comparison,omitempty"`
	Protected       int          `json:"protected_entries"`
	Refused         int          `json:"refused_entries"`
	Unknowns        int          `json:"unknown_observations"`
	Entries         []core.Entry `json:"entries"`
	// Verdicts is the safety engine's typed answer per entry, ordered by
	// path. A refusal here cannot be overridden by any later stage.
	Verdicts   []core.Verdict `json:"verdicts"`
	Guards     []string       `json:"guards"`
	Target     safetyTarget   `json:"quarantine_target"`
	EntryLimit int            `json:"entry_limit"`
	Roots      []scanRootRef  `json:"roots"`
}

// safetyTarget reports what the engine learned about the quarantine
// destination, including that it could not learn anything.
type safetyTarget struct {
	Dir       string `json:"dir"`
	Known     bool   `json:"known"`
	FreeBytes int64  `json:"free_bytes,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// scanRootRef records the bounds a root was scanned with.
type scanRootRef struct {
	Path            string `json:"path"`
	MaxDepth        int    `json:"max_depth"`
	FollowSymlinks  bool   `json:"follow_symlinks"`
	CrossFilesystem bool   `json:"cross_filesystem"`
	ReportOnly      bool   `json:"report_only"`
}

// runScan collects the inventory for the configured or requested roots.
//
// The scan is read-only: it records what it observed, including what it
// could not observe, and stores the result. It makes no decisions; the
// safety and policy engines consume this inventory.
func runScan(ctx context.Context, e *env, args []string, opts scanOptions) error {
	format, err := e.format()
	if err != nil {
		return err
	}
	paths, err := e.resolvePaths()
	if err != nil {
		return err
	}
	policy, err := e.loadPolicy()
	if err != nil {
		return err
	}
	roots, err := scanRoots(policy, args, opts)
	if err != nil {
		return err
	}

	// A reporting-only run must leave no trace. store.Open would create the
	// state directory, the database, and its schema, so it is called only
	// when this scan will actually write; a comparison-only run opens an
	// existing database and tolerates its absence.
	var db *store.Store
	if !opts.noPersist {
		db, err = store.Open(ctx, paths.DatabaseFile)
		if err != nil {
			return err
		}
		defer db.Close()
	}

	comparisonNote := ""
	if opts.noPersist && !opts.noPriorScan {
		// Read-only: no migration, no journal-mode change, no chmod. The
		// comparison is an optimisation, so a database this build cannot
		// read read-only is reported and skipped rather than upgraded.
		readOnly, err := store.OpenReadOnly(ctx, paths.DatabaseFile)
		switch {
		case errors.Is(err, store.ErrNotInitialized):
			comparisonNote = "skipped: no previous scan is stored"
		case err != nil:
			comparisonNote = "skipped: " + err.Error()
		default:
			defer readOnly.Close()
			db = readOnly
		}
	}

	prior, priorID, err := priorInventory(ctx, db, opts)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	scan := core.Scan{
		ID:        newScanID(now),
		Roots:     rootPaths(roots),
		Status:    core.ScanRunning,
		StartedAt: now,
	}

	result, err := collect.Run(ctx, collect.Options{
		Roots:           roots,
		Limits:          collectLimits(policy, opts),
		DeepSize:        !opts.noDeepSize && (opts.deepSize || policy.Collectors.DeepSize),
		Git:             policy.Collectors.Git && !opts.noGit,
		Processes:       policy.Collectors.Processes && !opts.noProcesses,
		Services:        policy.Collectors.Services && !opts.noServices,
		GitmootHome:     policy.Gitmoot.Home,
		GitmootDatabase: policy.Gitmoot.Database,
		ProcRoot:        policy.Collectors.ProcRoot,
		ProjectMarkers:  policy.Classification.ProjectMarkers,
		ServiceSources: collect.ServiceSources{
			SystemdDirs: policy.Collectors.SystemdDirs,
			CronPaths:   policy.Collectors.CronPaths,
			PM2Dumps:    policy.Collectors.PM2Dumps,
		},
		AgentSources: e.agentSources,
		Prior:        prior,
		PriorScanID:  priorID,
	})
	if err != nil {
		return err
	}

	finished := time.Now().UTC()
	scan.FinishedAt = &finished
	scan.Status = core.ScanCompleted
	scan.EntryCount = len(result.Entries)
	scan.Collectors = result.Reports
	scan.Normalize()

	// The safety engine runs over every observed entry. A scan makes no
	// decisions, but it must report which paths may never be mutated and
	// why, with the remedy for each refusal.
	target := safety.ResolveTarget(policy.Retention.QuarantineDir)
	engine := enginePolicy(paths, policy)

	report := scanReport{
		Scan:            scan,
		PriorScan:       priorID,
		PriorComparison: comparisonNote,
		Entries:         result.Entries,
		Verdicts:        make([]core.Verdict, 0, len(result.Entries)),
		Guards:          safety.GuardNames(),
		Target: safetyTarget{
			Dir:       target.Dir,
			Known:     target.Known,
			FreeBytes: target.FreeBytes,
			Detail:    target.Detail,
		},
		EntryLimit: policy.Limits.MaxEntries,
		Roots:      rootRefs(roots),
	}
	for _, entry := range result.Entries {
		if entry.Protected() {
			report.Protected++
		}
		for _, evidence := range entry.Evidence {
			if strings.HasPrefix(evidence.Signal, "unknown:") {
				report.Unknowns++
			}
		}
		verdict := safety.Evaluate(safety.Input{
			Entry:  entry,
			Policy: engine,
			Target: &target,
			Now:    now,
		})
		if verdict.Refused() {
			report.Refused++
		}
		report.Verdicts = append(report.Verdicts, verdict)
	}

	if !opts.noPersist {
		if err := persistScan(ctx, db, scan, result.Entries); err != nil {
			return err
		}
		report.Persisted = true
		if opts.recordScanID != nil {
			*opts.recordScanID = scan.ID
		}
	}

	if format == output.FormatJSON {
		return output.WriteJSON(e.stdout, "scan", report)
	}
	return writeScanText(e, report)
}

// scanRoots resolves the roots to scan: explicit arguments when given,
// otherwise the policy roots. Explicit roots inherit the bounds of the
// policy root that contains them, so a command-line path cannot quietly
// escape the configured limits.
func scanRoots(policy config.Policy, args []string, opts scanOptions) ([]collect.RootSpec, error) {
	specs := make([]collect.RootSpec, 0, len(policy.Roots))
	if len(args) == 0 {
		for _, root := range policy.Roots {
			specs = append(specs, rootSpec(root, opts))
		}
		return specs, nil
	}
	for _, arg := range args {
		path := filepath.Clean(arg)
		if !filepath.IsAbs(path) {
			return nil, &usageError{msg: fmt.Sprintf("root %q must be an absolute path", arg)}
		}
		spec := collect.RootSpec{Path: path, MaxDepth: 1}
		for _, root := range policy.Roots {
			if path == root.Path || strings.HasPrefix(path, root.Path+string(filepath.Separator)) {
				spec = rootSpec(root, opts)
				spec.Path = path
				break
			}
		}
		if opts.maxDepth > 0 {
			spec.MaxDepth = opts.maxDepth
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

func rootSpec(root config.Root, opts scanOptions) collect.RootSpec {
	depth := root.MaxDepth
	if depth < 1 {
		depth = 1
	}
	if opts.maxDepth > 0 {
		depth = opts.maxDepth
	}
	return collect.RootSpec{
		Path:            root.Path,
		MaxDepth:        depth,
		FollowSymlinks:  root.FollowSymlinks,
		CrossFilesystem: root.CrossFilesystem,
		ReportOnly:      root.ReportOnly,
	}
}

func collectLimits(policy config.Policy, opts scanOptions) collect.Limits {
	limits := collect.Limits{
		GitTimeout:         policy.Limits.GitTimeout.Duration(),
		CommandTimeout:     policy.Limits.CommandTimeout.Duration(),
		MaxEntries:         policy.Limits.MaxEntries,
		MaxDirEntries:      policy.Limits.MaxDirEntries,
		DeepSizeMaxEntries: policy.Limits.DeepSizeMaxEntries,
		DeepSizeMaxDepth:   policy.Limits.DeepSizeMaxDepth,
	}
	if opts.entriesLimit > 0 {
		limits.MaxEntries = opts.entriesLimit
	}
	return limits
}

// priorInventory loads the most recent completed scan for fingerprint
// comparison.
func priorInventory(ctx context.Context, db *store.Store, opts scanOptions) ([]core.Entry, string, error) {
	if opts.noPriorScan || db == nil {
		return nil, "", nil
	}
	var (
		entries []core.Entry
		scanID  string
	)
	err := db.Read(ctx, func(tx *store.Tx) error {
		scan, err := tx.LatestScan(ctx, core.ScanCompleted)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		scanID = scan.ID
		entries, err = tx.Entries(ctx, scan.ID)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	return entries, scanID, nil
}

func persistScan(ctx context.Context, db *store.Store, scan core.Scan, entries []core.Entry) error {
	return db.Write(ctx, func(tx *store.Tx) error {
		if err := tx.CreateScan(ctx, scan); err != nil {
			return err
		}
		for _, entry := range entries {
			if err := tx.PutEntry(ctx, scan.ID, entry); err != nil {
				return err
			}
		}
		return nil
	})
}

// newScanID builds a sortable, collision-resistant scan identifier.
func newScanID(now time.Time) string {
	return "scan-" + now.Format("20060102T150405.000000000Z")
}

func rootPaths(roots []collect.RootSpec) []string {
	paths := make([]string, 0, len(roots))
	for _, root := range roots {
		paths = append(paths, root.Path)
	}
	sort.Strings(paths)
	return paths
}

func rootRefs(roots []collect.RootSpec) []scanRootRef {
	refs := make([]scanRootRef, 0, len(roots))
	for _, root := range roots {
		refs = append(refs, scanRootRef{
			Path:            root.Path,
			MaxDepth:        root.MaxDepth,
			FollowSymlinks:  root.FollowSymlinks,
			CrossFilesystem: root.CrossFilesystem,
			ReportOnly:      root.ReportOnly,
		})
	}
	sort.SliceStable(refs, func(i, j int) bool { return refs[i].Path < refs[j].Path })
	return refs
}

func writeScanText(e *env, report scanReport) error {
	fields := []output.Field{
		{Key: "scan:", Value: report.Scan.ID},
		{Key: "roots:", Value: strings.Join(report.Scan.Roots, ", ")},
		{Key: "entries:", Value: strconv.Itoa(report.Scan.EntryCount)},
		{Key: "protected:", Value: strconv.Itoa(report.Protected)},
		{Key: "refused:", Value: strconv.Itoa(report.Refused)},
		{Key: "unknowns:", Value: strconv.Itoa(report.Unknowns)},
		{Key: "persisted:", Value: strconv.FormatBool(report.Persisted)},
	}
	if report.PriorScan != "" {
		fields = append(fields, output.Field{Key: "compared with:", Value: report.PriorScan})
	}
	if report.PriorComparison != "" {
		fields = append(fields, output.Field{Key: "comparison:", Value: report.PriorComparison})
	}
	if err := output.WriteFields(e.stdout, fields); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(e.stdout, "\nCollectors:"); err != nil {
		return err
	}
	rows := make([][]string, 0, len(report.Scan.Collectors))
	for _, collector := range report.Scan.Collectors {
		rows = append(rows, []string{
			string(collector.Status),
			collector.Name,
			fmt.Sprintf("visited=%d recorded=%d unknown=%d", collector.Visited, collector.Recorded, collector.Unknowns),
			collector.Detail,
		})
	}
	if err := output.WriteTable(e.stdout, []string{"STATUS", "COLLECTOR", "COUNTS", "DETAIL"}, rows); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(e.stdout, "\nEntries:"); err != nil {
		return err
	}
	verdicts := make(map[string]core.Verdict, len(report.Verdicts))
	for _, verdict := range report.Verdicts {
		verdicts[verdict.Path] = verdict
	}
	entryRows := make([][]string, 0, len(report.Entries))
	for _, entry := range report.Entries {
		verdict := verdicts[entry.Path]
		entryRows = append(entryRows, []string{
			string(verdict.Decision),
			string(entry.Kind),
			output.HumanBytes(entry.SizeBytes),
			protectionSummary(entry),
			entry.Path,
		})
	}
	if err := output.WriteTable(e.stdout, []string{"SAFETY", "KIND", "SIZE", "PROTECTIONS", "PATH"}, entryRows); err != nil {
		return err
	}
	return writeRefusals(e, report)
}

// writeRefusals prints every refusal with its evidence and its remedy. A
// refusal the operator cannot act on is not a useful answer.
func writeRefusals(e *env, report scanReport) error {
	refused := make([]core.Verdict, 0, len(report.Verdicts))
	for _, verdict := range report.Verdicts {
		if verdict.Refused() {
			refused = append(refused, verdict)
		}
	}
	if len(refused) == 0 {
		_, err := fmt.Fprintf(e.stdout, "\nNo path is protected against mutation (%d guard(s) ran).\n", len(report.Guards))
		return err
	}
	if _, err := fmt.Fprintf(e.stdout, "\nRefusals (%d of %d entries, %d guard(s) ran):\n",
		len(refused), len(report.Entries), len(report.Guards)); err != nil {
		return err
	}
	for _, verdict := range refused {
		if _, err := fmt.Fprintf(e.stdout, "\n  %s\n", verdict.Path); err != nil {
			return err
		}
		rows := make([][]string, 0, len(verdict.Protections))
		for _, protection := range verdict.Protections {
			if !protection.Blocking {
				continue
			}
			rows = append(rows, []string{"    " + string(protection.Kind), protection.Reason, "-> " + protection.Remediation})
		}
		if err := output.WriteTable(e.stdout, nil, rows); err != nil {
			return err
		}
	}
	return nil
}

// protectionSummary lists the blocking protection kinds of an entry.
func protectionSummary(entry core.Entry) string {
	kinds := make([]string, 0, len(entry.Protections))
	seen := make(map[core.ProtectionKind]struct{}, len(entry.Protections))
	for _, protection := range entry.Protections {
		if !protection.Blocking {
			continue
		}
		if _, dup := seen[protection.Kind]; dup {
			continue
		}
		seen[protection.Kind] = struct{}{}
		kinds = append(kinds, string(protection.Kind))
	}
	if len(kinds) == 0 {
		return "-"
	}
	sort.Strings(kinds)
	return strings.Join(kinds, ",")
}
