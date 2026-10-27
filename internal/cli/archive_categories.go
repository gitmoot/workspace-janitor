package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/output"
	"github.com/gitmoot/workspace-janitor/internal/plan"
	"github.com/gitmoot/workspace-janitor/internal/safety"
	"github.com/gitmoot/workspace-janitor/internal/store"
	"github.com/gitmoot/workspace-janitor/internal/workspacearchive"
)

// Category item outcomes.
const (
	categoryRefused         = "refused"
	categoryAlreadyArchived = "already_archived"
	categoryDeferred        = "deferred"
	categoryWouldArchive    = "would_archive"
	categoryArchived        = "archived"
	categoryFailed          = "failed"
)

// categoryArchiveItem is one depth-1 entry of a category root and what the
// category run decided about it.
type categoryArchiveItem struct {
	Category         string                    `json:"category,omitempty"`
	Kind             string                    `json:"kind,omitempty"`
	Path             string                    `json:"path"`
	Status           string                    `json:"status"`
	SizeBytes        int64                     `json:"size_bytes"`
	SizeKnown        bool                      `json:"size_known"`
	NewestModifiedAt *time.Time                `json:"newest_modified_at,omitempty"`
	IdleFor          string                    `json:"idle_for,omitempty"`
	Reasons          []string                  `json:"reasons,omitempty"`
	Name             string                    `json:"name,omitempty"`
	Binding          *workspacearchive.Binding `json:"binding,omitempty"`
}

type categoryArchiveReport struct {
	Mode            string                `json:"mode"`
	DryRun          bool                  `json:"dry_run"`
	RunID           string                `json:"run_id"`
	Status          string                `json:"status"`
	Archived        int                   `json:"archived"`
	WouldArchive    int                   `json:"would_archive"`
	AlreadyArchived int                   `json:"already_archived"`
	Refused         int                   `json:"refused"`
	Deferred        int                   `json:"deferred"`
	Failed          int                   `json:"failed"`
	LocalFreedBytes uint64                `json:"local_freed_bytes"`
	Items           []categoryArchiveItem `json:"items"`
	Attribution     string                `json:"attribution"`
}

// withCategoryArchives adds one pinned, expiry-enabled workspace archive rule
// per active category archive receipt. A receipt is active only while its
// category is still configured with the same kind, root and archive
// directory, and no policy fact (KEEP, protect.paths, explicit rules,
// report-only roots, ...) refuses its path; otherwise its path simply has no
// archive authority and stays local.
func withCategoryArchives(ctx context.Context, paths config.Paths, policy config.Policy) (config.Policy, error) {
	if len(policy.WorkspaceArchiveCategories) == 0 {
		return policy, nil
	}
	records, err := store.ReadCategoryArchives(ctx, paths.DatabaseFile)
	if err != nil {
		return config.Policy{}, fmt.Errorf("category archive receipts: %w", err)
	}
	rules := append([]config.WorkspaceArchiveRule(nil), policy.WorkspaceArchives...)
	for _, record := range records {
		if rule, inactive := activeCategoryRule(policy, record); inactive == "" {
			rules = append(rules, rule)
		}
	}
	policy.WorkspaceArchives = rules
	return policy, nil
}

// activeCategoryRule rebuilds the pinned rule of record, or reports why the
// receipt carries no local-expiry authority under policy.
func activeCategoryRule(policy config.Policy, record store.CategoryArchive) (config.WorkspaceArchiveRule, string) {
	category, ok := policy.WorkspaceArchiveCategory(record.Category)
	switch {
	case !ok:
		return config.WorkspaceArchiveRule{}, "its category is no longer configured"
	case string(category.Kind) != record.Kind:
		return config.WorkspaceArchiveRule{}, "its category kind changed"
	case category.Archive.Directory != record.ArchiveDirectory:
		return config.WorkspaceArchiveRule{}, "its category archive directory changed"
	case !slices.Contains(category.Roots, filepath.Dir(record.Path)):
		return config.WorkspaceArchiveRule{}, "its path is no longer directly inside a category root"
	case record.RestoredByOwner:
		return config.WorkspaceArchiveRule{}, "its quarantine was restored after archiving; it stays local until it changes, idles again and is archived anew"
	case record.Withdrawn:
		return config.WorkspaceArchiveRule{}, "it was restored from its archive; it stays local until it changes, idles again and is archived anew"
	}
	if refusals := policy.CategoryArchiveRefusals(record.Path); len(refusals) != 0 {
		return config.WorkspaceArchiveRule{}, strings.Join(refusals, "; ")
	}
	rule := categoryRule(category, record.Name, record.Path, record.Owner, record.Release)
	rule.LocalExpiryEnabled = true
	rule.Archive.Manifest, rule.Archive.ManifestSHA256 = record.Manifest, record.ManifestSHA256
	return rule, ""
}

// categoryRule is the workspace archive rule a category item is archived
// and bound under. Its rule hash covers name, path, owner, release and the
// archive directory.
func categoryRule(category config.WorkspaceArchiveCategory, name, path, owner, release string) config.WorkspaceArchiveRule {
	return config.WorkspaceArchiveRule{
		Name: name, Path: path, Owner: owner, Release: release,
		DependentRoots: []string{}, LocalRetention: category.LocalRetention,
		Archive: config.WorkspaceArchiveDestination{
			Directory:         category.Archive.Directory,
			ExpectMountSource: category.Archive.ExpectMountSource,
			ExpectFSType:      category.Archive.ExpectFSType,
		},
	}
}

// categoryItemName derives a plain, unique archive name from the category,
// the item's base name and a hash of its path and the run that archived it,
// so a later re-archive of the same path never reuses or replaces outputs.
func categoryItemName(category, path, runID string) string {
	base := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, filepath.Base(path))
	if len(base) > 40 {
		base = base[:40]
	}
	sum := sha256.Sum256([]byte(path + "\x00" + runID))
	return category + "-" + base + "-" + hex.EncodeToString(sum[:])[:12]
}

// categoryKindOf maps an observed entry onto the one category kind it could
// belong to, or explains why it belongs to none.
func categoryKindOf(entry core.Entry) (config.WorkspaceArchiveCategoryKind, string) {
	switch {
	case entry.Kind != core.EntryKindDirectory:
		return "", fmt.Sprintf("only ordinary directories are category items, not a %s", entry.Kind)
	case entry.Git == nil:
		return config.CategoryRootScratch, ""
	case entry.Git.Bare:
		return "", "bare repositories are never category items"
	case entry.Git.WorktreeOf != "":
		return config.CategoryMergedWorktrees, ""
	default:
		return config.CategoryPushedClones, ""
	}
}

// categoryGitRefusals is the per-kind Git gate: nothing dirty, stashed,
// locked or unpublished, publication measured, metadata intact and ignored
// contents accounted for.
func categoryGitRefusals(git *core.GitState) []string {
	if git == nil {
		return nil
	}
	if git.Degraded {
		return []string{"Git state is degraded: " + git.DegradedReason}
	}
	var out []string
	if git.DirtyFiles > 0 {
		out = append(out, fmt.Sprintf("%d uncommitted change(s)", git.DirtyFiles))
	}
	if git.Stashes > 0 {
		out = append(out, fmt.Sprintf("%d stash entr(ies)", git.Stashes))
	}
	if git.Locked {
		out = append(out, "a Git lock file is present")
	}
	switch {
	case !git.PublicationKnown:
		out = append(out, "publication against remote-tracking branches was not measured")
	case git.UnpublishedCommits > 0:
		out = append(out, fmt.Sprintf("%d commit(s) are not on any remote-tracking branch", git.UnpublishedCommits))
	}
	if !git.ContentsKnown {
		reason := git.ContentsProtection
		if reason == "" {
			reason = "ignored worktree contents have not been proven reconstructible"
		}
		out = append(out, reason)
	}
	return out
}

// categoryRefusals lists every reason entry may not be archived under
// category: policy facts, the full safety verdict (collected protections,
// unknown evidence, Git state, protected paths, sensitive names, live
// databases, durable evidence), the Git gate, and the size and idle bounds
// from the bounded deep walk.
func categoryRefusals(policy config.Policy, category config.WorkspaceArchiveCategory, entry core.Entry, verdict core.Verdict, now time.Time) []string {
	out := policy.CategoryArchiveRefusals(entry.Path)
	seen := map[string]bool{}
	gitRefused := false
	for _, protection := range verdict.Protections {
		gitRefused = gitRefused || protection.Source == core.SourceGit
		reason := fmt.Sprintf("%s: %s", protection.Kind, protection.Reason)
		if !seen[reason] {
			seen[reason] = true
			out = append(out, reason)
		}
	}
	if !gitRefused {
		out = append(out, categoryGitRefusals(entry.Git)...)
	}
	switch {
	case !entry.SizeIsDeep || entry.SizeIsLowerBound:
		out = append(out, "tree size is unknown or partial; the bounded deep walk did not finish")
	case entry.SizeBytes > category.MaxBytesPerItem:
		out = append(out, fmt.Sprintf("tree holds %d bytes, above max_bytes_per_item %d", entry.SizeBytes, category.MaxBytesPerItem))
	}
	switch idle := now.Sub(entry.LatestModifiedAt); {
	case entry.LatestModifiedAt.IsZero():
		out = append(out, "newest modification in the tree is unknown; the bounded deep walk did not finish")
	case idle < category.Idle.Duration():
		out = append(out, fmt.Sprintf("changed %s ago; %s requires %s idle", idle.Truncate(time.Second), category.Kind, category.Idle))
	}
	return out
}

// categoryPreflight re-reads the policy file before and after the slow copy:
// a withdrawn or changed category, or a KEEP/protection added meanwhile,
// refuses the archive and leaves the original untouched.
func categoryPreflight(paths config.Paths, category config.WorkspaceArchiveCategory, path string) error {
	current, err := config.LoadPolicy(paths)
	if err != nil {
		return fmt.Errorf("policy recheck refused category archive: %w", err)
	}
	latest, ok := current.WorkspaceArchiveCategory(category.Name)
	if !ok || latest.Kind != category.Kind || latest.Archive != category.Archive || latest.LocalRetention != category.LocalRetention ||
		!slices.Contains(latest.Roots, filepath.Dir(path)) {
		return fmt.Errorf("archive category %q was withdrawn or changed during archiving; original retained", category.Name)
	}
	if refusals := current.CategoryArchiveRefusals(path); len(refusals) != 0 {
		return fmt.Errorf("policy now refuses %s: %s; original retained", path, strings.Join(refusals, "; "))
	}
	return nil
}

// archiveCategories selects, inspects and (unless dryRun) archives category
// items. It never removes anything: archived items reach quarantine and
// expiry only through the pinned rules withCategoryArchives derives from the
// receipts recorded here. Per-item failures are reported on their item and
// joined into the returned error; the run continues with the next item.
func archiveCategories(ctx context.Context, e *env, paths config.Paths, policy config.Policy, dryRun bool) (categoryArchiveReport, error) {
	now := time.Now().UTC()
	report := categoryArchiveReport{Mode: "category_archive", DryRun: dryRun, RunID: "category-" + now.Format("20060102T150405.000000000Z"), Status: "preview", Items: []categoryArchiveItem{},
		Attribution: "Category archive creation copies data and frees no source bytes. Archived items reach quarantine only after their local retention, through the ordinary quarantine and expiry engine."}
	if len(policy.WorkspaceArchiveCategories) == 0 {
		return report, errors.New("no workspace_archive_categories are configured")
	}
	var db *store.Store
	if !dryRun {
		if err := config.EnsureDir(paths.StateDir); err != nil {
			return report, err
		}
		unlock, err := lockApply(paths.StateDir)
		if err != nil {
			return report, err
		}
		defer unlock()
		if db, err = store.Open(ctx, paths.DatabaseFile); err != nil {
			return report, err
		}
		defer db.Close()
	}
	records, err := store.ReadCategoryArchives(ctx, paths.DatabaseFile)
	if err != nil {
		return report, fmt.Errorf("category archive receipts: %w", err)
	}
	recorded := make(map[string]store.CategoryArchive, len(records))
	for _, record := range records {
		recorded[record.Path] = record
	}

	// One fresh, deep, depth-1 observation of every category root with the
	// policy file alone: existing category pins must not shape selection.
	// Every candidate gets its own deep-size budget, so a few large siblings
	// cannot leave the rest of a root unmeasured (and so unselectable).
	var specs []collect.RootSpec
	for _, category := range policy.WorkspaceArchiveCategories {
		for _, root := range category.Roots {
			if slices.ContainsFunc(specs, func(spec collect.RootSpec) bool { return spec.Path == root }) {
				continue
			}
			for _, configured := range policy.Roots {
				if configured.Path == root {
					spec := rootSpec(configured, scanOptions{})
					spec.MaxDepth = 1
					specs = append(specs, spec)
				}
			}
		}
	}
	engine := cleanupEngine(e, nil, paths, policy)
	options := engine.Collect
	options.Roots, options.DeepSize, options.DeepSizePerEntry = specs, true, true
	observed, err := collect.Run(ctx, options)
	if err != nil {
		return report, err
	}
	safetyPolicy := enginePolicy(paths, policy)

	type pending struct {
		item   int
		newest time.Time
	}
	queues := map[string][]pending{}
	for _, entry := range observed.Entries {
		parent := filepath.Dir(entry.Path)
		var matching []config.WorkspaceArchiveCategory
		for _, category := range policy.WorkspaceArchiveCategories {
			if slices.Contains(category.Roots, parent) {
				matching = append(matching, category)
			}
		}
		if len(matching) == 0 {
			continue
		}
		item := categoryArchiveItem{Path: entry.Path, Status: categoryRefused, SizeBytes: entry.SizeBytes, SizeKnown: entry.SizeIsDeep && !entry.SizeIsLowerBound}
		if !entry.LatestModifiedAt.IsZero() {
			newest := entry.LatestModifiedAt.UTC()
			item.NewestModifiedAt = &newest
			item.IdleFor = now.Sub(newest).Truncate(time.Second).String()
		}
		kind, reason := categoryKindOf(entry)
		var category *config.WorkspaceArchiveCategory
		for i := range matching {
			if kind != "" && matching[i].Kind == kind {
				category = &matching[i]
				break
			}
		}
		if category == nil {
			if reason == "" {
				reason = fmt.Sprintf("a %s item matches no category configured for %s", kind, parent)
			}
			item.Reasons = []string{reason}
			report.Items = append(report.Items, item)
			continue
		}
		item.Category, item.Kind = category.Name, string(category.Kind)
		if record, ok := recorded[entry.Path]; ok && (entry.LatestModifiedAt.IsZero() || !entry.LatestModifiedAt.After(record.CreatedAt)) {
			item.Status, item.Name = categoryAlreadyArchived, record.Name
			follow := "its local retention and quarantine follow that archive"
			if _, inactive := activeCategoryRule(policy, record); inactive != "" {
				follow = "it has no local expiry authority: " + inactive
			}
			item.Reasons = []string{fmt.Sprintf("archived as %s at %s and unchanged since; %s", record.Name, record.CreatedAt.Format(time.RFC3339), follow)}
			report.Items = append(report.Items, item)
			continue
		}
		entry.Class = plan.Classify(entry, policy).Class
		verdict := safety.Evaluate(safety.Input{Entry: entry, Policy: safetyPolicy, Now: now})
		if item.Reasons = categoryRefusals(policy, *category, entry, verdict, now); len(item.Reasons) == 0 {
			queues[category.Name] = append(queues[category.Name], pending{len(report.Items), entry.LatestModifiedAt})
		}
		report.Items = append(report.Items, item)
	}

	var failures []error
	for _, category := range policy.WorkspaceArchiveCategories {
		queue := queues[category.Name]
		// Oldest first: the longest-idle items are archived before newer ones.
		sort.SliceStable(queue, func(i, j int) bool {
			if !queue[i].newest.Equal(queue[j].newest) {
				return queue[i].newest.Before(queue[j].newest)
			}
			return report.Items[queue[i].item].Path < report.Items[queue[j].item].Path
		})
		for n, next := range queue {
			item := &report.Items[next.item]
			if n >= category.MaxItemsPerCycle {
				item.Status = categoryDeferred
				item.Reasons = []string{fmt.Sprintf("max_items_per_cycle %d reached; retried next cycle", category.MaxItemsPerCycle)}
				continue
			}
			if err := ctx.Err(); err != nil {
				item.Status, item.Reasons = categoryDeferred, []string{err.Error()}
				continue
			}
			name := categoryItemName(category.Name, item.Path, report.RunID)
			owner := config.CategoryOwnerPrefix + category.Name
			rule := categoryRule(category, name, item.Path, owner, owner+"@"+report.RunID)
			scope := workspacearchive.PolicyScope(policy, rule)
			inspection, err := workspacearchive.Inspect(ctx, rule, scope)
			switch {
			case err != nil:
				item.Reasons = []string{"archive inspection refused: " + err.Error()}
			case inspection.ContentBytes > category.MaxBytesPerItem:
				item.Reasons = []string{fmt.Sprintf("archive content is %d bytes, above max_bytes_per_item %d", inspection.ContentBytes, category.MaxBytesPerItem)}
			case inspection.LinkedWorktree != (category.Kind == config.CategoryMergedWorktrees):
				item.Reasons = []string{"archive inspection disagrees with the category kind about the linked-worktree history pointer"}
			}
			if len(item.Reasons) != 0 {
				continue
			}
			if dryRun {
				item.Status, item.Name = categoryWouldArchive, name
				continue
			}
			binding, err := createCategoryArchive(ctx, db, paths, category, rule, scope, report.RunID)
			if err != nil {
				item.Status, item.Reasons = categoryFailed, []string{err.Error()}
				failures = append(failures, fmt.Errorf("%s: %w", item.Path, err))
				continue
			}
			item.Status, item.Name, item.Binding = categoryArchived, name, binding
		}
	}
	for _, item := range report.Items {
		switch item.Status {
		case categoryRefused:
			report.Refused++
		case categoryAlreadyArchived:
			report.AlreadyArchived++
		case categoryDeferred:
			report.Deferred++
		case categoryWouldArchive:
			report.WouldArchive++
		case categoryArchived:
			report.Archived++
		case categoryFailed:
			report.Failed++
		}
	}
	if !dryRun {
		report.Status = "completed"
		if len(failures) != 0 {
			report.Status = "completed_with_failures"
		}
	}
	return report, errors.Join(failures...)
}

// createCategoryArchive runs the verified copy-only Create under a capacity
// activity receipt and records the pinned manifest in Janitor's state.
func createCategoryArchive(ctx context.Context, db *store.Store, paths config.Paths, category config.WorkspaceArchiveCategory, rule config.WorkspaceArchiveRule, scope workspacearchive.Scope, runID string) (*workspacearchive.Binding, error) {
	monitor, err := startCapacityActivity(ctx, db, "verified_archive", rule.Name, rule.Path, rule.Owner, rule.Archive.Directory, activityVolume)
	if err != nil {
		return nil, err
	}
	monitor.activity.Attempted = 1
	m, binding, err := workspacearchive.Create(ctx, rule, scope, func() error { return categoryPreflight(paths, category, rule.Path) })
	if err == nil {
		err = db.Write(ctx, func(tx *store.Tx) error {
			return tx.RecordCategoryArchive(ctx, store.CategoryArchive{
				Name: rule.Name, Category: category.Name, Kind: string(category.Kind), Path: rule.Path,
				Owner: rule.Owner, Release: rule.Release, RunID: runID, ArchiveDirectory: rule.Archive.Directory,
				Manifest: binding.Manifest, ManifestSHA256: binding.ManifestSHA256,
				ContentBytes: m.ContentBytes, Members: len(m.Members), CreatedAt: m.CreatedAt, RecordedAt: time.Now().UTC(),
			})
		})
		if err != nil {
			err = fmt.Errorf("verified archive %s was created but its receipt was not recorded, so it has no expiry authority: %w", binding.Manifest, err)
		} else {
			monitor.activity.Completed = 1
		}
	}
	if err := monitor.finish(ctx, err); err != nil {
		return nil, err
	}
	return binding, nil
}

// runCategoryArchives is `janitor archive --categories`.
func runCategoryArchives(ctx context.Context, e *env, opts archiveOptions, format output.Format, paths config.Paths) error {
	policy, err := e.loadFilePolicy()
	if err != nil {
		return err
	}
	report, runErr := archiveCategories(ctx, e, paths, policy, opts.dryRun)
	if err := writeCategoryArchiveReport(e, format, report); err != nil {
		return errors.Join(runErr, err)
	}
	return runErr
}

func writeCategoryArchiveReport(e *env, format output.Format, report categoryArchiveReport) error {
	if format == output.FormatJSON {
		return output.WriteJSON(e.stdout, report.Mode, report)
	}
	if _, err := fmt.Fprintf(e.stdout, "mode: %s\nrun: %s\nstatus: %s\narchived: %d  would archive: %d  already archived: %d  refused: %d  deferred: %d  failed: %d\nlocal freed bytes: %d\n%s\n",
		report.Mode, report.RunID, report.Status, report.Archived, report.WouldArchive, report.AlreadyArchived, report.Refused, report.Deferred, report.Failed,
		report.LocalFreedBytes, report.Attribution); err != nil {
		return err
	}
	for _, item := range report.Items {
		category := item.Category
		if category == "" {
			category = "-"
		}
		size := "unknown"
		if item.SizeKnown {
			size = fmt.Sprintf("%d bytes", item.SizeBytes)
		}
		idle := item.IdleFor
		if idle == "" {
			idle = "unknown"
		}
		if _, err := fmt.Fprintf(e.stdout, "\n%s  %s  [%s]  size %s  idle %s\n", item.Status, item.Path, category, size, idle); err != nil {
			return err
		}
		if item.Name != "" {
			if _, err := fmt.Fprintf(e.stdout, "  archive: %s\n", item.Name); err != nil {
				return err
			}
		}
		for _, reason := range item.Reasons {
			if _, err := fmt.Fprintf(e.stdout, "  - %s\n", reason); err != nil {
				return err
			}
		}
	}
	return nil
}

// cycleCategoryArchives is the daily cycle's category step. The cycle report
// keeps the counts and only the items it archived or failed.
func cycleCategoryArchives(ctx context.Context, e *env, paths config.Paths) (*categoryArchiveReport, error) {
	policy, err := e.loadFilePolicy()
	if err != nil {
		return nil, err
	}
	report, err := archiveCategories(ctx, e, paths, policy, false)
	items := []categoryArchiveItem{}
	for _, item := range report.Items {
		if item.Status == categoryArchived || item.Status == categoryFailed {
			items = append(items, item)
		}
	}
	report.Items = items
	return &report, err
}

// runCategoryItemRestore verifies or restores the newest category archive of
// one path through the ordinary workspace archive verify/restore path.
func runCategoryItemRestore(ctx context.Context, e *env, opts archiveOptions, format output.Format, paths config.Paths, policy config.Policy) error {
	records, err := store.ReadCategoryArchives(ctx, paths.DatabaseFile)
	if err != nil {
		return fmt.Errorf("category archive receipts: %w", err)
	}
	for _, record := range records {
		if record.Path != opts.categoryItem {
			continue
		}
		// Mount expectations come from the category while it still names the
		// same directory; they are never part of the archive's rule hash.
		category, _ := policy.WorkspaceArchiveCategory(record.Category)
		if category.Archive.Directory != record.ArchiveDirectory {
			category = config.WorkspaceArchiveCategory{Archive: config.WorkspaceArchiveCategoryDestination{Directory: record.ArchiveDirectory}}
		}
		rule := categoryRule(category, record.Name, record.Path, record.Owner, record.Release)
		rule.Archive.Manifest, rule.Archive.ManifestSHA256 = record.Manifest, record.ManifestSHA256
		return runWorkspaceArchiveRule(ctx, e, opts, format, paths, policy, &rule)
	}
	return fmt.Errorf("no category archive receipt for %s", opts.categoryItem)
}
