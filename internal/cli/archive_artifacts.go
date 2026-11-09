package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/action"
	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/output"
	"github.com/gitmoot/workspace-janitor/internal/store"
	"github.com/gitmoot/workspace-janitor/internal/workspacearchive"
	"github.com/google/uuid"
)

// artifactNotes counts, per reason, the files of one session folder that are
// not in its batch, with one example each. Quiet reasons (too young, already
// archived) alone do not make a session folder worth listing.
type artifactNotes struct {
	order   []string
	count   map[string]int
	example map[string]string
	notable bool
}

func (n *artifactNotes) add(reason, path string, quiet bool) {
	if n.count == nil {
		n.count, n.example = map[string]int{}, map[string]string{}
	}
	if _, seen := n.count[reason]; !seen {
		n.order = append(n.order, reason)
		n.example[reason] = path
	}
	n.count[reason]++
	n.notable = n.notable || !quiet
}

func (n *artifactNotes) total() int {
	total := 0
	for _, count := range n.count {
		total += count
	}
	return total
}

// lines renders each reason once: "<n> file(s) <reason> (e.g. <path>)".
func (n *artifactNotes) lines() []string {
	out := make([]string, 0, len(n.order))
	for _, reason := range n.order {
		out = append(out, fmt.Sprintf("%d file(s) kept: %s (e.g. %s)", n.count[reason], reason, n.example[reason]))
	}
	return out
}

// artifactPlan is one session folder of an omp_session_artifacts root and
// the batch selected from it.
type artifactPlan struct {
	category config.WorkspaceArchiveCategory
	root     *workspacearchive.ArtifactRoot
	rootPath string
	session  string // relative to rootPath: "<project>/<session>"
	refusal  string
	files    []workspacearchive.ArtifactFile
	bytes    int64
	newest   int64
	notes    artifactNotes
}

func (p *artifactPlan) path() string { return p.rootPath + "/" + p.session }

// wholeSessionUnits maps the session folders the run's omp_sessions
// categories archive (or have archived) as a whole to that outcome: their
// files are never batched one by one, so the two kinds never race.
func wholeSessionUnits(report *categoryArchiveReport) map[string]string {
	out := map[string]string{}
	for _, item := range report.Items {
		if item.Kind != string(config.CategoryOMPSessions) {
			continue
		}
		switch item.Status {
		case categoryWouldArchive, categoryArchived, categoryDeferred, categoryAlreadyArchived:
			out[item.Path] = item.Status
		}
	}
	return out
}

// archiveSessionArtifacts selects, and unless dryRun archives, the batches
// of every omp_session_artifacts category: per session folder, one tar of
// its eligible files. A file is eligible when it is a single-link regular
// file below "<project>/<session>/" idle for the category's idle by its own
// mtime, no policy fact refuses it, it is not already archived unchanged,
// and no process holds it. A session folder that omp_sessions archives
// whole in this run is left to it. Per-batch failures are reported on the
// batch and returned; the run continues with the next batch.
func archiveSessionArtifacts(ctx context.Context, db *store.Store, paths config.Paths, policy config.Policy, report *categoryArchiveReport, now time.Time, dryRun bool) []error {
	var failures []error
	var archived map[string]store.ArchivedArtifact
	whole := wholeSessionUnits(report)
	for _, category := range policy.WorkspaceArchiveCategories {
		if category.Kind != config.CategoryOMPSessionArtifacts {
			continue
		}
		if archived == nil {
			var err error
			if archived, err = store.ReadArchivedArtifacts(ctx, paths.DatabaseFile); err != nil {
				return append(failures, fmt.Errorf("session artifact receipts: %w", err))
			}
		}
		plans, roots, err := observeArtifacts(ctx, policy, category, whole, archived, report, now)
		if err != nil {
			failures = append(failures, err)
		}
		failures = append(failures, batchArtifacts(ctx, db, paths, policy, category, plans, report, dryRun)...)
		for _, root := range roots {
			root.Close()
		}
	}
	return failures
}

// observeArtifacts walks every session folder of category's roots and keeps
// the eligible files of each, after one live-process pass over all of them.
// An unreadable root or procfs, or any process that cannot be inspected,
// refuses every batch of the category. The caller closes the returned roots,
// which the plans share.
func observeArtifacts(ctx context.Context, policy config.Policy, category config.WorkspaceArchiveCategory, whole map[string]string,
	archived map[string]store.ArchivedArtifact, report *categoryArchiveReport, now time.Time) ([]*artifactPlan, []*workspacearchive.ArtifactRoot, error) {
	var plans []*artifactPlan
	var roots []*workspacearchive.ArtifactRoot
	var failures []error
	for _, rootPath := range category.Roots {
		root, err := workspacearchive.OpenArtifactRoot(rootPath)
		var sessions []string
		if err == nil {
			roots = append(roots, root)
			sessions, err = root.Sessions(policy.Limits.MaxDirEntries)
		}
		if err != nil {
			report.Items = append(report.Items, categoryArchiveItem{Category: category.Name, Kind: string(category.Kind), Path: rootPath, Status: categoryRefused,
				Reasons: []string{"session folders could not be listed; none is selected from a partial view: " + err.Error()}})
			failures = append(failures, fmt.Errorf("%s: %w", rootPath, err))
			continue
		}
		for _, session := range sessions {
			plan := &artifactPlan{category: category, root: root, rootPath: rootPath, session: session}
			plans = append(plans, plan)
			if status, ok := whole[plan.path()]; ok {
				plan.refusal = fmt.Sprintf("omp_sessions archives this session folder whole (%s in this run); its files are not batched one by one", status)
				continue
			}
			files, skips, err := root.ObserveSession(ctx, session, policy.Protect.NamePatterns, policy.Limits.DeepSizeMaxEntries)
			if err != nil {
				plan.refusal = "session folder could not be observed completely: " + err.Error()
				continue
			}
			for _, skip := range skips {
				plan.notes.add(skip.Reason, skip.Path, false)
			}
			for _, file := range files {
				path := rootPath + "/" + file.Path
				if age := now.Sub(time.Unix(0, file.ModifiedNS)); age < category.Idle.Duration() {
					plan.notes.add(fmt.Sprintf("changed within %s", category.Idle), file.Path, true)
					continue
				}
				if record, ok := archived[path]; ok && record.Size == file.Size && record.ModifiedNS == file.ModifiedNS && (record.Pending || record.Moved) {
					if record.Pending {
						plan.notes.add("already archived, waiting for its batch's quarantine", file.Path, true)
					} else {
						plan.notes.add("archived and moved before, then restored; stays local until it changes", file.Path, true)
					}
					continue
				}
				if refusals := artifactRefusals(policy, category, path); len(refusals) != 0 {
					plan.notes.add(refusals[0], file.Path, false)
					continue
				}
				plan.files = append(plan.files, file)
			}
		}
	}
	var candidates []string
	for _, plan := range plans {
		for _, file := range plan.files {
			candidates = append(candidates, plan.rootPath+"/"+file.Path)
		}
	}
	if len(candidates) == 0 {
		return plans, roots, errors.Join(failures...)
	}
	used, err := workspacearchive.OpenFiles(ctx, policy.Collectors.ProcRoot, candidates)
	if err != nil {
		reason := "live process check refused every session artifact: " + err.Error()
		for _, plan := range plans {
			if len(plan.files) != 0 {
				plan.refusal, plan.files = reason, nil
			}
		}
		return plans, roots, errors.Join(append(failures, fmt.Errorf("category %s: %s", category.Name, reason))...)
	}
	for _, plan := range plans {
		plan.files = slices.DeleteFunc(plan.files, func(file workspacearchive.ArtifactFile) bool {
			use, open := used[plan.rootPath+"/"+file.Path]
			if open {
				plan.notes.add("open in a process ("+use+")", file.Path, false)
			}
			return open
		})
	}
	return plans, roots, errors.Join(failures...)
}

// batchArtifacts caps each session folder's eligible files at
// max_files_per_batch and max_bytes_per_item, caps the batches at
// max_items_per_cycle (longest idle first), and archives each batch, or
// reports it in a dry run.
func batchArtifacts(ctx context.Context, db *store.Store, paths config.Paths, policy config.Policy, category config.WorkspaceArchiveCategory,
	plans []*artifactPlan, report *categoryArchiveReport, dryRun bool) []error {
	var failures []error
	var queue []*artifactPlan
	for _, plan := range plans {
		var batch []workspacearchive.ArtifactFile
		var bytes int64
		for _, file := range plan.files {
			switch {
			case file.Size > category.MaxBytesPerItem:
				plan.notes.add(fmt.Sprintf("larger than max_bytes_per_item %d", category.MaxBytesPerItem), file.Path, false)
			case len(batch) >= category.MaxFilesPerBatch || bytes+file.Size > category.MaxBytesPerItem:
				plan.notes.add(fmt.Sprintf("beyond this batch's max_files_per_batch %d or max_bytes_per_item %d; a later cycle archives it",
					category.MaxFilesPerBatch, category.MaxBytesPerItem), file.Path, true)
			default:
				batch = append(batch, file)
				bytes += file.Size
				plan.newest = max(plan.newest, file.ModifiedNS)
			}
		}
		plan.files, plan.bytes = batch, bytes
		switch {
		case plan.refusal != "":
			report.Items = append(report.Items, plan.item(categoryRefused, append([]string{plan.refusal}, plan.notes.lines()...)))
		case len(batch) == 0:
			if plan.notes.notable {
				report.Items = append(report.Items, plan.item(categoryRefused, plan.notes.lines()))
			}
		default:
			queue = append(queue, plan)
		}
	}
	sort.SliceStable(queue, func(i, j int) bool {
		if queue[i].newest != queue[j].newest {
			return queue[i].newest < queue[j].newest
		}
		return queue[i].path() < queue[j].path()
	})
	for n, plan := range queue {
		item := plan.item(categoryWouldArchive, plan.notes.lines())
		item.Name = categoryItemName(category.Name, plan.path(), report.RunID)
		switch {
		case n >= category.MaxItemsPerCycle:
			item.Status, item.Name = categoryDeferred, ""
			item.Reasons = append([]string{fmt.Sprintf("max_items_per_cycle %d batches reached; retried next cycle", category.MaxItemsPerCycle)}, item.Reasons...)
		case ctx.Err() != nil:
			item.Status, item.Name = categoryDeferred, ""
			item.Reasons = append([]string{ctx.Err().Error()}, item.Reasons...)
		case !dryRun:
			cleanupID, binding, err := createArtifactBatch(ctx, db, paths, plan, item.Name, report.RunID)
			if err != nil {
				item.Status, item.Reasons = categoryFailed, append([]string{err.Error()}, item.Reasons...)
				failures = append(failures, fmt.Errorf("%s: %w", plan.path(), err))
				break
			}
			item.Status, item.Binding, item.CleanupID = categoryArchived, binding, cleanupID
		}
		report.Items = append(report.Items, item)
	}
	return failures
}

func (p *artifactPlan) item(status string, reasons []string) categoryArchiveItem {
	item := categoryArchiveItem{Category: p.category.Name, Kind: string(p.category.Kind), Path: p.path(), Status: status,
		SizeBytes: p.bytes, SizeKnown: true, Files: len(p.files), Reasons: reasons}
	if p.newest > 0 {
		newest := time.Unix(0, p.newest).UTC()
		item.NewestModifiedAt = &newest
		item.IdleFor = time.Since(newest).Truncate(time.Second).String()
	}
	return item
}

// createArtifactBatch archives one batch under a capacity activity receipt
// and records the batch with its files. Its cleanup id, chosen now, is the
// receipt its quarantine journals every moved file under.
func createArtifactBatch(ctx context.Context, db *store.Store, paths config.Paths, plan *artifactPlan, name, runID string) (string, *workspacearchive.Binding, error) {
	category := plan.category
	owner := config.CategoryOwnerPrefix + category.Name
	monitor, err := startCapacityActivity(ctx, db, "verified_archive", name, plan.path(), owner, category.Archive.Directory, activityVolume)
	if err != nil {
		return "", nil, err
	}
	monitor.activity.Attempted = 1
	files := make([]string, len(plan.files))
	for i, file := range plan.files {
		files[i] = plan.rootPath + "/" + file.Path
	}
	preflight := func() error { return artifactPreflight(paths, category, plan.rootPath, files) }
	cleanupID := "cleanup-" + uuid.NewString()
	m, binding, err := plan.root.CreateBatch(ctx, category.Archive, name, plan.session, plan.files, preflight)
	if err == nil {
		receipt := store.ArtifactBatch{Name: name, Category: category.Name, Root: plan.rootPath, Session: plan.path(), RunID: runID,
			CleanupID: cleanupID, ArchiveDirectory: category.Archive.Directory, Manifest: binding.Manifest, ManifestSHA256: binding.ManifestSHA256,
			Files: len(m.Members), ContentBytes: m.ContentBytes, CreatedAt: m.CreatedAt, RecordedAt: time.Now().UTC()}
		records := make([]store.ArtifactFile, len(m.Members))
		for i, member := range m.Members {
			records[i] = store.ArtifactFile{ActionID: artifactActionID(i), Path: plan.rootPath + "/" + member.Path, Size: member.Size, ModifiedNS: member.ModifiedNS}
		}
		err = db.Write(ctx, func(tx *store.Tx) error { return tx.RecordArtifactBatch(ctx, receipt, records) })
		if err != nil {
			err = fmt.Errorf("verified batch archive %s was created but its receipt was not recorded, so nothing of it is ever moved: %w", binding.Manifest, err)
		} else {
			monitor.activity.Completed = 1
		}
	}
	if err := monitor.finish(ctx, err); err != nil {
		return "", nil, err
	}
	return cleanupID, binding, nil
}

func artifactActionID(i int) string { return fmt.Sprintf("file-%05d", i) }

// artifactRefusals is CategoryArchiveRefusals for a session artifact plus
// the current protected-name screen (built-in secret names and
// protect.name_patterns) on every name from the session folder down to the
// file, so a pattern added after selection keeps the file at every later
// boundary: before publication, at quarantine and at expiry.
func artifactRefusals(policy config.Policy, category config.WorkspaceArchiveCategory, path string) []string {
	out := policy.CategoryArchiveRefusals(path)
	session, ok := category.ArtifactSession(path)
	if !ok {
		return append(out, "not a file inside a session folder of the category")
	}
	parent := session
	for _, name := range strings.Split(strings.TrimPrefix(path, session+"/"), "/") {
		if workspacearchive.SensitiveName(name, parent, policy.Protect.NamePatterns) {
			out = append(out, fmt.Sprintf("protected name %q (built-in secret screen or protect.name_patterns)", name))
			break
		}
		parent += "/" + name
	}
	return out
}

// artifactPreflight re-reads the policy file before and after the copy: a
// withdrawn or changed category, or a KEEP or protection that now covers one
// of the files, refuses the batch and leaves every file untouched.
func artifactPreflight(paths config.Paths, category config.WorkspaceArchiveCategory, root string, files []string) error {
	current, err := config.LoadPolicy(paths)
	if err != nil {
		return fmt.Errorf("policy recheck refused the batch archive: %w", err)
	}
	latest, ok := current.WorkspaceArchiveCategory(category.Name)
	if !ok || latest.Kind != category.Kind || latest.Archive != category.Archive || latest.LocalRetention != category.LocalRetention ||
		!slices.Contains(latest.Roots, root) {
		return fmt.Errorf("archive category %q was withdrawn or changed during archiving; files retained", category.Name)
	}
	for _, file := range files {
		if refusals := artifactRefusals(current, latest, file); len(refusals) != 0 {
			return fmt.Errorf("policy now refuses %s: %s; files retained", file, strings.Join(refusals, "; "))
		}
	}
	return nil
}

// artifactAuthority returns the category whose verified archive still
// stands in for batch's files, or why none does.
func artifactAuthority(policy config.Policy, batch store.ArtifactBatch) (config.WorkspaceArchiveCategory, string) {
	category, ok := policy.WorkspaceArchiveCategory(batch.Category)
	switch {
	case !ok:
		return category, "its category is no longer configured"
	case category.Kind != config.CategoryOMPSessionArtifacts:
		return category, "its category kind changed"
	case category.Archive.Directory != batch.ArchiveDirectory:
		return category, "its category archive directory changed"
	case !slices.Contains(category.Roots, batch.Root):
		return category, "its root is no longer a category root"
	}
	return category, ""
}

// wholeSessionArchived reports whether an omp_sessions archive receipt with
// expiry authority covers session: its quarantine moves the folder whole,
// so its files are not moved one by one.
func wholeSessionArchived(policy config.Policy, session string) bool {
	for _, rule := range policy.WorkspaceArchives {
		if rule.Path == session && rule.LocalExpiryEnabled && strings.HasPrefix(rule.Owner, config.CategoryOwnerPrefix) {
			return true
		}
	}
	return false
}

// Session artifact batch quarantine outcomes.
const (
	artifactQuarantined     = "quarantined"
	artifactWouldQuarantine = "would_quarantine"
	artifactWaiting         = "waiting"
	artifactFailed          = "failed"
)

type artifactQuarantineBatch struct {
	Name       string   `json:"name"`
	Session    string   `json:"session"`
	CleanupID  string   `json:"cleanup_id"`
	Status     string   `json:"status"`
	Moved      int      `json:"moved"`
	MovedBytes int64    `json:"moved_bytes"`
	Kept       int      `json:"kept"`
	Reasons    []string `json:"reasons,omitempty"`
}

type artifactQuarantineReport struct {
	Mode    string                    `json:"mode"`
	DryRun  bool                      `json:"dry_run"`
	Batches []artifactQuarantineBatch `json:"batches"`
	Errors  []string                  `json:"errors"`
}

// quarantineArtifacts moves the files of every unsettled session artifact
// batch whose local retention has elapsed into the batch's cleanup receipt,
// one journaled cleanup item per file. Each batch archive is fully verified
// first; then each file must still be exactly the archived file (identity,
// size, mtime and contents), unprotected and unused (one procfs pass per
// batch) and is re-checked immediately before its rename. A file that fails
// any of that stays in place and is reported; the batch is then settled. A
// batch whose archive does not verify, or whose live-process check cannot
// complete, moves nothing and is retried.
func quarantineArtifacts(ctx context.Context, engine *action.Engine, policy config.Policy, dryRun bool) (artifactQuarantineReport, error) {
	report := artifactQuarantineReport{Mode: "artifact_quarantine", DryRun: dryRun, Batches: []artifactQuarantineBatch{}, Errors: []string{}}
	var batches []store.ArtifactBatch
	if err := engine.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		batches, err = tx.ArtifactBatches(ctx)
		return err
	}); err != nil {
		return report, err
	}
	now := time.Now().UTC()
	for _, batch := range batches {
		if batch.Settled {
			continue
		}
		out := artifactQuarantineBatch{Name: batch.Name, Session: batch.Session, CleanupID: batch.CleanupID}
		if err := quarantineArtifactBatch(ctx, engine, policy, batch, now, dryRun, &out); err != nil {
			out.Status, out.Reasons = artifactFailed, append([]string{err.Error()}, out.Reasons...)
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", batch.Name, err))
		}
		report.Batches = append(report.Batches, out)
	}
	if len(report.Errors) != 0 {
		return report, fmt.Errorf("%d session artifact batch(es) failed; first: %s", len(report.Errors), report.Errors[0])
	}
	return report, nil
}

func quarantineArtifactBatch(ctx context.Context, engine *action.Engine, policy config.Policy, batch store.ArtifactBatch, now time.Time, dryRun bool, out *artifactQuarantineBatch) error {
	category, inactive := artifactAuthority(policy, batch)
	switch {
	case inactive != "":
		out.Status, out.Reasons = artifactWaiting, []string{"no quarantine authority: " + inactive}
		return nil
	case !category.LocalRetention.Expired(batch.CreatedAt, now):
		out.Status, out.Reasons = artifactWaiting, []string{"the local retention window measured from archive creation has not elapsed"}
		return nil
	case wholeSessionArchived(policy, batch.Session):
		out.Status, out.Reasons = artifactWaiting, []string{"omp_sessions archived this session folder whole; its quarantine moves the folder"}
		return nil
	}
	var files []store.ArtifactFile
	var existing []core.CleanupItem
	if err := engine.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		if files, err = tx.ArtifactBatchFiles(ctx, batch.Name); err != nil {
			return err
		}
		existing, err = tx.CleanupItems(ctx, batch.CleanupID)
		return err
	}); err != nil {
		return err
	}
	m, err := workspacearchive.CheckArtifacts(ctx, category.Archive, workspacearchive.Binding{Manifest: batch.Manifest, ManifestSHA256: batch.ManifestSHA256})
	if err != nil {
		return fmt.Errorf("batch archive does not verify; nothing moved: %w", err)
	}
	if m.Root != batch.Root || m.Root+"/"+m.Session != batch.Session || len(m.Members) != len(files) {
		return errors.New("batch archive and its receipt disagree; nothing moved")
	}
	members := make(map[string]workspacearchive.ArtifactMember, len(m.Members))
	for _, member := range m.Members {
		members[m.Root+"/"+member.Path] = member
	}
	root, err := workspacearchive.OpenArtifactRoot(batch.Root)
	if err != nil {
		return err
	}
	defer root.Close()
	var notes artifactNotes
	journaled := make(map[string]bool, len(existing))
	for _, item := range existing {
		journaled[item.ActionID] = true
		if item.State != core.CleanupPrepared || dryRun {
			continue
		}
		// An earlier run stopped between journaling and moving this file:
		// finish a move that happened, otherwise close it unmoved.
		item, err := engine.Reconcile(ctx, item)
		if err == nil && item.State == core.CleanupPrepared {
			item, err = engine.Restore(ctx, item)
		}
		switch {
		case err != nil:
			return fmt.Errorf("interrupted earlier quarantine of %s: %w", item.Source, err)
		case item.State == core.CleanupQuarantined:
			out.Moved++
			out.MovedBytes += item.Entry.SizeBytes
		default:
			notes.add("an interrupted earlier quarantine left it in place", item.Source, false)
		}
	}
	type verified struct {
		file   store.ArtifactFile
		member workspacearchive.ArtifactMember
		state  workspacearchive.VerifiedArtifact
	}
	var ready []verified
	for _, file := range files {
		member, ok := members[file.Path]
		if !ok || member.Size != file.Size || member.ModifiedNS != file.ModifiedNS {
			return fmt.Errorf("batch archive and its receipt disagree about %s; nothing moved", file.Path)
		}
		if journaled[file.ActionID] {
			continue // an earlier, interrupted run journaled it already
		}
		if refusals := artifactRefusals(policy, category, file.Path); len(refusals) != 0 {
			notes.add(refusals[0], file.Path, false)
			continue
		}
		state, err := root.VerifyFile(ctx, member)
		if err != nil {
			reason := "changed since archiving: " + err.Error()
			if errors.Is(err, os.ErrNotExist) {
				reason = "no longer present"
			}
			notes.add(reason, file.Path, false)
			continue
		}
		ready = append(ready, verified{file, member, state})
	}
	candidates := make([]string, len(ready))
	for i, r := range ready {
		candidates[i] = r.file.Path
	}
	used := map[string]string{}
	if len(candidates) != 0 {
		if used, err = workspacearchive.OpenFiles(ctx, policy.Collectors.ProcRoot, candidates); err != nil {
			return fmt.Errorf("live process check: %w; nothing moved", err)
		}
	}
	var failures []error
	for _, r := range ready {
		if use, open := used[r.file.Path]; open {
			notes.add("open in a process ("+use+")", r.file.Path, false)
			continue
		}
		if dryRun {
			out.Moved++
			out.MovedBytes += r.file.Size
			continue
		}
		member, state := r.member, r.state
		_, err := engine.QuarantineArtifact(ctx, artifactCleanupItem(policy, batch, r.file, member.Identity, now), func() error { return root.Same(member, state) })
		switch {
		case err == nil:
			out.Moved++
			out.MovedBytes += r.file.Size
		case errors.Is(err, action.ErrArtifactKept):
			notes.add(err.Error(), r.file.Path, false)
		default:
			failures = append(failures, fmt.Errorf("%s: %w", r.file.Path, err))
		}
	}
	out.Kept, out.Reasons = notes.total(), notes.lines()
	if len(failures) != 0 {
		return errors.Join(failures...)
	}
	if dryRun {
		out.Status = artifactWouldQuarantine
		return nil
	}
	settlement := store.ArtifactSettlement{Moved: out.Moved, Kept: out.Kept, Notes: out.Reasons}
	if err := engine.DB.Write(ctx, func(tx *store.Tx) error { return tx.SettleArtifactBatch(ctx, batch.Name, time.Now().UTC(), settlement) }); err != nil {
		return err
	}
	out.Status = artifactQuarantined
	return nil
}

// artifactCleanupItem is the cleanup receipt of one verified batch file,
// which has the archived identity.
func artifactCleanupItem(policy config.Policy, batch store.ArtifactBatch, file store.ArtifactFile, id core.FilesystemID, now time.Time) core.CleanupItem {
	modified := time.Unix(0, file.ModifiedNS).UTC()
	entry := core.Entry{ContractVersion: core.ContractVersion, Path: file.Path, Root: batch.Root, Kind: core.EntryKindFile, Class: core.ClassEvidence,
		SizeBytes: file.Size, SizeIsDeep: true, ModifiedAt: modified, LatestModifiedAt: modified, FilesystemID: id, ObservedAt: now}
	return core.CleanupItem{CleanupID: batch.CleanupID, PlanID: batch.Name, ActionID: file.ActionID, Source: file.Path, Entry: entry,
		Action: core.Action{ID: file.ActionID, PlanID: batch.Name, Path: file.Path, Kind: core.ActionQuarantine, Class: core.ClassEvidence,
			Retention: policy.Retention.Default, Confidence: 1, Status: core.ActionApplied, FilesystemID: entry.FilesystemID, CreatedAt: now,
			Rules:   []string{action.ArtifactRulePrefix + batch.Name},
			Reasons: []string{"archived in verified session artifact batch " + batch.Name}}}
}

func writeArtifactQuarantine(out io.Writer, format output.Format, report artifactQuarantineReport) error {
	if format == output.FormatJSON {
		return output.WriteJSON(out, report.Mode, report)
	}
	if _, err := fmt.Fprintf(out, "mode: %s\ndry run: %t\nbatches: %d\n", report.Mode, report.DryRun, len(report.Batches)); err != nil {
		return err
	}
	for _, batch := range report.Batches {
		if _, err := fmt.Fprintf(out, "\n%s  %s  receipt %s  moved %d (%d bytes)  kept %d\n", batch.Status, batch.Session, batch.CleanupID, batch.Moved, batch.MovedBytes, batch.Kept); err != nil {
			return err
		}
		for _, reason := range batch.Reasons {
			if _, err := fmt.Fprintf(out, "  - %s\n", reason); err != nil {
				return err
			}
		}
	}
	return nil
}

// artifactExpiry is the action.ArtifactGuard of one expiry run. It verifies
// each batch archive once and makes one procfs pass over every quarantined
// session artifact (copy and original path) of the run.
type artifactExpiry struct {
	db      *store.Store
	policy  config.Policy
	items   []core.CleanupItem
	batches map[string]store.ArtifactBatch
	checked map[string]artifactCheck
	used    map[string]string
	usedErr error
	scanned bool
}

type artifactCheck struct {
	members map[string]workspacearchive.ArtifactMember
	err     error
}

func newArtifactExpiry(db *store.Store, policy config.Policy, items []core.CleanupItem) *artifactExpiry {
	return &artifactExpiry{db: db, policy: policy, items: items, checked: map[string]artifactCheck{}}
}

// Eligible implements action.ArtifactGuard.
func (g *artifactExpiry) Eligible(ctx context.Context, item core.CleanupItem) error {
	name, _ := action.ArtifactBatch(item)
	if g.batches == nil {
		var batches []store.ArtifactBatch
		if err := g.db.Read(ctx, func(tx *store.Tx) error {
			var err error
			batches, err = tx.ArtifactBatches(ctx)
			return err
		}); err != nil {
			return err
		}
		g.batches = make(map[string]store.ArtifactBatch, len(batches))
		for _, batch := range batches {
			g.batches[batch.Name] = batch
		}
	}
	batch, ok := g.batches[name]
	if !ok || batch.CleanupID != item.CleanupID {
		return fmt.Errorf("session artifact batch receipt %s is missing", name)
	}
	category, inactive := artifactAuthority(g.policy, batch)
	if inactive != "" {
		return fmt.Errorf("no expiry authority: %s", inactive)
	}
	// The current local_retention decides, as for workspace archives: one
	// raised after quarantine still holds the copy.
	if refusal := collect.LocalExpiryRefusal(config.WorkspaceArchiveRule{LocalRetention: category.LocalRetention, LocalExpiryEnabled: true}, batch.CreatedAt, time.Now().UTC()); refusal != "" {
		return fmt.Errorf("no expiry authority: %s", refusal)
	}
	if refusals := artifactRefusals(g.policy, category, item.Source); len(refusals) != 0 {
		return fmt.Errorf("policy now keeps %s: %s", item.Source, strings.Join(refusals, "; "))
	}
	check, ok := g.checked[name]
	if !ok {
		m, err := workspacearchive.CheckArtifacts(ctx, category.Archive, workspacearchive.Binding{Manifest: batch.Manifest, ManifestSHA256: batch.ManifestSHA256})
		check.err = err
		if err == nil && (m.Root != batch.Root || m.Root+"/"+m.Session != batch.Session) {
			check.err = errors.New("batch archive and its receipt disagree")
		}
		check.members = make(map[string]workspacearchive.ArtifactMember, len(m.Members))
		for _, member := range m.Members {
			check.members[m.Root+"/"+member.Path] = member
		}
		g.checked[name] = check
	}
	if check.err != nil {
		return fmt.Errorf("batch archive does not verify: %w", check.err)
	}
	member, ok := check.members[item.Source]
	if !ok {
		return errors.New("batch archive holds no such file")
	}
	verified, err := workspacearchive.VerifyArtifactCopy(ctx, item.Destination, member)
	if err != nil {
		return fmt.Errorf("quarantined copy is not the archived file: %w", err)
	}
	if !g.scanned {
		g.scanned = true
		var paths []string
		for _, other := range g.items {
			if _, ok := action.ArtifactBatch(other); ok && (other.State == core.CleanupQuarantined || other.State == core.CleanupInvestigate) {
				paths = append(paths, other.Source, other.Destination)
			}
		}
		g.used, g.usedErr = workspacearchive.OpenFiles(ctx, g.policy.Collectors.ProcRoot, paths)
	}
	if g.usedErr != nil {
		return fmt.Errorf("live process check: %w", g.usedErr)
	}
	for _, path := range []string{item.Destination, item.Source} {
		if use, ok := g.used[path]; ok {
			return fmt.Errorf("%s is in use (%s)", path, use)
		}
	}
	// The process scan can take long: the copy must still be exactly the
	// state verified against the archive before it, or an append made
	// meanwhile would be deleted without ever having been archived.
	if err := workspacearchive.SameCopy(item.Destination, verified); err != nil {
		return fmt.Errorf("quarantined copy is not the archived file: %w", err)
	}
	return nil
}

// artifactCategories reports whether policy configures an
// omp_session_artifacts category.
func artifactCategories(policy config.Policy) bool {
	return slices.ContainsFunc(policy.WorkspaceArchiveCategories, func(category config.WorkspaceArchiveCategory) bool {
		return category.Kind == config.CategoryOMPSessionArtifacts
	})
}
