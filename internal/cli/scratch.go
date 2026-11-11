package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/action"
	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/output"
	"github.com/gitmoot/workspace-janitor/internal/store"
	"github.com/gitmoot/workspace-janitor/internal/workspacearchive"
)

// Scratch entry outcomes.
const (
	scratchWouldArchive = "would_archive"
	scratchWouldDelete  = "would_delete"
	scratchArchived     = "archived_and_deleted"
	scratchDeleted      = "deleted"
	scratchKept         = "kept"
	scratchSkipped      = "skipped"
	scratchDeferred     = "deferred"
	scratchFailed       = "failed"
)

// createScratchArchive is the archive step; tests wrap it to damage or
// change what was archived before the deletion step runs.
var createScratchArchive = (*workspacearchive.ScratchDir).CreateScratch

// scratchNow is the clock idle ages and due times are measured with. Tests
// move it forward rather than set every member's mtime back.
var scratchNow = func() time.Time { return time.Now().UTC() }

// scratchIdle is how long an entry has gone unmodified: since the newest
// mtime of any member. ctime is not used, because systemd-tmpfiles-clean
// bumps it daily on everything it scans; it only anchors the unchanged
// check and removal. An mtime in the future counts as modified now.
func scratchIdle(now time.Time, newestMtimeNS int64) time.Duration {
	return max(0, now.Sub(time.Unix(0, newestMtimeNS)))
}

// scratchRunID names the acting run started at now; it always has the same
// length, which the run receipt estimate relies on.
func scratchRunID(now time.Time) string { return now.Format("20060102T150405.000000000Z") }

type scratchItem struct {
	Entry     string `json:"entry"`
	Path      string `json:"path"`
	Status    string `json:"status"`
	SizeBytes int64  `json:"size_bytes"`
	IdleFor   string `json:"idle_for,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type scratchArchiveSummary struct {
	Manifest       string   `json:"manifest"`
	ManifestSHA256 string   `json:"manifest_sha256"`
	TarBytes       int64    `json:"tar_bytes"`
	Files          int      `json:"files_verified"`
	Entries        []string `json:"entries"`
}

type scratchRunReport struct {
	Path       string                 `json:"path"`
	RunID      string                 `json:"run_id,omitempty"`
	DryRun     bool                   `json:"dry_run"`
	Status     string                 `json:"status"`
	Error      string                 `json:"error,omitempty"`
	NextDue    *time.Time             `json:"next_due,omitempty"`
	Archive    *scratchArchiveSummary `json:"archive,omitempty"`
	FreedBytes int64                  `json:"freed_bytes"`
	Archived   int                    `json:"archived_deleted"`
	Deleted    int                    `json:"regenerable_deleted"`
	// WouldArchive and WouldDelete count a preview's selection, and
	// WouldFreeBytes its local bytes; an acting run reports what it did.
	WouldArchive   int           `json:"would_archive"`
	WouldDelete    int           `json:"would_delete"`
	WouldFreeBytes int64         `json:"would_free_bytes"`
	Kept           int           `json:"kept"`
	Skipped        int           `json:"skipped"`
	Deferred       int           `json:"deferred"`
	Failed         int           `json:"failed"`
	Items          []scratchItem `json:"items"`
	// Unlisted counts the entries, of any status, left out of Items once
	// scratchListedMax items are listed; they are in the counts above.
	Unlisted    int    `json:"unlisted"`
	Attribution string `json:"attribution"`

	unlistedBy    map[string]int
	unlistedBytes map[string]int64
}

type scratchReport struct {
	Mode   string             `json:"mode"`
	DryRun bool               `json:"dry_run"`
	Runs   []scratchRunReport `json:"runs"`
}

// scratchCandidate is an entry that may be removed this run. item is its
// index in the report's Items, or -1 when the listed bound left it out.
type scratchCandidate struct {
	item           int
	entry          workspacearchive.ScratchEntry
	regenerable    bool
	status, reason string
}

// scratchListedMax bounds the items one run report lists, whatever their
// status; a scratch directory may hold many thousands of entries.
var scratchListedMax = 1000

// list adds item to the report while the bound allows, or counts it as
// unlisted.
func (r *scratchRunReport) list(item scratchItem) {
	if r.slot(item) < 0 {
		r.unlisted(item.Status, item.SizeBytes)
	}
}

// slot adds item to the report while the bound allows and returns its
// index, or returns -1. A candidate's final outcome is counted by settle.
func (r *scratchRunReport) slot(item scratchItem) int {
	if len(r.Items) >= scratchListedMax {
		return -1
	}
	r.Items = append(r.Items, item)
	return len(r.Items) - 1
}

func (r *scratchRunReport) unlisted(status string, size int64) {
	if r.unlistedBy == nil {
		r.unlistedBy, r.unlistedBytes = map[string]int{}, map[string]int64{}
	}
	r.unlistedBy[status]++
	r.unlistedBytes[status] += size
	r.Unlisted++
}

// set records a candidate's outcome, on its listed item when it has one.
func (r *scratchRunReport) set(c *scratchCandidate, status, reason string) {
	c.status, c.reason = status, reason
	if c.item >= 0 {
		r.Items[c.item].Status, r.Items[c.item].Reason = status, reason
	}
}

// settle counts the final outcome of every unlisted candidate once, then
// recounts the report.
func (r *scratchRunReport) settle(candidates []scratchCandidate) {
	for _, c := range candidates {
		if c.item < 0 {
			r.unlisted(c.status, c.entry.SizeBytes)
		}
	}
	r.count()
}

func (r *scratchRunReport) count() {
	r.Archived, r.Deleted, r.WouldArchive, r.WouldDelete = r.unlistedBy[scratchArchived], r.unlistedBy[scratchDeleted], r.unlistedBy[scratchWouldArchive], r.unlistedBy[scratchWouldDelete]
	r.Kept, r.Skipped, r.Deferred, r.Failed = r.unlistedBy[scratchKept], r.unlistedBy[scratchSkipped], r.unlistedBy[scratchDeferred], r.unlistedBy[scratchFailed]
	r.FreedBytes = r.unlistedBytes[scratchArchived] + r.unlistedBytes[scratchDeleted]
	r.WouldFreeBytes = r.unlistedBytes[scratchWouldArchive] + r.unlistedBytes[scratchWouldDelete]
	for _, item := range r.Items {
		switch item.Status {
		case scratchArchived:
			r.Archived++
			r.FreedBytes += item.SizeBytes
		case scratchDeleted:
			r.Deleted++
			r.FreedBytes += item.SizeBytes
		case scratchWouldArchive:
			r.WouldArchive++
			r.WouldFreeBytes += item.SizeBytes
		case scratchWouldDelete:
			r.WouldDelete++
			r.WouldFreeBytes += item.SizeBytes
		case scratchKept:
			r.Kept++
		case scratchSkipped:
			r.Skipped++
		case scratchDeferred:
			r.Deferred++
		case scratchFailed:
			r.Failed++
		}
	}
}

// scratchCleanup runs one scratch directory: it observes every depth-1
// entry, keeps whatever policy, a process, a sensitive name, an unsupported
// member or a recent change protects, and (unless dryRun) archives the
// rest that is not regenerable into one verified archive. Only after that
// archive is published and read back does it delete anything, each entry
// after a fresh in-use and unchanged check, recording a receipt per entry.
//
// A regenerableOnly run selects only regenerable entries, archives nothing
// and is recorded as its own kind, so it never resets the full sweep's
// cadence.
func scratchCleanup(ctx context.Context, paths config.Paths, policy config.Policy, scratch config.ScratchCleanup, dryRun, regenerableOnly bool) (scratchRunReport, error) {
	now := scratchNow()
	report := scratchRunReport{Path: scratch.Path, DryRun: dryRun, Status: "preview", Items: []scratchItem{},
		Attribution: "Sizes are the local bytes of regular files. Archived bytes on the archive mount are never counted as local headroom."}
	// A preview records nothing, so it reports no run ID, but its receipt
	// estimate still sizes one: otherwise it would admit entries an acting
	// run defers.
	runID := scratchRunID(now)
	if !dryRun {
		report.RunID = runID
	}
	fail := func(err error) (scratchRunReport, error) {
		report.Status, report.Error = "failed", err.Error()
		report.count()
		return report, fmt.Errorf("scratch cleanup of %s: %w", scratch.Path, err)
	}
	var unlock func()
	if !dryRun {
		if err := config.EnsureDir(paths.StateDir); err != nil {
			return fail(err)
		}
		var err error
		if unlock, err = lockApply(paths.StateDir); err != nil {
			return fail(err)
		}
		defer unlock()
	}
	dir, err := workspacearchive.OpenScratch(scratch.Path)
	if err != nil {
		return fail(err)
	}
	defer dir.Close()
	used, err := workspacearchive.ScratchReferences(ctx, policy.Collectors.ProcRoot, scratch.Path)
	if err != nil {
		return fail(fmt.Errorf("nothing is touched: %w", err))
	}
	// The name listing is the only structure that grows with the directory:
	// a scratch directory may hold far more entries than an inventory scan
	// directory, so it has its own bound, and exceeding it refuses the run
	// rather than cleaning a partial listing.
	names, err := dir.Names(scratch.MaxEntries)
	if err != nil {
		return fail(fmt.Errorf("nothing is touched: %w", err))
	}
	// Pass 1 keeps only a fixed-size record per candidate. Every entry is
	// counted, and listed only up to a bound.
	type pending struct {
		name          string
		newestMtimeNS int64
		size          int64
		identity      core.FilesystemID
		regenerable   bool
	}
	var found []pending
	for _, name := range names {
		item := scratchItem{Entry: name, Path: filepath.Join(scratch.Path, name), Status: scratchKept}
		if config.MatchesAny(name, scratch.Skip) {
			item.Status, item.Reason = scratchSkipped, "matches a skip pattern"
			report.list(item)
			continue
		}
		entry, reason := scratchCheck(ctx, dir, policy, scratch, used, name, now)
		item.SizeBytes = entry.SizeBytes
		if entry.Members != 0 {
			item.IdleFor = scratchIdle(now, entry.NewestMtimeNS).Truncate(time.Second).String()
		}
		if reason != "" {
			item.Reason = reason
			report.list(item)
			continue
		}
		found = append(found, pending{name: name, newestMtimeNS: entry.NewestMtimeNS, size: entry.SizeBytes, identity: entry.Identity,
			regenerable: config.MatchesAny(name, scratch.Regenerable)})
	}

	names = nil
	// Oldest first: the bound keeps the longest-idle entries. Pass 2 observes
	// only the selected entries again; their member lists are the run's
	// archive, bounded by max_bytes_per_run.
	sort.SliceStable(found, func(i, j int) bool { return found[i].newestMtimeNS < found[j].newestMtimeNS })
	var selected, archive []scratchCandidate
	var total int64
	// The run receipt names every archived entry and has a fixed size bound;
	// entries that would overflow it are deferred before any archive exists.
	// The manifest name and checksum are sized at their final lengths.
	receipt := store.ScratchRunReceiptBytes(store.ScratchRun{RunID: runID, Path: scratch.Path, StartedAt: now, RecordedAt: now,
		ArchiveDirectory: scratch.Archive.Directory, ArchiveManifest: filepath.Join(scratch.Archive.Directory, workspacearchive.ScratchArchiveName(runID)+".manifest.json"),
		ArchiveManifestSHA256: strings.Repeat("0", 64)})
	for _, next := range found {
		item := scratchItem{Entry: next.name, Path: filepath.Join(scratch.Path, next.name), SizeBytes: next.size,
			IdleFor: scratchIdle(now, next.newestMtimeNS).Truncate(time.Second).String()}
		if regenerableOnly && !next.regenerable {
			item.Status, item.Reason = scratchKept, "not regenerable; left for the full sweep"
			report.list(item)
			continue
		}
		if scratch.MaxBytesPerRun > 0 && total+next.size > scratch.MaxBytesPerRun {
			item.Status, item.Reason = scratchDeferred, fmt.Sprintf("max_bytes_per_run %d reached; retried next run", scratch.MaxBytesPerRun)
			report.list(item)
			continue
		}
		if !next.regenerable {
			encoded, _ := json.Marshal(next.name)
			if receipt+len(encoded)+1 > store.ScratchRunReceiptMaxBytes {
				item.Status, item.Reason = scratchDeferred, "run receipt size bound reached; retried next run"
				report.list(item)
				continue
			}
		}
		entry, reason := scratchCheck(ctx, dir, policy, scratch, used, next.name, now)
		if reason == "" && entry.Identity != next.identity {
			reason = "replaced while the directory was being listed"
		}
		if reason != "" {
			item.Status, item.Reason = scratchKept, reason
			report.list(item)
			continue
		}
		total += entry.SizeBytes
		if !next.regenerable {
			encoded, _ := json.Marshal(next.name)
			receipt += len(encoded) + 1
		}
		item.SizeBytes = entry.SizeBytes
		item.Status, item.Reason = scratchWouldArchive, "would be archived, verified and then deleted"
		if next.regenerable {
			item.Status, item.Reason = scratchWouldDelete, "would be deleted without an archive (matches a regenerable pattern)"
		}
		candidate := scratchCandidate{item: report.slot(item), entry: entry, regenerable: next.regenerable, status: item.Status, reason: item.Reason}
		if !candidate.regenerable {
			archive = append(archive, candidate)
		}
		selected = append(selected, candidate)
	}
	found = nil
	if dryRun {
		report.settle(selected)
		return report, nil
	}

	failAll := func(err error) (scratchRunReport, error) {
		for i := range selected {
			report.set(&selected[i], scratchFailed, "nothing deleted: "+err.Error())
		}
		report.settle(selected)
		report.Status, report.Error = "failed", err.Error()
		return report, fmt.Errorf("scratch cleanup of %s: %w", scratch.Path, err)
	}
	run := store.ScratchRun{RunID: report.RunID, Path: scratch.Path, StartedAt: now, ArchivedEntries: []string{}}
	if regenerableOnly {
		run.Kind = store.ScratchRunRegenerable
	}
	if len(archive) != 0 {
		entries := make([]workspacearchive.ScratchEntry, len(archive))
		for i, candidate := range archive {
			entries[i] = candidate.entry
		}
		preflight := func() error { return scratchPreflight(paths, scratch, entries) }
		m, binding, err := createScratchArchive(dir, ctx, scratch.Archive, report.RunID, entries, preflight)
		if err != nil {
			return failAll(fmt.Errorf("archive: %w", err))
		}
		// Read the published archive back once more, from the archive
		// directory alone, before anything is deleted.
		if _, err := workspacearchive.CheckScratch(ctx, scratch.Archive, *binding); err != nil {
			return failAll(fmt.Errorf("archive verification: %w", err))
		}
		files := 0
		for _, member := range m.Members {
			if member.Type == workspacearchive.TypeFile {
				files++
			}
		}
		report.Archive = &scratchArchiveSummary{Manifest: binding.Manifest, ManifestSHA256: binding.ManifestSHA256, TarBytes: m.TarBytes, Files: files, Entries: m.Entries}
		run.ArchiveDirectory, run.ArchiveManifest, run.ArchiveManifestSHA256, run.ArchivedEntries = scratch.Archive.Directory, binding.Manifest, binding.ManifestSHA256, m.Entries
	}
	db, err := store.Open(ctx, paths.DatabaseFile)
	if err != nil {
		return failAll(err)
	}
	defer db.Close()
	run.RecordedAt = time.Now().UTC()
	if err := db.Write(ctx, func(tx *store.Tx) error { return tx.RecordScratchRun(ctx, run) }); err != nil {
		return failAll(err)
	}
	// The policy decides again, freshly loaded, immediately before anything
	// is deleted: a protect.paths, KEEP, skip, regenerable, name-pattern,
	// idle or proc_root change made while the run was in flight still stops
	// its deletions.
	scratchBeforeDeletion()
	latest, err := config.LoadPolicy(paths)
	if err != nil {
		return failAll(fmt.Errorf("policy recheck before deletion: %w", err))
	}
	current, ok := latest.ScratchCleanupFor(scratch.Path)
	if !ok {
		return failAll(fmt.Errorf("scratch_cleanup for %s was withdrawn during the run", scratch.Path))
	}
	used, err = workspacearchive.ScratchReferences(ctx, latest.Collectors.ProcRoot, scratch.Path)
	if err != nil {
		return failAll(fmt.Errorf("in-use recheck: %w", err))
	}
	var failures []error
	for i := range selected {
		candidate := &selected[i]
		path := filepath.Join(scratch.Path, candidate.entry.Name)
		if reason := scratchDeletionRefusal(latest, current, *candidate); reason != "" {
			report.set(candidate, scratchKept, reason)
			continue
		}
		if ref, ok := used[candidate.entry.Name]; ok {
			report.set(candidate, scratchKept, "in use at deletion time: "+ref)
			continue
		}
		if err := dir.Unchanged(candidate.entry); err != nil {
			report.set(candidate, scratchKept, "changed after it was observed; kept local")
			continue
		}
		// Judge idleness by the freshly loaded policy: withdrawing or raising
		// regenerable_idle (or idle) mid-run still stops the deletion.
		if idle := scratchIdle(scratchNow(), candidate.entry.NewestMtimeNS); idle < current.IdleFor(config.MatchesAny(candidate.entry.Name, current.Regenerable)) {
			report.set(candidate, scratchKept, "no longer idle at deletion time")
			continue
		}
		// The observed ctime is checked again at removal, so an entry
		// replaced by a new one that reuses its inode is not deleted.
		if err := action.RemoveAnchored(ctx, path, candidate.entry.Identity, candidate.entry.CtimeNS); err != nil {
			report.set(candidate, scratchFailed, "removal: "+err.Error())
			failures = append(failures, fmt.Errorf("%s: %w", path, err))
			continue
		}
		deletion := store.ScratchDeletion{RunID: run.RunID, Path: scratch.Path, Entry: candidate.entry.Name, SizeBytes: candidate.entry.SizeBytes, DeletedAt: time.Now().UTC()}
		status := scratchDeleted
		deletion.Disposition = store.ScratchRegenerable
		if !candidate.regenerable {
			status, deletion.Disposition, deletion.ArchiveManifest = scratchArchived, store.ScratchArchived, run.ArchiveManifest
		}
		report.set(candidate, status, "")
		if err := db.Write(ctx, func(tx *store.Tx) error { return tx.RecordScratchDeletion(ctx, deletion) }); err != nil {
			failures = append(failures, fmt.Errorf("%s was deleted but its receipt was not recorded: %w", path, err))
		}
	}
	report.Status = "completed"
	if len(failures) != 0 {
		report.Status = "completed_with_failures"
	}
	report.settle(selected)
	return report, errors.Join(failures...)
}

// scratchBeforeDeletion runs just before the deletion re-check; tests use
// it to change the policy while a run is in flight.
var scratchBeforeDeletion = func() {}

// scratchDeletionRefusal re-applies the freshly loaded policy to one
// selected entry: protect.paths and KEEP, the skip list, the regenerable
// classification it was selected under (an entry deleted without an archive
// must still be regenerable) and the sensitive-name screen over every member.
func scratchDeletionRefusal(policy config.Policy, scratch config.ScratchCleanup, c scratchCandidate) string {
	path := filepath.Join(scratch.Path, c.entry.Name)
	if reason := policy.ScratchRefusal(path); reason != "" {
		return "policy now keeps it: " + reason
	}
	if config.MatchesAny(c.entry.Name, scratch.Skip) {
		return "policy now skips it"
	}
	if c.regenerable && !config.MatchesAny(c.entry.Name, scratch.Regenerable) {
		return "no longer matches a regenerable pattern and was not archived; kept local"
	}
	if name := c.entry.SensitiveMember(scratch.Path, policy.Protect.NamePatterns); name != "" {
		return fmt.Sprintf("sensitive name %s now keeps the entry local", name)
	}
	return ""
}

// scratchCheck observes one entry and returns why it must stay, if it must:
// policy, a process, an unobservable or unsupported member, a sensitive name
// or a recent (or future) mtime. It never touches the entry.
func scratchCheck(ctx context.Context, dir *workspacearchive.ScratchDir, policy config.Policy, scratch config.ScratchCleanup, used map[string]string, name string, now time.Time) (workspacearchive.ScratchEntry, string) {
	if reason := policy.ScratchRefusal(filepath.Join(scratch.Path, name)); reason != "" {
		return workspacearchive.ScratchEntry{Name: name}, reason
	}
	if ref, ok := used[name]; ok {
		return workspacearchive.ScratchEntry{Name: name}, "in use: " + ref
	}
	entry, err := dir.Observe(ctx, name, policy.Protect.NamePatterns, policy.Limits.DeepSizeMaxEntries)
	if err != nil {
		return entry, "could not be observed: " + err.Error()
	}
	newest, idle := time.Unix(0, entry.NewestMtimeNS), scratchIdle(now, entry.NewestMtimeNS)
	switch {
	case entry.Refusal != "":
		return entry, entry.Refusal
	case entry.Sensitive != "":
		return entry, fmt.Sprintf("sensitive name %s keeps the entry local", entry.Sensitive)
	case newest.After(now):
		return entry, fmt.Sprintf("a member's mtime %s is in the future; counted as changed now", newest.UTC().Format(time.RFC3339))
	case idle < scratch.IdleFor(config.MatchesAny(name, scratch.Regenerable)):
		return entry, fmt.Sprintf("changed %s ago; scratch entries must be unchanged for %s", idle.Truncate(time.Second), scratch.IdleFor(config.MatchesAny(name, scratch.Regenerable)))
	}
	return entry, ""
}

// scratchPreflight re-reads the policy file before and after the slow copy:
// a withdrawn or changed scratch entry, or a KEEP/protection added meanwhile,
// refuses the archive and leaves everything in place.
func scratchPreflight(paths config.Paths, scratch config.ScratchCleanup, entries []workspacearchive.ScratchEntry) error {
	current, err := config.LoadPolicy(paths)
	if err != nil {
		return fmt.Errorf("policy recheck refused the scratch archive: %w", err)
	}
	latest, ok := current.ScratchCleanupFor(scratch.Path)
	if !ok || latest.Archive != scratch.Archive {
		return fmt.Errorf("scratch_cleanup for %s was withdrawn or its archive changed; nothing is deleted", scratch.Path)
	}
	for _, entry := range entries {
		path := filepath.Join(scratch.Path, entry.Name)
		if reason := current.ScratchRefusal(path); reason != "" {
			return fmt.Errorf("policy now keeps %s: %s; nothing is deleted", path, reason)
		}
		if config.MatchesAny(entry.Name, latest.Skip) {
			return fmt.Errorf("policy now skips %s; nothing is deleted", path)
		}
	}
	return nil
}

// scratchDue reports whether scratch has not run for its interval.
func scratchDue(ctx context.Context, paths config.Paths, scratch config.ScratchCleanup, now time.Time) (bool, time.Time, error) {
	last, err := store.ReadLastScratchRun(ctx, paths.DatabaseFile, scratch.Path, "")
	if err != nil {
		return false, time.Time{}, err
	}
	next := last.Add(scratch.Every.Duration())
	return last.IsZero() || !next.After(now), next, nil
}

// scratchRegenerableTick is how often the watcher checks whether a
// regenerable-only pass is due; the due time itself comes from the store,
// so a watcher restart neither skips nor repeats a pass.
var scratchRegenerableTick = 5 * time.Minute

func scratchRegenerableConfigured(policy config.Policy) bool {
	for _, scratch := range policy.ScratchCleanup {
		if scratch.RegenerableEvery.Duration() > 0 {
			return true
		}
	}
	return false
}

// scratchRegenerableLoop runs, from the watcher, each scratch directory's
// regenerable-only pass whenever its regenerable_every is due. A pass that
// finds the apply lock held (a cycle or apply is running) is reported busy
// and retried at the next tick; any other pass failure is reported and does
// not stop the watcher. Only a report that cannot be written does.
func scratchRegenerableLoop(ctx context.Context, e *env, paths config.Paths, policy config.Policy) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
		var reports []scratchRunReport
		for _, scratch := range policy.ScratchCleanup {
			every := scratch.RegenerableEvery.Duration()
			if every <= 0 {
				continue
			}
			last, err := store.ReadLastScratchRun(ctx, paths.DatabaseFile, scratch.Path, store.ScratchRunRegenerable)
			if err != nil && !errors.Is(err, store.ErrNotInitialized) {
				reports = append(reports, scratchRunReport{Path: scratch.Path, Status: "failed", Error: err.Error(), Items: []scratchItem{}})
				continue
			}
			if !last.IsZero() && scratchNow().Before(last.Add(every)) {
				continue
			}
			report, err := scratchCleanup(ctx, paths, policy, scratch, false, true)
			if ctx.Err() != nil {
				return nil
			}
			if err != nil && strings.Contains(err.Error(), "another janitor apply or restore is active") {
				report = scratchRunReport{Path: scratch.Path, Status: "busy", Error: "apply lock held; retried next tick", Items: []scratchItem{}}
			}
			reports = append(reports, report)
		}
		if len(reports) > 0 {
			if err := writeWatchReport(e, watchReport{Reason: "scratch_regenerable", ScratchCleanup: reports}); err != nil {
				return fmt.Errorf("scratch report: %w", err)
			}
		}
		timer.Reset(scratchRegenerableTick)
	}
}

// cycleScratchCleanup is the daily cycle's scratch step: every configured
// directory that is due runs once.
func cycleScratchCleanup(ctx context.Context, paths config.Paths, policy config.Policy) ([]scratchRunReport, error) {
	var reports []scratchRunReport
	var failures []error
	now := scratchNow()
	for _, scratch := range policy.ScratchCleanup {
		due, next, err := scratchDue(ctx, paths, scratch, now)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !due {
			reports = append(reports, scratchRunReport{Path: scratch.Path, Status: "not_due", NextDue: &next, Items: []scratchItem{}})
			continue
		}
		report, err := scratchCleanup(ctx, paths, policy, scratch, false, false)
		reports = append(reports, report)
		if err != nil {
			failures = append(failures, err)
		}
	}
	return reports, errors.Join(failures...)
}

type scratchOptions struct {
	dryRun, confirm bool
	path, restoreTo string
}

func scratchCommand() *command {
	return &command{
		name:    "scratch",
		usage:   "janitor scratch [--path DIR] [--dry-run=false --confirm] | janitor scratch restore RUN ENTRY [--restore-to PATH] [--dry-run=false --confirm]",
		summary: "Archive and remove idle entries of opt-in scratch directories (scratch_cleanup), or restore one archived entry",
		long: "Previews by default. Entries matching skip are never touched; regenerable entries are deleted without\n" +
			"an archive; every other idle, unused entry is archived into one verified archive per run before deletion.\n" +
			"Sensitive names (built-in screen and protect.name_patterns) anywhere inside keep an entry local.",
		register: func(fs *flag.FlagSet) func(ctx context.Context, e *env, args []string) error {
			opts := scratchOptions{}
			fs.BoolVar(&opts.dryRun, "dry-run", true, "preview without archiving, deleting or restoring")
			fs.BoolVar(&opts.confirm, "confirm", false, "required with --dry-run=false")
			fs.StringVar(&opts.path, "path", "", "run only this configured scratch directory")
			fs.StringVar(&opts.restoreTo, "restore-to", "", "restore destination (default: the entry's original path); never overwritten")
			return func(ctx context.Context, e *env, args []string) error {
				// Flags may follow "restore RUN ENTRY".
				var positional []string
				for rest := args; len(rest) != 0; {
					if err := fs.Parse(rest); err != nil {
						return &usageError{msg: err.Error()}
					}
					left := fs.Args()
					if len(left) == 0 {
						break
					}
					positional, rest = append(positional, left[0]), left[1:]
				}
				if !opts.dryRun && !opts.confirm {
					return &usageError{msg: "--confirm is required with --dry-run=false"}
				}
				switch {
				case len(positional) == 0:
					if opts.restoreTo != "" {
						return &usageError{msg: "--restore-to applies only to scratch restore"}
					}
					return runScratch(ctx, e, opts)
				case positional[0] == "restore" && len(positional) == 3:
					return runScratchRestore(ctx, e, positional[1], positional[2], opts)
				default:
					return &usageError{msg: "usage: janitor scratch [flags] | janitor scratch restore RUN ENTRY [flags]"}
				}
			}
		},
	}
}

func runScratch(ctx context.Context, e *env, opts scratchOptions) error {
	format, err := e.format()
	if err != nil {
		return err
	}
	paths, err := e.resolvePaths()
	if err != nil {
		return err
	}
	policy, err := e.loadFilePolicy()
	if err != nil {
		return err
	}
	if len(policy.ScratchCleanup) == 0 {
		return errors.New("no scratch_cleanup directories are configured")
	}
	report := scratchReport{Mode: "scratch_cleanup", DryRun: opts.dryRun, Runs: []scratchRunReport{}}
	var failures []error
	matched := false
	for _, scratch := range policy.ScratchCleanup {
		if opts.path != "" && scratch.Path != opts.path {
			continue
		}
		matched = true
		run, err := scratchCleanup(ctx, paths, policy, scratch, opts.dryRun, false)
		report.Runs = append(report.Runs, run)
		if err != nil {
			failures = append(failures, err)
		}
	}
	if !matched {
		return fmt.Errorf("%s is not a configured scratch_cleanup path", opts.path)
	}
	if err := writeScratchReport(e, format, report); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func writeScratchReport(e *env, format output.Format, report scratchReport) error {
	if format == output.FormatJSON {
		return output.WriteJSON(e.stdout, report.Mode, report)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "mode: %s\ndry run: %t\n", report.Mode, report.DryRun)
	for _, run := range report.Runs {
		fmt.Fprintf(&b, "\n%s  status %s", run.Path, run.Status)
		if run.RunID != "" {
			fmt.Fprintf(&b, "  run %s", run.RunID)
		}
		fmt.Fprintf(&b, "\narchived+deleted: %d  regenerable deleted: %d  kept: %d  skipped: %d  deferred: %d  failed: %d  local freed bytes: %d\n",
			run.Archived, run.Deleted, run.Kept, run.Skipped, run.Deferred, run.Failed, run.FreedBytes)
		if run.Error != "" {
			fmt.Fprintf(&b, "error: %s\n", run.Error)
		}
		if run.Archive != nil {
			fmt.Fprintf(&b, "archive: %s (%d files verified)\n", run.Archive.Manifest, run.Archive.Files)
		}
		if run.DryRun {
			fmt.Fprintf(&b, "would archive+delete: %d  would delete (regenerable): %d  would free local bytes: %d\n", run.WouldArchive, run.WouldDelete, run.WouldFreeBytes)
		}
		if run.Unlisted != 0 {
			fmt.Fprintf(&b, "%d entries are counted but not listed\n", run.Unlisted)
		}
		for _, item := range run.Items {
			if item.Status == scratchSkipped {
				continue
			}
			fmt.Fprintf(&b, "  %-20s %s  %d bytes", item.Status, item.Entry, item.SizeBytes)
			if item.Reason != "" {
				fmt.Fprintf(&b, "  (%s)", item.Reason)
			}
			b.WriteString("\n")
		}
	}
	_, err := fmt.Fprint(e.stdout, b.String())
	return err
}

type scratchRestoreReport struct {
	Mode       string `json:"mode"`
	DryRun     bool   `json:"dry_run"`
	RunID      string `json:"run_id"`
	Entry      string `json:"entry"`
	Manifest   string `json:"manifest"`
	RestoredTo string `json:"restored_to"`
	Status     string `json:"status"`
}

// runScratchRestore restores one archived entry of a recorded run. It
// previews by default; it never overwrites anything.
func runScratchRestore(ctx context.Context, e *env, runID, entry string, opts scratchOptions) error {
	format, err := e.format()
	if err != nil {
		return err
	}
	paths, err := e.resolvePaths()
	if err != nil {
		return err
	}
	policy, err := e.loadFilePolicy()
	if err != nil {
		return err
	}
	// Receipts are read without creating, migrating or writing the
	// database, so a verify-only restore leaves Janitor's state untouched.
	run, found, err := store.ReadScratchRun(ctx, paths.DatabaseFile, runID)
	if err != nil {
		return err
	}
	archived := false
	for _, name := range run.ArchivedEntries {
		archived = archived || name == entry
	}
	if !found || !archived {
		return fmt.Errorf("scratch run %q archived no entry %q", runID, entry)
	}
	destination := opts.restoreTo
	if destination == "" {
		destination = filepath.Join(run.Path, entry)
	}
	// Mount expectations come from the policy while it still names the same
	// archive directory; they are never part of the receipt.
	dest := config.WorkspaceArchiveCategoryDestination{Directory: run.ArchiveDirectory}
	if scratch, ok := policy.ScratchCleanupFor(run.Path); ok && scratch.Archive.Directory == run.ArchiveDirectory {
		dest = scratch.Archive
	}
	binding := workspacearchive.Binding{Manifest: run.ArchiveManifest, ManifestSHA256: run.ArchiveManifestSHA256}
	report := scratchRestoreReport{Mode: "scratch_restore", DryRun: opts.dryRun, RunID: runID, Entry: entry, Manifest: run.ArchiveManifest, RestoredTo: destination, Status: "verified"}
	if opts.dryRun {
		if _, err := workspacearchive.CheckScratch(ctx, dest, binding); err != nil {
			return err
		}
	} else {
		// Restores serialize with apply, quarantine restore and scratch runs.
		unlock, err := lockRestore(paths.StateDir)
		if err != nil {
			return err
		}
		_, err = workspacearchive.RestoreScratch(ctx, dest, binding, entry, destination)
		unlock()
		if err != nil {
			return err
		}
		report.Status = "restored"
	}
	if format == output.FormatJSON {
		return output.WriteJSON(e.stdout, report.Mode, report)
	}
	_, err = fmt.Fprintf(e.stdout, "mode: %s\nrun: %s\nentry: %s\narchive: %s\n%s to %s\n", report.Mode, runID, entry, report.Manifest, report.Status, destination)
	return err
}
