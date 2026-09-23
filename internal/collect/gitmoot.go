package collect

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
	_ "modernc.org/sqlite"
)

// Gitmoot owns the cleanup lifecycle. Even a reclaimable observation is only
// advice to ask Gitmoot to clean up; it never authorizes generic mutation.
const gitmootMinimumAge = 24 * time.Hour

func collectGitmoot(ctx context.Context, opts *Options, entries []core.Entry, now time.Time) core.CollectorReport {
	report := core.CollectorReport{Name: CollectorGitmoot, Status: core.CollectorRan}
	if opts.GitmootHome == "" {
		report.Status = core.CollectorSkipped
		report.Detail = "no Gitmoot home configured"
		return report
	}
	if _, err := os.Lstat(opts.GitmootHome); errors.Is(err, os.ErrNotExist) {
		report.Status = core.CollectorSkipped
		report.Detail = "Gitmoot home does not exist"
		return report
	}
	managed := make([]bool, len(entries))
	for i := range entries {
		managed[i] = core.PathWithin(entries[i].Path, opts.GitmootHome)
	}
	mark := func(entry *core.Entry, signal, detail string, unknown bool) {
		if unknown {
			addUnknown(entry, core.SourceJob, core.ProtectOwningJob, "gitmoot", detail, now)
			report.Unknowns++
		} else {
			addEvidence(entry, core.Evidence{Source: core.SourceJob, Signal: "gitmoot:" + signal,
				Detail: detail, ObservedAt: now})
			addProtection(entry, core.Protection{Kind: core.ProtectOwningJob, Source: core.SourceJob,
				Reason: "Gitmoot-managed worktree; use Gitmoot's own lifecycle cleanup", Blocking: true})
		}
		report.Recorded++
	}
	fail := func(err error) core.CollectorReport {
		report.Status = core.CollectorPartial
		report.Detail = fmt.Sprintf("Gitmoot observation unavailable: %v", err)
		report.Recorded = 0
		report.Unknowns = 0
		for i := range entries {
			if managed[i] {
				entries[i].Evidence = removeGitmootEvidence(entries[i].Evidence)
				mark(&entries[i], "", report.Detail, true)
			}
		}
		return report
	}
	if !core.IsCanonicalPath(opts.GitmootHome) || !core.IsCanonicalPath(opts.GitmootDatabase) {
		return fail(errors.New("home or database path is not canonical"))
	}
	if resolved, err := filepath.EvalSymlinks(opts.GitmootHome); err != nil || resolved != opts.GitmootHome {
		return fail(errors.New("Gitmoot home could not be verified without symlinks"))
	}
	if _, err := os.Stat(opts.GitmootDatabase); err != nil {
		return fail(err)
	}
	uri := (&url.URL{Scheme: "file", Path: opts.GitmootDatabase, RawQuery: "mode=ro&_pragma=query_only(1)"}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return fail(err)
	}
	defer db.Close()
	// One bounded read-only transaction gives all per-entry lookups the same
	// SQLite snapshot. An incomplete observation never yields reclaim advice.
	observeCtx, cancel := context.WithTimeout(ctx, opts.Limits.CommandTimeout)
	defer cancel()
	db.SetMaxOpenConns(1)
	tx, err := db.BeginTx(observeCtx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback()
	var malformed int
	if err := tx.QueryRowContext(observeCtx, `SELECT EXISTS(SELECT 1 FROM jobs
		WHERE state NOT IN ('succeeded','failed','cancelled') AND NOT json_valid(payload))`).Scan(&malformed); err != nil {
		return fail(err)
	}
	refs, err := loadGitmootRefs(observeCtx, tx, entries, opts.Limits.MaxEntries)
	if err != nil {
		return fail(err)
	}
	for i := range entries {
		entry := &entries[i]
		inside := managed[i]
		// DB records may name other scanned locations. Only an exact path match
		// receives protection there; never protect an arbitrary parent entry.
		reference := refs[entry.Path]
		job, jobs := reference.job, reference.jobs
		task, tasks := reference.task, reference.tasks
		obligation, obligations := reference.obligation, reference.obligations
		if !inside && jobs == 0 && tasks == 0 && obligations == 0 {
			continue
		}
		if !inside {
			mark(entry, "", "Gitmoot references an inventory path outside its managed home; provenance cannot authorize reclamation", true)
			continue
		}
		resolved, resolveErr := filepath.EvalSymlinks(entry.Path)
		if resolveErr != nil || resolved != entry.Path || entry.Kind == core.EntryKindSymlink {
			mark(entry, "", "Gitmoot path has unverifiable identity or a symlink escape", true)
			continue
		}
		if jobs > 1 || tasks > 1 || obligations > 1 || malformed != 0 {
			mark(entry, "", "Gitmoot owner identity is ambiguous or an active payload is malformed", true)
			continue
		}
		if jobs == 1 && (job.state == "queued" || job.state == "running" || job.state == "blocked") ||
			tasks == 1 && !gitmootTerminalTask(task.state) {
			mark(entry, "pinned", "Gitmoot has a resumable job or active task reference for this exact path", false)
			continue
		}
		if jobs != 1 || obligations != 1 || job.id == "" || obligation.owner == "" || obligation.owner != job.id ||
			obligation.kind != "delegation_worktree" ||
			(obligation.state != "pending" && obligation.state != "retryable") ||
			(job.state != "succeeded" && job.state != "failed" && job.state != "cancelled") ||
			tasks != 0 {
			mark(entry, "", "Gitmoot cannot prove a final owner and live cleanup obligation for this exact path", true)
			continue
		}
		jobAt, jobOK := gitmootTime(job.updated)
		obligationAt, obligationOK := gitmootTime(obligation.created)
		obligationUpdated, updatedOK := gitmootTime(obligation.updated)
		if !jobOK || !obligationOK || !updatedOK ||
			jobAt.After(now.Add(-gitmootMinimumAge)) ||
			obligationAt.After(now.Add(-gitmootMinimumAge)) ||
			obligationUpdated.Before(obligationAt) || obligationUpdated.After(now) || jobAt.After(now) {
			mark(entry, "", "Gitmoot final owner age or obligation timestamp is unproven", true)
			continue
		}
		mark(entry, "final_reclaimable", fmt.Sprintf("Gitmoot job %s is final with a live %s obligation; reclaim only through Gitmoot", job.id, obligation.state), false)
	}
	if err := tx.Commit(); err != nil {
		return fail(err)
	}
	return report
}

func removeGitmootEvidence(evidence []core.Evidence) []core.Evidence {
	filtered := evidence[:0]
	for _, e := range evidence {
		if e.Signal != "unknown:gitmoot" && !strings.HasPrefix(e.Signal, "gitmoot:") {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

type gitmootJobRow struct{ id, state, updated string }
type gitmootTaskRow struct{ state string }
type gitmootObligationRow struct{ owner, state, kind, created, updated string }

type gitmootRefs struct {
	job         gitmootJobRow
	jobs        int
	task        gitmootTaskRow
	tasks       int
	obligation  gitmootObligationRow
	obligations int
}

// Load each ledger once. A path-by-path json_extract scan would read the
// entire jobs table once per inventory entry on a real Gitmoot home.
func loadGitmootRefs(ctx context.Context, tx *sql.Tx, entries []core.Entry, limit int) (map[string]gitmootRefs, error) {
	if limit <= 0 {
		limit = 20000
	}
	wanted := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		wanted[entry.Path] = struct{}{}
	}
	refs := make(map[string]gitmootRefs)
	jobs, err := tx.QueryContext(ctx, `SELECT id, state, updated_at, json_extract(payload, '$.worktree_path') FROM jobs
		WHERE CASE WHEN json_valid(payload) THEN json_type(payload, '$.worktree_path') = 'text'
			AND json_extract(payload, '$.worktree_path') <> '' ELSE 0 END LIMIT ?`, limit+1)
	if err != nil {
		return nil, err
	}
	count := 0
	for jobs.Next() {
		var id, state, updated, path string
		if err = jobs.Scan(&id, &state, &updated, &path); err != nil {
			break
		}
		count++
		if _, ok := wanted[path]; ok {
			ref := refs[path]
			ref.job, ref.jobs = gitmootJobRow{id, state, updated}, ref.jobs+1
			refs[path] = ref
		}
	}
	if err == nil {
		err = jobs.Err()
	}
	if closeErr := jobs.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	if count > limit {
		return nil, fmt.Errorf("Gitmoot job reference limit %d reached", limit)
	}

	tasks, err := tx.QueryContext(ctx, `SELECT state, worktree_path FROM tasks
		WHERE worktree_path IS NOT NULL AND worktree_path <> '' LIMIT ?`, limit+1)
	if err != nil {
		return nil, err
	}
	count = 0
	for tasks.Next() {
		var state, path string
		if err = tasks.Scan(&state, &path); err != nil {
			break
		}
		count++
		if _, ok := wanted[path]; ok {
			ref := refs[path]
			ref.task, ref.tasks = gitmootTaskRow{state}, ref.tasks+1
			refs[path] = ref
		}
	}
	if err == nil {
		err = tasks.Err()
	}
	if closeErr := tasks.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	if count > limit {
		return nil, fmt.Errorf("Gitmoot task reference limit %d reached", limit)
	}

	obligations, err := tx.QueryContext(ctx, `SELECT owner_job_id, state, resource_kind, created_at, updated_at, expected_path
		FROM cleanup_obligations WHERE expected_path <> '' LIMIT ?`, limit+1)
	if err != nil {
		return nil, err
	}
	count = 0
	for obligations.Next() {
		var owner, state, kind, created, updated, path string
		if err = obligations.Scan(&owner, &state, &kind, &created, &updated, &path); err != nil {
			break
		}
		count++
		if _, ok := wanted[path]; ok {
			ref := refs[path]
			ref.obligation, ref.obligations = gitmootObligationRow{owner, state, kind, created, updated}, ref.obligations+1
			refs[path] = ref
		}
	}
	if err == nil {
		err = obligations.Err()
	}
	if closeErr := obligations.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, err
	}
	if count > limit {
		return nil, fmt.Errorf("Gitmoot obligation reference limit %d reached", limit)
	}
	return refs, nil
}

func gitmootTerminalTask(state string) bool {
	switch state {
	case "merged", "dismissed", "superseded", "stranded":
		return true
	default:
		return false
	}
}

func gitmootTime(value string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}
