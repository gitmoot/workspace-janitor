package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/core"
)

// CreateScan inserts a new scan run.
func (t *Tx) CreateScan(ctx context.Context, scan core.Scan) error {
	scan.Normalize()
	if err := scan.Validate(); err != nil {
		return fmt.Errorf("store: invalid scan: %w", err)
	}
	roots, collectors, err := encodeScanColumns(scan)
	if err != nil {
		return err
	}
	_, err = t.tx.ExecContext(ctx,
		`INSERT INTO scans (id, contract_version, roots, status, started_at, finished_at, entry_count, error, collectors)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scan.ID, scan.ContractVersion, roots, string(scan.Status),
		formatTime(scan.StartedAt), nullableTime(scan.FinishedAt), scan.EntryCount, scan.Error, collectors,
	)
	if err != nil {
		return fmt.Errorf("store: insert scan %s: %w", scan.ID, err)
	}
	return nil
}

// UpdateScan replaces the mutable fields of an existing scan.
func (t *Tx) UpdateScan(ctx context.Context, scan core.Scan) error {
	scan.Normalize()
	if err := scan.Validate(); err != nil {
		return fmt.Errorf("store: invalid scan: %w", err)
	}
	roots, collectors, err := encodeScanColumns(scan)
	if err != nil {
		return err
	}
	res, err := t.tx.ExecContext(ctx,
		`UPDATE scans SET roots = ?, status = ?, started_at = ?, finished_at = ?, entry_count = ?, error = ?, collectors = ?
		 WHERE id = ?`,
		roots, string(scan.Status), formatTime(scan.StartedAt),
		nullableTime(scan.FinishedAt), scan.EntryCount, scan.Error, collectors, scan.ID,
	)
	if err != nil {
		return fmt.Errorf("store: update scan %s: %w", scan.ID, err)
	}
	return requireAffected(res, fmt.Sprintf("scan %s", scan.ID))
}

// Scan loads one scan by id.
func (t *Tx) Scan(ctx context.Context, id string) (core.Scan, error) {
	row := t.tx.QueryRowContext(ctx,
		`SELECT id, contract_version, roots, status, started_at, finished_at, entry_count, error, collectors
		 FROM scans WHERE id = ?`, id)
	scan, err := scanScanRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return core.Scan{}, fmt.Errorf("%w: scan %s", ErrNotFound, id)
	}
	return scan, err
}

// ListScans returns scans newest first, bounded by limit (0 means all).
func (t *Tx) ListScans(ctx context.Context, limit int) ([]core.Scan, error) {
	query := `SELECT id, contract_version, roots, status, started_at, finished_at, entry_count, error, collectors
	          FROM scans ORDER BY started_at DESC, id DESC`
	args := []any{}
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := t.tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list scans: %w", err)
	}
	defer rows.Close()
	var out []core.Scan
	for rows.Next() {
		scan, err := scanScanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, scan)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list scans: %w", err)
	}
	return out, nil
}

// LatestScan returns the most recent scan with the given status. It reports
// ErrNotFound when no such scan exists.
func (t *Tx) LatestScan(ctx context.Context, status core.ScanStatus) (core.Scan, error) {
	if !status.Valid() {
		return core.Scan{}, fmt.Errorf("store: unknown scan status %q", string(status))
	}
	row := t.tx.QueryRowContext(ctx,
		`SELECT id, contract_version, roots, status, started_at, finished_at, entry_count, error, collectors
		 FROM scans WHERE status = ? ORDER BY started_at DESC, id DESC LIMIT 1`, string(status))
	scan, err := scanScanRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return core.Scan{}, fmt.Errorf("%w: no %s scan", ErrNotFound, status)
	}
	return scan, err
}

// PutEntry inserts or replaces one inventory entry for a scan. The full
// entry document is stored verbatim so later slices can read fields that the
// indexed columns do not carry.
func (t *Tx) PutEntry(ctx context.Context, scanID string, entry core.Entry) error {
	if scanID == "" {
		return errors.New("store: scan id must not be empty")
	}
	entry.Normalize()
	if err := entry.Validate(); err != nil {
		return fmt.Errorf("store: invalid inventory entry: %w", err)
	}
	doc, err := core.MarshalJSON(entry)
	if err != nil {
		return fmt.Errorf("store: encode entry %s: %w", entry.Path, err)
	}
	_, err = t.tx.ExecContext(ctx,
		`INSERT INTO inventories
		   (scan_id, path, root, kind, class, device, inode, size_bytes, modified_at, observed_at, protected, fingerprint, document)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(scan_id, path) DO UPDATE SET
		   root = excluded.root,
		   kind = excluded.kind,
		   class = excluded.class,
		   device = excluded.device,
		   inode = excluded.inode,
		   size_bytes = excluded.size_bytes,
		   modified_at = excluded.modified_at,
		   observed_at = excluded.observed_at,
		   protected = excluded.protected,
		   fingerprint = excluded.fingerprint,
		   document = excluded.document`,
		scanID, entry.Path, entry.Root, string(entry.Kind), string(entry.Class),
		int64(entry.FilesystemID.Device), int64(entry.FilesystemID.Inode), entry.SizeBytes,
		formatTime(entry.ModifiedAt), formatTime(entry.ObservedAt), boolToInt(entry.Protected()),
		entry.Fingerprint, string(doc),
	)
	if err != nil {
		return fmt.Errorf("store: put entry %s: %w", entry.Path, err)
	}
	return nil
}

// Entry loads one inventory entry by scan and path.
func (t *Tx) Entry(ctx context.Context, scanID, path string) (core.Entry, error) {
	var doc string
	err := t.tx.QueryRowContext(ctx,
		`SELECT document FROM inventories WHERE scan_id = ? AND path = ?`, scanID, path).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return core.Entry{}, fmt.Errorf("%w: entry %s in scan %s", ErrNotFound, path, scanID)
	}
	if err != nil {
		return core.Entry{}, fmt.Errorf("store: load entry %s: %w", path, err)
	}
	return decodeEntry(doc)
}

// Entries lists every inventory entry of a scan, ordered by path.
func (t *Tx) Entries(ctx context.Context, scanID string) ([]core.Entry, error) {
	rows, err := t.tx.QueryContext(ctx,
		`SELECT document FROM inventories WHERE scan_id = ? ORDER BY path`, scanID)
	if err != nil {
		return nil, fmt.Errorf("store: list entries: %w", err)
	}
	defer rows.Close()
	var out []core.Entry
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return nil, fmt.Errorf("store: scan entry row: %w", err)
		}
		entry, err := decodeEntry(doc)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list entries: %w", err)
	}
	return out, nil
}

// SavePlan writes a plan and its actions, replacing any previous action set
// for that plan id.
func (t *Tx) SavePlan(ctx context.Context, plan core.Plan) error {
	plan.Normalize()
	if err := plan.Validate(); err != nil {
		return fmt.Errorf("store: invalid plan: %w", err)
	}
	if _, err := t.tx.ExecContext(ctx,
		`INSERT INTO plans (id, scan_id, contract_version, status, created_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   scan_id = excluded.scan_id,
		   contract_version = excluded.contract_version,
		   status = excluded.status,
		   created_at = excluded.created_at`,
		plan.ID, plan.ScanID, plan.ContractVersion, string(plan.Status), formatTime(plan.CreatedAt),
	); err != nil {
		return fmt.Errorf("store: save plan %s: %w", plan.ID, err)
	}
	if _, err := t.tx.ExecContext(ctx, `DELETE FROM actions WHERE plan_id = ?`, plan.ID); err != nil {
		return fmt.Errorf("store: clear actions of plan %s: %w", plan.ID, err)
	}
	for _, action := range plan.Actions {
		reasons, err := core.MarshalJSON(stringsOrEmpty(action.Reasons))
		if err != nil {
			return fmt.Errorf("store: encode reasons of action %s: %w", action.ID, err)
		}
		guards, err := core.MarshalJSON(stringsOrEmpty(action.Guards))
		if err != nil {
			return fmt.Errorf("store: encode guards of action %s: %w", action.ID, err)
		}
		if _, err := t.tx.ExecContext(ctx,
			`INSERT INTO actions
			   (id, plan_id, path, kind, retention, confidence, status, destination, device, inode, reasons, guards, created_at, applied_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			action.ID, plan.ID, action.Path, string(action.Kind), string(action.Retention),
			action.Confidence, string(action.Status), action.Destination,
			int64(action.FilesystemID.Device), int64(action.FilesystemID.Inode),
			string(reasons), string(guards), formatTime(action.CreatedAt), nullableTime(action.AppliedAt),
		); err != nil {
			return fmt.Errorf("store: insert action %s: %w", action.ID, err)
		}
	}
	return nil
}

// Plan loads a plan and its actions.
func (t *Tx) Plan(ctx context.Context, id string) (core.Plan, error) {
	var (
		plan      core.Plan
		status    string
		createdAt string
	)
	err := t.tx.QueryRowContext(ctx,
		`SELECT id, scan_id, contract_version, status, created_at FROM plans WHERE id = ?`, id).
		Scan(&plan.ID, &plan.ScanID, &plan.ContractVersion, &status, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return core.Plan{}, fmt.Errorf("%w: plan %s", ErrNotFound, id)
	}
	if err != nil {
		return core.Plan{}, fmt.Errorf("store: load plan %s: %w", id, err)
	}
	if plan.Status, err = core.ParsePlanStatus(status); err != nil {
		return core.Plan{}, fmt.Errorf("store: plan %s: %w", id, err)
	}
	if plan.CreatedAt, err = parseTime(createdAt); err != nil {
		return core.Plan{}, err
	}
	actions, err := t.planActions(ctx, id)
	if err != nil {
		return core.Plan{}, err
	}
	plan.Actions = actions
	return plan, nil
}

func (t *Tx) planActions(ctx context.Context, planID string) ([]core.Action, error) {
	rows, err := t.tx.QueryContext(ctx,
		`SELECT id, plan_id, path, kind, retention, confidence, status, destination, device, inode, reasons, guards, created_at, applied_at
		 FROM actions WHERE plan_id = ? ORDER BY path, id`, planID)
	if err != nil {
		return nil, fmt.Errorf("store: list actions of plan %s: %w", planID, err)
	}
	defer rows.Close()
	actions := []core.Action{}
	for rows.Next() {
		var (
			action              core.Action
			kind, retention     string
			status, reasonsJSON string
			guardsJSON          string
			createdAt           string
			appliedAt           sql.NullString
			device, inode       int64
		)
		if err := rows.Scan(&action.ID, &action.PlanID, &action.Path, &kind, &retention,
			&action.Confidence, &status, &action.Destination, &device, &inode,
			&reasonsJSON, &guardsJSON, &createdAt, &appliedAt); err != nil {
			return nil, fmt.Errorf("store: scan action row: %w", err)
		}
		if action.Kind, err = core.ParseActionKind(kind); err != nil {
			return nil, fmt.Errorf("store: action %s: %w", action.ID, err)
		}
		if action.Retention, err = core.ParseRetention(retention); err != nil {
			return nil, fmt.Errorf("store: action %s: %w", action.ID, err)
		}
		if action.Status, err = core.ParseActionStatus(status); err != nil {
			return nil, fmt.Errorf("store: action %s: %w", action.ID, err)
		}
		action.FilesystemID = core.FilesystemID{Device: uint64(device), Inode: uint64(inode)}
		if err := json.Unmarshal([]byte(reasonsJSON), &action.Reasons); err != nil {
			return nil, fmt.Errorf("store: decode reasons of action %s: %w", action.ID, err)
		}
		if err := json.Unmarshal([]byte(guardsJSON), &action.Guards); err != nil {
			return nil, fmt.Errorf("store: decode guards of action %s: %w", action.ID, err)
		}
		if action.CreatedAt, err = parseTime(createdAt); err != nil {
			return nil, err
		}
		if appliedAt.Valid {
			applied, err := parseTime(appliedAt.String)
			if err != nil {
				return nil, err
			}
			action.AppliedAt = &applied
		}
		actions = append(actions, action)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list actions of plan %s: %w", planID, err)
	}
	return actions, nil
}

// ListPlans returns plans newest first, bounded by limit (0 means all).
func (t *Tx) ListPlans(ctx context.Context, limit int) ([]core.Plan, error) {
	query := `SELECT id FROM plans ORDER BY created_at DESC, id DESC`
	args := []any{}
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := t.tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list plans: %w", err)
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: scan plan row: %w", err)
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, fmt.Errorf("store: list plans: %w", err)
	}
	out := make([]core.Plan, 0, len(ids))
	for _, id := range ids {
		plan, err := t.Plan(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, plan)
	}
	return out, nil
}

// UpdateActionStatus records the outcome of applying one action.
func (t *Tx) UpdateActionStatus(ctx context.Context, actionID string, status core.ActionStatus, appliedAt *time.Time) error {
	if !status.Valid() {
		return fmt.Errorf("store: unknown action status %q", string(status))
	}
	res, err := t.tx.ExecContext(ctx,
		`UPDATE actions SET status = ?, applied_at = ? WHERE id = ?`,
		string(status), nullableTime(appliedAt), actionID)
	if err != nil {
		return fmt.Errorf("store: update action %s: %w", actionID, err)
	}
	return requireAffected(res, fmt.Sprintf("action %s", actionID))
}

// RecordModelUsage stores one billed model interaction.
func (t *Tx) RecordModelUsage(ctx context.Context, usage core.ModelUsage) error {
	usage.Normalize()
	if err := usage.Validate(); err != nil {
		return fmt.Errorf("store: invalid model usage: %w", err)
	}
	var scanID any
	if usage.ScanID != "" {
		scanID = usage.ScanID
	}
	_, err := t.tx.ExecContext(ctx,
		`INSERT INTO model_usage
		   (id, scan_id, provider, model, request_kind, prompt_tokens, completion_tokens, estimated_cost_usd, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		usage.ID, scanID, usage.Provider, usage.Model, usage.RequestKind,
		usage.PromptTokens, usage.CompletionTokens, usage.EstimatedCostUSD, formatTime(usage.CreatedAt),
	)
	if err != nil {
		return fmt.Errorf("store: insert model usage %s: %w", usage.ID, err)
	}
	return nil
}

// UsageTotals aggregates recorded model spend.
type UsageTotals struct {
	Records          int64   `json:"records"`
	PromptTokens     int64   `json:"prompt_tokens"`
	CompletionTokens int64   `json:"completion_tokens"`
	EstimatedCostUSD float64 `json:"estimated_cost_usd"`
}

// UsageTotals sums every recorded model interaction.
func (t *Tx) UsageTotals(ctx context.Context) (UsageTotals, error) {
	var totals UsageTotals
	err := t.tx.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(prompt_tokens), 0), COALESCE(SUM(completion_tokens), 0), COALESCE(SUM(estimated_cost_usd), 0)
		 FROM model_usage`).
		Scan(&totals.Records, &totals.PromptTokens, &totals.CompletionTokens, &totals.EstimatedCostUSD)
	if err != nil {
		return UsageTotals{}, fmt.Errorf("store: model usage totals: %w", err)
	}
	return totals, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanScanRow(row rowScanner) (core.Scan, error) {
	var (
		scan           core.Scan
		rootsJSON      string
		collectorsJSON string
		status         string
		startedAt      string
		finishedAt     sql.NullString
	)
	if err := row.Scan(&scan.ID, &scan.ContractVersion, &rootsJSON, &status, &startedAt,
		&finishedAt, &scan.EntryCount, &scan.Error, &collectorsJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return core.Scan{}, err
		}
		return core.Scan{}, fmt.Errorf("store: scan row: %w", err)
	}
	if err := json.Unmarshal([]byte(rootsJSON), &scan.Roots); err != nil {
		return core.Scan{}, fmt.Errorf("store: decode roots of scan %s: %w", scan.ID, err)
	}
	if err := json.Unmarshal([]byte(collectorsJSON), &scan.Collectors); err != nil {
		return core.Scan{}, fmt.Errorf("store: decode collector reports of scan %s: %w", scan.ID, err)
	}
	for _, report := range scan.Collectors {
		if _, err := core.ParseCollectorStatus(string(report.Status)); err != nil {
			return core.Scan{}, fmt.Errorf("store: scan %s collector %s: %w", scan.ID, report.Name, err)
		}
	}
	var err error
	if scan.Status, err = core.ParseScanStatus(status); err != nil {
		return core.Scan{}, fmt.Errorf("store: scan %s: %w", scan.ID, err)
	}
	if scan.StartedAt, err = parseTime(startedAt); err != nil {
		return core.Scan{}, err
	}
	if finishedAt.Valid {
		finished, err := parseTime(finishedAt.String)
		if err != nil {
			return core.Scan{}, err
		}
		scan.FinishedAt = &finished
	}
	return scan, nil
}

// decodeEntry rebuilds an entry from its stored document and re-validates
// it. A row that no longer satisfies the contract is a corrupt or
// hand-edited database, and reporting it beats acting on it.
func decodeEntry(doc string) (core.Entry, error) {
	var entry core.Entry
	if err := json.Unmarshal([]byte(doc), &entry); err != nil {
		return core.Entry{}, fmt.Errorf("store: decode entry document: %w", err)
	}
	if err := entry.Validate(); err != nil {
		return core.Entry{}, fmt.Errorf("store: stored entry %s is invalid: %w", entry.Path, err)
	}
	return entry, nil
}

func requireAffected(res sql.Result, what string) error {
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: rows affected for %s: %w", what, err)
	}
	if affected == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, what)
	}
	return nil
}

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return formatTime(*t)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func stringsOrEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// encodeScanColumns renders the JSON-valued scan columns.
func encodeScanColumns(scan core.Scan) (roots string, collectors string, err error) {
	rootsJSON, err := core.MarshalJSON(scan.Roots)
	if err != nil {
		return "", "", fmt.Errorf("store: encode roots of scan %s: %w", scan.ID, err)
	}
	reports := scan.Collectors
	if reports == nil {
		reports = []core.CollectorReport{}
	}
	collectorsJSON, err := core.MarshalJSON(reports)
	if err != nil {
		return "", "", fmt.Errorf("store: encode collector reports of scan %s: %w", scan.ID, err)
	}
	return string(rootsJSON), string(collectorsJSON), nil
}
