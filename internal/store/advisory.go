package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// The daily limits are admission limits, not a claim about provider billing.
// Every HTTP attempt reserves its worst-known input before the request starts.
const (
	AdvisoryMaxAttempts     = 7
	AdvisoryMaxEntries      = 140
	AdvisoryMaxInputTokens  = 100000
	AdvisoryMaxCostMicroUSD = 10000 // $0.01
)

var (
	ErrAdvisoryAlreadyRun = errors.New("store: daily advisory already started")
	ErrAdvisoryBudget     = errors.New("store: daily advisory budget exhausted or unavailable")
)

type AdvisoryBudget struct {
	Attempts              int64 `json:"attempts"`
	Entries               int64 `json:"entries"`
	EstimatedInputTokens  int64 `json:"estimated_input_tokens"`
	EstimatedCostMicroUSD int64 `json:"estimated_cost_micro_usd"`
}

type AdvisoryRecord struct {
	Day    string
	ScanID string
	Status string
	Report string
}

func advisoryDay(now time.Time) string { return now.UTC().Format("2006-01-02") }

// RecordCompletedCycle is called only after the inventory and every enabled
// cycle action succeeded. A scan alone cannot authorize a scheduled advisory.
func (t *Tx) RecordCompletedCycle(ctx context.Context, scanID string, now time.Time) error {
	scan, err := t.Scan(ctx, scanID)
	if err != nil {
		return err
	}
	if scan.Status != "completed" || scan.FinishedAt == nil {
		return errors.New("store: cycle scan is not completed")
	}
	_, err = t.tx.ExecContext(ctx, `INSERT INTO completed_cycles(day, scan_id, completed_at_ns)
		VALUES (?, ?, ?) ON CONFLICT(day) DO UPDATE SET scan_id=excluded.scan_id,
		completed_at_ns=excluded.completed_at_ns WHERE excluded.completed_at_ns > completed_cycles.completed_at_ns`,
		advisoryDay(now), scanID, now.UTC().UnixNano())
	return err
}

func (t *Tx) CompletedCycle(ctx context.Context, day string) (string, error) {
	var scanID string
	err := t.tx.QueryRowContext(ctx, `SELECT scan_id FROM completed_cycles WHERE day=?`, day).Scan(&scanID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return scanID, err
}

// ClaimAdvisory admits exactly one run per UTC day, atomically checking the
// successful cycle binding. A crash leaves its running claim in place and
// cannot silently start another run or reclaim an attempt slot.
func (t *Tx) ClaimAdvisory(ctx context.Context, day, scanID, initialReport string, now time.Time) error {
	if day != advisoryDay(now) || scanID == "" || initialReport == "" {
		return ErrAdvisoryBudget
	}
	var cycleScan string
	if err := t.tx.QueryRowContext(ctx, `SELECT scan_id FROM completed_cycles WHERE day=?`, day).Scan(&cycleScan); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if cycleScan != scanID {
		return ErrAdvisoryBudget
	}
	_, err := t.tx.ExecContext(ctx, `INSERT INTO advisory_runs(day, scan_id, status, report, started_at_ns)
		VALUES (?, ?, 'running', ?, ?)`, day, scanID, initialReport, now.UTC().UnixNano())
	if err != nil {
		var existing string
		if lookupErr := t.tx.QueryRowContext(ctx, `SELECT scan_id FROM advisory_runs WHERE day=?`, day).Scan(&existing); lookupErr == nil {
			return ErrAdvisoryAlreadyRun
		}
		return fmt.Errorf("store: claim daily advisory: %w", err)
	}
	return nil
}

func (t *Tx) Advisory(ctx context.Context, day string) (AdvisoryRecord, error) {
	var r AdvisoryRecord
	err := t.tx.QueryRowContext(ctx, `SELECT day, scan_id, status, report FROM advisory_runs WHERE day=?`, day).
		Scan(&r.Day, &r.ScanID, &r.Status, &r.Report)
	if errors.Is(err, sql.ErrNoRows) {
		return AdvisoryRecord{}, ErrNotFound
	}
	return r, err
}

// FinishAdvisory stores a private report. A running claim with no final report
// is intentionally visible as interrupted on the next launch.
func (t *Tx) FinishAdvisory(ctx context.Context, day, scanID, status, report string, now time.Time) error {
	if status != "complete" && status != "incomplete" && status != "blocked" {
		return ErrAdvisoryBudget
	}
	result, err := t.tx.ExecContext(ctx, `UPDATE advisory_runs SET status=?, report=?, finished_at_ns=?
		WHERE day=? AND scan_id=? AND status='running'`, status, report, now.UTC().UnixNano(), day, scanID)
	if err != nil {
		return err
	}
	return requireAffected(result, "running advisory")
}

func (t *Tx) AdvisoryBudget(ctx context.Context, day string) (AdvisoryBudget, error) {
	var b AdvisoryBudget
	err := t.tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(entries),0),
		COALESCE(SUM(estimated_tokens),0), COALESCE(SUM(estimated_cost_micro_usd),0)
		FROM advisory_attempts WHERE day=?`, day).
		Scan(&b.Attempts, &b.Entries, &b.EstimatedInputTokens, &b.EstimatedCostMicroUSD)
	return b, err
}

// ReserveAdvisoryAttempt is committed before HTTP Do. SQLite serializes the
// admission write across processes. An error, timeout or crash does not refund
// a reservation, including an attempt that may never have reached the server.
func (t *Tx) ReserveAdvisoryAttempt(ctx context.Context, day, scanID string, entries, tokens, costMicroUSD int64, now time.Time) error {
	if day != advisoryDay(now) || entries <= 0 || tokens <= 0 || costMicroUSD <= 0 ||
		entries > AdvisoryMaxEntries || tokens > AdvisoryMaxInputTokens || costMicroUSD > AdvisoryMaxCostMicroUSD {
		return ErrAdvisoryBudget
	}
	var status string
	if err := t.tx.QueryRowContext(ctx, `SELECT status FROM advisory_runs WHERE day=? AND scan_id=?`, day, scanID).Scan(&status); err != nil || status != "running" {
		return ErrAdvisoryBudget
	}
	latest, err := t.ListScans(ctx, 1)
	if err != nil {
		return err
	}
	if len(latest) != 1 || latest[0].ID != scanID || latest[0].Status != "completed" {
		return ErrAdvisoryBudget
	}
	budget, err := t.AdvisoryBudget(ctx, day)
	if err != nil {
		return err
	}
	if budget.Attempts >= AdvisoryMaxAttempts || budget.Entries+entries > AdvisoryMaxEntries ||
		budget.EstimatedInputTokens+tokens > AdvisoryMaxInputTokens ||
		budget.EstimatedCostMicroUSD+costMicroUSD > AdvisoryMaxCostMicroUSD {
		return ErrAdvisoryBudget
	}
	_, err = t.tx.ExecContext(ctx, `INSERT INTO advisory_attempts
		(day, scan_id, entries, estimated_tokens, estimated_cost_micro_usd, reserved_at_ns)
		VALUES (?, ?, ?, ?, ?, ?)`, day, scanID, entries, tokens, costMicroUSD, now.UTC().UnixNano())
	return err
}
