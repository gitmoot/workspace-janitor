package collect

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/config"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

// OwnerAttribution is the owning role Gitmoot's producer ledger names for one
// exact path. Role is empty when the ledger names none, or more than one.
// Active describes nonterminal ledger work on the path: the path is in use.
type OwnerAttribution struct {
	Role     string   `json:"role,omitempty"`
	Active   string   `json:"active,omitempty"`
	Evidence []string `json:"evidence"`
}

// GitmootOwners reads, read-only and in one snapshot, which role Gitmoot's
// ledger names for each exact path: a task's disposal_escalation_role and a
// job's dispatched_by for its payload worktree_path. Paths the ledger never
// mentions are absent from the result. It returns a status line for reports;
// an unavailable ledger is an error, never an empty attribution.
func GitmootOwners(ctx context.Context, policy config.GitmootPolicy, paths []string, limit int, timeout time.Duration) (map[string]OwnerAttribution, string, error) {
	switch {
	case policy.Home == "" || policy.Database == "":
		return map[string]OwnerAttribution{}, "no Gitmoot home configured", nil
	case !core.IsCanonicalPath(policy.Home) || !core.IsCanonicalPath(policy.Database):
		return nil, "", errors.New("Gitmoot home or database path is not canonical")
	}
	if _, err := os.Lstat(policy.Home); errors.Is(err, os.ErrNotExist) {
		return map[string]OwnerAttribution{}, "Gitmoot home does not exist", nil
	}
	if _, err := os.Stat(policy.Database); err != nil {
		return nil, "", err
	}
	if limit <= 0 {
		limit = 20000
	}
	uri := (&url.URL{Scheme: "file", Path: policy.Database, RawQuery: "mode=ro&_pragma=query_only(1)"}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, "", err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	readCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tx, err := db.BeginTx(readCtx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()

	wanted := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		wanted[path] = struct{}{}
	}
	roles := map[string]map[string]bool{}
	evidence := map[string][]string{}
	active := map[string]string{}
	note := func(path, role, detail string) {
		if roles[path] == nil {
			roles[path] = map[string]bool{}
		}
		if role != "" {
			roles[path][role] = true
		}
		evidence[path] = append(evidence[path], detail)
	}
	var sources []string
	for _, ledger := range []struct {
		table, roleColumn, pathColumn, query, what string
		terminal                                   func(string) bool
	}{
		{"tasks", "disposal_escalation_role", "worktree_path", `SELECT id, state, disposal_escalation_role, worktree_path FROM tasks
			WHERE worktree_path IS NOT NULL AND worktree_path <> '' LIMIT ?`, "task", gitmootTerminalTask},
		{"jobs", "dispatched_by", "payload", `SELECT id, state, dispatched_by, json_extract(payload, '$.worktree_path') FROM jobs
			WHERE CASE WHEN json_valid(payload) THEN json_type(payload, '$.worktree_path') = 'text'
				AND json_extract(payload, '$.worktree_path') <> '' ELSE 0 END LIMIT ?`, "job", gitmootTerminalJob},
	} {
		present, err := hasColumns(readCtx, tx, ledger.table, "id", "state", ledger.roleColumn, ledger.pathColumn)
		if err != nil {
			return nil, "", err
		}
		if !present {
			continue
		}
		sources = append(sources, ledger.table+"."+ledger.roleColumn)
		rows, err := tx.QueryContext(readCtx, ledger.query, limit+1)
		if err != nil {
			return nil, "", err
		}
		count := 0
		for rows.Next() {
			var id, state, role, path sql.NullString
			if err = rows.Scan(&id, &state, &role, &path); err != nil {
				break
			}
			count++
			if _, ok := wanted[path.String]; !ok {
				continue
			}
			if !ledger.terminal(state.String) && active[path.String] == "" {
				active[path.String] = fmt.Sprintf("Gitmoot %s %s is %s", ledger.what, id.String, state.String)
			}
			value := strings.TrimSpace(role.String)
			detail := fmt.Sprintf("Gitmoot %s %s names no %s", ledger.what, id.String, ledger.roleColumn)
			if value != "" {
				detail = fmt.Sprintf("Gitmoot %s %s %s %q", ledger.what, id.String, ledger.roleColumn, value)
			}
			note(path.String, value, detail)
		}
		if err == nil {
			err = rows.Err()
		}
		if closeErr := rows.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return nil, "", err
		}
		if count > limit {
			return nil, "", fmt.Errorf("Gitmoot %s reference limit %d reached", ledger.table, limit)
		}
	}
	out := make(map[string]OwnerAttribution, len(evidence))
	for path, details := range evidence {
		attribution := OwnerAttribution{Active: active[path], Evidence: details}
		var named []string
		for role := range roles[path] {
			named = append(named, role)
		}
		sort.Strings(named)
		switch {
		case len(named) == 1 && config.ValidRole(named[0]):
			attribution.Role = named[0]
		case len(named) == 1:
			attribution.Evidence = append(attribution.Evidence, fmt.Sprintf("%q is not a routable role name", named[0]))
		case len(named) > 1:
			attribution.Evidence = append(attribution.Evidence, "ambiguous: the ledger names roles "+strings.Join(named, ", "))
		}
		out[path] = attribution
	}
	status := "Gitmoot ledger has no role columns; every owner is unknown"
	if len(sources) != 0 {
		status = "read " + strings.Join(sources, " and ") + " for exact paths"
	}
	return out, status, nil
}

// hasColumns reports whether table exists with every named column.
func hasColumns(ctx context.Context, tx *sql.Tx, table string, columns ...string) (bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	for _, column := range columns {
		if !have[column] {
			return false, nil
		}
	}
	return true, nil
}

// gitmootTerminalJob reports whether a job state is final; any other state,
// including an unknown one, means the job may still use its worktree.
func gitmootTerminalJob(state string) bool {
	switch state {
	case "succeeded", "failed", "cancelled":
		return true
	default:
		return false
	}
}
