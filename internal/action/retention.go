package action

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/core"
	"github.com/gitmoot/workspace-janitor/internal/safety"
)

// recollect refuses incomplete reference observation, rather than interpreting
// a partial or skipped collector as proof that nobody uses a path.
func (e *Engine) recollect(ctx context.Context, path string) (core.Entry, error) {
	opts := e.Collect
	// Resolve a live source symlink only to check containment; quarantine
	// snapshots never follow links because a relative target may be absent
	// until restore. In both cases the filesystem move operates on the link.
	opts.Roots = []collect.RootSpec{{Path: filepath.Dir(path), MaxDepth: 1, FollowSymlinks: !within(path, e.QuarantineDir)}}
	opts.Prior, opts.PriorScanID = nil, ""
	result, err := collect.Run(ctx, opts)
	if err != nil {
		return core.Entry{}, err
	}
	for _, report := range result.Reports {
		switch report.Name {
		case collect.CollectorFilesystem, collect.CollectorProcesses, collect.CollectorServices:
			if report.Status != core.CollectorRan {
				return core.Entry{}, fmt.Errorf("%s evidence incomplete: %s: %s", path, report.Name, report.Detail)
			}
		case collect.CollectorGit:
			// Git's aggregate report becomes partial when any sibling repo is
			// unknown. The target's own unknown Git state is represented in
			// its entry and blocked by the safety engine.
			if report.Status != core.CollectorRan && report.Status != core.CollectorPartial {
				return core.Entry{}, fmt.Errorf("%s Git evidence incomplete: %s", path, report.Detail)
			}
		case collect.CollectorAgents:
			if len(opts.AgentSources) != 0 && report.Status != core.CollectorRan {
				return core.Entry{}, fmt.Errorf("%s agent evidence incomplete: %s", path, report.Detail)
			}
		}
	}
	for _, entry := range result.Entries {
		if entry.Path == path {
			return entry, nil
		}
	}
	return core.Entry{}, fmt.Errorf("%s not found in fresh collection", path)
}

// originalReferences re-checks the missing source's parent, because services
// or jobs can begin referring to an absent path after the quarantine move.
// Attaching to the parent is deliberately conservative: any descendant
// reference blocks deletion rather than silently losing a source-path claim.
func (e *Engine) originalReferences(ctx context.Context, source string) error {
	if err := absent(source); err != nil {
		return err
	}
	parent, err := e.recollect(ctx, filepath.Dir(source))
	if err != nil {
		return err
	}
	verdict := safety.Evaluate(safety.Input{Entry: parent, Policy: e.Policy, Now: e.now()})
	if verdict.Refused() {
		return fmt.Errorf("original source has new protected references: %s", verdict.Summary())
	}
	return nil
}

// Eligible performs a second complete observation and guard evaluation. It
// never deletes. An expired timestamp alone is not an authorization.
func (e *Engine) Eligible(ctx context.Context, item core.CleanupItem) error {
	if item.State != core.CleanupQuarantined {
		return fmt.Errorf("%s is not quarantined", item.ActionID)
	}
	if item.MovedAt == nil || !item.Action.Retention.Expired(*item.MovedAt, e.now()) {
		return errors.New("retention has not expired")
	}
	if item.Quarantined == nil {
		return errors.New("missing post-move safety snapshot")
	}
	if err := e.originalReferences(ctx, item.Source); err != nil {
		return err
	}
	handle, err := safety.Open(item.Destination)
	if err != nil {
		return err
	}
	defer handle.Close()
	policy := e.Policy
	// This exact receipt is within our own state/quarantine directory. Those
	// self-protections are not evidence about the object; all configured path,
	// name, Git, live-reference, identity and unknown-evidence guards remain.
	policy.StateDir, policy.QuarantineDir = "", ""
	policy.ProtectedPaths = make([]string, 0, len(e.Policy.ProtectedPaths))
	for _, protected := range e.Policy.ProtectedPaths {
		if filepath.Clean(protected) != filepath.Clean(e.Policy.StateDir) &&
			filepath.Clean(protected) != filepath.Clean(e.Policy.QuarantineDir) {
			policy.ProtectedPaths = append(policy.ProtectedPaths, protected)
		}
	}
	planned := *item.Quarantined
	planned.Root = item.Entry.Root // symlink containment is judged against its original discovery root
	var observed core.Entry
	probe := func(ctx context.Context, path string) (core.Entry, error) {
		fresh, err := e.recollect(ctx, path)
		fresh.Root = item.Entry.Root
		observed = fresh
		return fresh, err
	}
	action := item.Action
	action.Path, action.Kind, action.FilesystemID = item.Destination, core.ActionDeleteCandidate, planned.FilesystemID
	verdict := safety.Revalidate(ctx, safety.RevalidateInput{
		Planned: planned, Action: action, Policy: policy, Now: e.now(), Handle: handle, Recollect: probe,
	})
	if !verdict.Allows(core.ActionDeleteCandidate) {
		return fmt.Errorf("deletion safety refused: %s", verdict.Summary())
	}
	// Re-evaluate the *original* pathname as well. Names and protected-path
	// rules can change after quarantine; evaluating only the receipt's generic
	// name \"item\" would silently lose those protections.
	mirror := observed
	mirror.Path, mirror.Root, mirror.CanonicalPath = item.Source, item.Entry.Root, item.Entry.CanonicalPath
	original := safety.Evaluate(safety.Input{Entry: mirror, Policy: e.Policy, Now: e.now()})
	if !original.Allows(core.ActionDeleteCandidate) {
		return fmt.Errorf("original source safety refused: %s", original.Summary())
	}
	return nil
}

// Delete is a distinct, explicit operation, never part of Quarantine. The
// caller must gate it on both policy opt-in and operator confirmation.
func (e *Engine) Delete(ctx context.Context, item core.CleanupItem) (core.CleanupItem, error) {
	if item.State != core.CleanupQuarantined || item.MovedAt == nil || !item.Action.Retention.Expired(*item.MovedAt, e.now()) {
		return item, errors.New("retention has not expired or item is not quarantined")
	}
	if err := e.Eligible(ctx, item); err != nil {
		return e.investigate(ctx, item, err.Error())
	}
	if err := deleteAnchored(item.Destination, item.Entry.FilesystemID); err != nil {
		return item, err
	}
	item.State, item.UpdatedAt = core.CleanupDeleted, e.now()
	if err := e.update(ctx, item, core.CleanupQuarantined); err != nil {
		return item, err
	}
	return item, nil
}

func filesystemID(info os.FileInfo) core.FilesystemID {
	return fileIdentity(info)
}

func identityMatches(info os.FileInfo, id core.FilesystemID) bool {
	return info != nil && !id.Zero() && fileIdentity(info) == id
}
