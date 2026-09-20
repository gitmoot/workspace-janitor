package safety

import (
	"context"
	"fmt"
	"time"

	"github.com/gitmoot/workspace-janitor/internal/collect"
	"github.com/gitmoot/workspace-janitor/internal/core"
)

// Recollector observes a single path again, immediately before a mutation.
type Recollector func(ctx context.Context, path string) (core.Entry, error)

// RevalidateInput is one apply-time safety check.
type RevalidateInput struct {
	// Planned is the entry as it was when the action was planned.
	Planned core.Entry
	// Action is the mutation about to be performed.
	Action core.Action
	Policy Policy
	Jobs   []JobRef
	Target *Target
	Now    time.Time
	// Recollect observes the path again. Required: revalidation without a
	// fresh observation would only restate the plan.
	Recollect Recollector
	// Handle is a reference to the object opened when the action was
	// planned. It is optional but strongly recommended: metadata alone
	// cannot always tell a replacement apart from the original, because a
	// removed inode can be reused immediately and the replacement can carry
	// identical device, inode, and timestamps. A handle refers to one
	// kernel object and knows when that object was unlinked.
	Handle *Handle
}

// Revalidate re-runs every guard against a freshly observed entry.
//
// This exists because a verdict is a statement about one moment. Between
// planning and applying, a path can be replaced, a repository can go dirty,
// a process can open a file, or a job can claim a directory. Applying a plan
// without this check is a time-of-check to time-of-use bug with rm-like
// consequences.
//
// Anything that changed since planning refuses the action outright: the plan
// described a different thing, so it no longer authorizes anything.
func Revalidate(ctx context.Context, in RevalidateInput) core.Verdict {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	if in.Recollect == nil {
		return refusal(in.Planned.Path, now, protect(core.ProtectCollectorFailure, core.SourceFilesystem,
			"no re-observation was available, so the target could not be revalidated before mutating"))
	}

	fresh, err := in.Recollect(ctx, in.Planned.Path)
	if err != nil {
		return refusal(in.Planned.Path, now, protect(core.ProtectCollectorFailure, core.SourceFilesystem,
			fmt.Sprintf("re-observing %s failed: %v", in.Planned.Path, err)))
	}

	verdict := Evaluate(Input{Entry: fresh, Policy: in.Policy, Jobs: in.Jobs, Target: in.Target, Now: now})
	for _, protection := range changeProtections(in, fresh) {
		addProtection(&verdict, protection)
	}
	verdict.Normalize()
	return verdict
}

// changeProtections compares the fresh observation with the plan.
func changeProtections(in RevalidateInput, fresh core.Entry) []core.Protection {
	var out []core.Protection

	if fresh.Path != in.Planned.Path {
		out = append(out, protect(core.ProtectIdentityChanged, core.SourceFilesystem,
			fmt.Sprintf("re-observation returned %s, not the planned path %s", fresh.Path, in.Planned.Path)))
	}
	if fresh.FilesystemID != in.Planned.FilesystemID {
		out = append(out, protect(core.ProtectIdentityChanged, core.SourceFilesystem,
			fmt.Sprintf("filesystem identity changed since planning: was %s, now %s",
				in.Planned.FilesystemID, fresh.FilesystemID)))
	}
	// The action carries the identity it was planned against, which is what
	// an apply engine would act on if this check did not exist.
	if !in.Action.FilesystemID.Zero() && in.Action.FilesystemID != fresh.FilesystemID {
		out = append(out, protect(core.ProtectIdentityChanged, core.SourceFilesystem,
			fmt.Sprintf("action %s was planned for identity %s, but %s is now %s",
				in.Action.ID, in.Action.FilesystemID, fresh.Path, fresh.FilesystemID)))
	}
	if in.Action.Path != "" && in.Action.Path != in.Planned.Path {
		out = append(out, protect(core.ProtectIdentityChanged, core.SourceFilesystem,
			fmt.Sprintf("action %s targets %s but was revalidated against %s",
				in.Action.ID, in.Action.Path, in.Planned.Path)))
	}

	if in.Handle != nil {
		out = append(out, handleProtections(in, fresh)...)
	}

	planned := in.Planned.Fingerprint
	if planned == "" {
		planned = collect.Fingerprint(in.Planned)
	}
	current := fresh.Fingerprint
	if current == "" {
		current = collect.Fingerprint(fresh)
	}
	if planned != current {
		out = append(out, protect(core.ProtectIdentityChanged, core.SourceFilesystem,
			fmt.Sprintf("metadata changed since planning: fingerprint was %s, now %s",
				shortFingerprint(planned), shortFingerprint(current))))
	}
	return out
}

// handleProtections compares the object opened at plan time with what the
// path resolves to now.
//
// This is the only check that survives inode reuse. Measured on ext4 while
// building this engine: rmdir followed by mkdir of the same name produced
// an identical device, inode, and modification time, so every
// metadata-based comparison saw no change at all. The handle saw nlink 0.
func handleProtections(in RevalidateInput, fresh core.Entry) []core.Protection {
	var out []core.Protection
	linked, err := in.Handle.Linked()
	switch {
	case err != nil:
		out = append(out, protect(core.ProtectCollectorFailure, core.SourceFilesystem,
			fmt.Sprintf("the planned object could not be re-checked through its handle: %v", err)))
	case !linked:
		out = append(out, protect(core.ProtectIdentityChanged, core.SourceFilesystem,
			fmt.Sprintf("the object planned at %s was removed after planning; the name now refers to something else",
				in.Handle.Path())))
	}
	if id := in.Handle.Identity(); !id.Zero() && id != fresh.FilesystemID {
		out = append(out, protect(core.ProtectIdentityChanged, core.SourceFilesystem,
			fmt.Sprintf("the planned object had identity %s, but %s is now %s", id, fresh.Path, fresh.FilesystemID)))
	}
	if in.Handle.Path() != "" && in.Handle.Path() != in.Planned.Path {
		out = append(out, protect(core.ProtectIdentityChanged, core.SourceFilesystem,
			fmt.Sprintf("the handle refers to %s but the plan targets %s", in.Handle.Path(), in.Planned.Path)))
	}
	return out
}

// refusal builds a single-protection refusal verdict.
func refusal(path string, now time.Time, protection core.Protection) core.Verdict {
	verdict := core.Verdict{
		Path:        path,
		EvaluatedAt: now,
		Guards:      GuardNames(),
		Protections: []core.Protection{protection},
	}
	verdict.Normalize()
	return verdict
}

func shortFingerprint(value string) string {
	if len(value) > 12 {
		return value[:12]
	}
	if value == "" {
		return "unknown"
	}
	return value
}

// CollectRecollector re-observes one path with the collectors, using the
// bounds the scan was configured with.
//
// The re-observation walks only the item's parent directory to depth one,
// which is the smallest scope that still produces a complete entry.
func CollectRecollector(base collect.Options) Recollector {
	return func(ctx context.Context, path string) (core.Entry, error) {
		opts := base
		opts.Roots = []collect.RootSpec{{
			Path:            parentOf(path),
			MaxDepth:        1,
			FollowSymlinks:  followSymlinks(base, path),
			CrossFilesystem: crossFilesystem(base, path),
		}}
		opts.Prior = nil
		opts.PriorScanID = ""
		result, err := collect.Run(ctx, opts)
		if err != nil {
			return core.Entry{}, err
		}
		for _, entry := range result.Entries {
			if entry.Path == path {
				return entry, nil
			}
		}
		return core.Entry{}, fmt.Errorf("safety: %s was not found during re-observation", path)
	}
}

func parentOf(path string) string {
	parent := path
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			parent = path[:i]
			break
		}
	}
	if parent == "" {
		return "/"
	}
	return parent
}

// followSymlinks and crossFilesystem inherit the bounds of the configured
// root that contains the path, so a re-observation cannot be more permissive
// than the scan that produced the plan.
func followSymlinks(base collect.Options, path string) bool {
	if root, ok := containingRoot(base, path); ok {
		return root.FollowSymlinks
	}
	return false
}

func crossFilesystem(base collect.Options, path string) bool {
	if root, ok := containingRoot(base, path); ok {
		return root.CrossFilesystem
	}
	return false
}

func containingRoot(base collect.Options, path string) (collect.RootSpec, bool) {
	var (
		best  collect.RootSpec
		found bool
	)
	for _, root := range base.Roots {
		if !pathWithin(path, root.Path) {
			continue
		}
		if !found || len(root.Path) > len(best.Path) {
			best, found = root, true
		}
	}
	return best, found
}
