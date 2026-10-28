package cli

import (
	"context"
	"errors"
	"flag"
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
)

// Suggested actions of a stale report entry. They are advice to the owner;
// only an owner's release reply (and release_action archive) archives.
const (
	staleSuggestArchive = "archive"
	staleSuggestKeep    = "keep"
	staleSuggestAsk     = "ask"
)

// Git states of a stale report entry, from the archive-category Git gate.
const (
	staleGitMerged   = "merged"
	staleGitPushed   = "pushed"
	staleGitUnpushed = "unpushed"
	staleGitDirty    = "dirty"
	staleGitNotGit   = "not_git"
	staleGitUnknown  = "unknown"
)

// staleInUse are the protections that mean something is using the item now.
var staleInUse = []core.ProtectionKind{
	core.ProtectActiveProcess, core.ProtectRegisteredAgent, core.ProtectServiceReference,
	core.ProtectLockHeld, core.ProtectLiveDatabase,
}

// staleEntry is one stale, unused item awaiting its owner's reply.
type staleEntry struct {
	Path string `json:"path"`
	// SizeBytes is the deep size; SizeMeasure says whether it is complete
	// ("deep") or a lower bound ("lower_bound").
	SizeBytes        int64     `json:"size_bytes"`
	SizeMeasure      string    `json:"size_measure"`
	Git              string    `json:"git"`
	GitDetail        string    `json:"git_detail,omitempty"`
	Owner            string    `json:"owner"`
	OwnerEvidence    []string  `json:"owner_evidence,omitempty"`
	NewestModifiedAt time.Time `json:"newest_modified_at"`
	IdleFor          string    `json:"idle_for"`
	SuggestedAction  string    `json:"suggested_action"`
	Reasons          []string  `json:"reasons,omitempty"`
	// PriorReply explains a reply that no longer applies.
	PriorReply string `json:"prior_reply,omitempty"`

	entry   core.Entry
	verdict core.Verdict
}

// staleGroup holds the entries addressed to one role. The unknown-owner
// group is addressed to the coordinator role.
type staleGroup struct {
	Owner       string       `json:"owner"`
	AddressedTo string       `json:"addressed_to"`
	Entries     []staleEntry `json:"entries"`
}

// staleReleased is a release reply that still applies to its unchanged item.
type staleReleased struct {
	Path      string    `json:"path"`
	Role      string    `json:"role"`
	Reply     int64     `json:"reply"`
	Note      string    `json:"note,omitempty"`
	RepliedAt time.Time `json:"replied_at"`
	// Status is recorded (release_action none: the operator acts on it),
	// pending_archive (the next cycle archives it if every check passes), or
	// archived.
	Status    string `json:"status"`
	Archive   string `json:"archive,omitempty"`
	SizeBytes int64  `json:"size_bytes"`
}

// staleKept is a keep reply that still suppresses its unchanged item.
type staleKept struct {
	Path      string     `json:"path"`
	Role      string     `json:"role"`
	Reply     int64      `json:"reply"`
	Until     *time.Time `json:"until,omitempty"`
	Note      string     `json:"note,omitempty"`
	RepliedAt time.Time  `json:"replied_at"`
}

// staleUnmeasured is an idle-looking item whose newest modification the
// bounded deep walk could not establish; it is never listed as stale.
type staleUnmeasured struct {
	Path        string `json:"path"`
	SizeBytes   int64  `json:"size_bytes"`
	SizeMeasure string `json:"size_measure"`
}

type staleCounts struct {
	Listed     int `json:"listed"`
	InUse      int `json:"in_use"`
	Recent     int `json:"changed_recently"`
	Policy     int `json:"excluded_by_policy"`
	Unmeasured int `json:"unmeasured"`
	Kept       int `json:"kept"`
	Archived   int `json:"already_archived"`
	Released   int `json:"released"`
}

type staleReport struct {
	Mode            string            `json:"mode"`
	GeneratedAt     time.Time         `json:"generated_at"`
	Role            string            `json:"role,omitempty"`
	Idle            string            `json:"idle"`
	Roots           []string          `json:"roots"`
	CoordinatorRole string            `json:"coordinator_role"`
	ReleaseAction   string            `json:"release_action"`
	OwnerEvidence   string            `json:"owner_evidence"`
	InUseEvidence   string            `json:"in_use_evidence"`
	Counts          staleCounts       `json:"counts"`
	Groups          []staleGroup      `json:"groups"`
	Released        []staleReleased   `json:"released"`
	Kept            []staleKept       `json:"kept"`
	Unmeasured      []staleUnmeasured `json:"unmeasured"`
	Attribution     string            `json:"attribution"`
}

// staleObservation is one report run plus what replies need to validate
// against it: every stale candidate (listed, kept or released) and why any
// other observed path is not an entry.
type staleObservation struct {
	report     staleReport
	candidates map[string]staleEntry
	excluded   map[string]string
	// ownerErr and inUseGap make every reply refuse: an owner or a not-in-use
	// claim that could not be observed is never assumed.
	ownerErr error
	inUseGap string
}

func sizeMeasure(entry core.Entry) string {
	switch {
	case !entry.SizeIsDeep:
		return "metadata"
	case entry.SizeIsLowerBound:
		return "lower_bound"
	}
	return "deep"
}

// staleGitState maps the archive-category Git gate onto the report's states.
func staleGitState(git *core.GitState) (string, string) {
	switch {
	case git == nil:
		return staleGitNotGit, ""
	case git.Bare:
		return staleGitUnknown, "bare repository"
	case git.Degraded:
		return staleGitUnknown, "Git state is degraded: " + git.DegradedReason
	case git.DirtyFiles > 0 || git.Stashes > 0 || git.Locked:
		var parts []string
		if git.DirtyFiles > 0 {
			parts = append(parts, fmt.Sprintf("%d uncommitted change(s)", git.DirtyFiles))
		}
		if git.Stashes > 0 {
			parts = append(parts, fmt.Sprintf("%d stash entr(ies)", git.Stashes))
		}
		if git.Locked {
			parts = append(parts, "a Git lock file is present")
		}
		return staleGitDirty, strings.Join(parts, ", ")
	case !git.PublicationKnown:
		return staleGitUnknown, "publication against remote-tracking branches was not measured"
	case git.UnpublishedCommits > 0:
		return staleGitUnpushed, fmt.Sprintf("%d commit(s) are not on any remote-tracking branch", git.UnpublishedCommits)
	case git.WorktreeOf != "":
		return staleGitMerged, "linked worktree whose commits are all on remote-tracking branches"
	}
	return staleGitPushed, "every commit is on a remote-tracking branch"
}

// staleInUseReason reports what is using entry now, if anything.
func staleInUseReason(entry core.Entry, verdict core.Verdict) string {
	for _, protection := range verdict.Protections {
		if slices.Contains(staleInUse, protection.Kind) {
			return fmt.Sprintf("%s: %s", protection.Kind, protection.Reason)
		}
	}
	for _, evidence := range entry.Evidence {
		if evidence.Signal == "gitmoot:pinned" {
			return evidence.Detail
		}
	}
	return ""
}

// ownerLookup is the owner attribution of a set of paths. A failed lookup
// attributes nothing: every owner is then unknown, never inferred.
type ownerLookup struct {
	owners map[string]collect.OwnerAttribution
	status string
	err    error
}

func lookupOwners(ctx context.Context, policy config.Policy, paths []string) ownerLookup {
	if len(paths) == 0 {
		return ownerLookup{owners: map[string]collect.OwnerAttribution{}, status: "no paths to attribute"}
	}
	owners, status, err := collect.GitmootOwners(ctx, policy.Gitmoot, paths, policy.Limits.MaxEntries, policy.Limits.CommandTimeout.Duration())
	if err != nil {
		return ownerLookup{status: "Gitmoot owner evidence unavailable: " + err.Error(), err: err}
	}
	return ownerLookup{owners: owners, status: status}
}

// owner is the attributed role of path, "unknown", or "" when evidence is
// unavailable.
func (o ownerLookup) owner(path string) string {
	if o.err != nil {
		return ""
	}
	if attribution, ok := o.owners[path]; ok && attribution.Role != "" {
		return attribution.Role
	}
	return config.UnknownOwner
}

func (o ownerLookup) evidence(path string) []string {
	if o.err != nil {
		return []string{o.status}
	}
	if attribution, ok := o.owners[path]; ok {
		return attribution.Evidence
	}
	return []string{"no registration or producer evidence names an owner"}
}

// active describes nonterminal producer work on path, if the ledger has any.
func (o ownerLookup) active(path string) string {
	return o.owners[path].Active
}

// snapshotChanged reports how entry differs from what reply saw.
func snapshotChanged(reply store.ReportReply, entry core.Entry) string {
	switch {
	case entry.LatestModifiedAt.IsZero():
		return "its newest modification is no longer measured"
	case !entry.LatestModifiedAt.Equal(reply.NewestModifiedAt):
		return fmt.Sprintf("it changed after the reply: newest modification %s, the reply saw %s",
			entry.LatestModifiedAt.UTC().Format(time.RFC3339Nano), reply.NewestModifiedAt.UTC().Format(time.RFC3339Nano))
	case entry.SizeBytes != reply.SizeBytes || entry.SizeIsLowerBound != reply.SizeIsLowerBound:
		return fmt.Sprintf("its size changed after the reply: %d bytes, the reply saw %d", entry.SizeBytes, reply.SizeBytes)
	case entry.FilesystemID.Device != reply.Device || entry.FilesystemID.Inode != reply.Inode:
		return "its filesystem identity changed after the reply"
	}
	return ""
}

// releaseVoid reports why reply no longer releases entry: the item changed,
// or its owner attribution is unavailable or differs from the reply's.
func releaseVoid(reply store.ReportReply, entry core.Entry, owner string) string {
	if changed := snapshotChanged(reply, entry); changed != "" {
		return changed
	}
	switch owner {
	case "":
		return "owner evidence is unavailable"
	case reply.Owner:
		return ""
	}
	return fmt.Sprintf("its owner attribution changed from %s to %s", reply.Owner, owner)
}

// archivableReleases are the effective release replies the category step
// may archive: none unless report.release_action is archive.
func archivableReleases(ctx context.Context, paths config.Paths, policy config.Policy) (map[string]store.ReportReply, error) {
	out := map[string]store.ReportReply{}
	if !policy.Report.ArchivesReleases() {
		return out, nil
	}
	replies, err := store.ReadReportReplies(ctx, paths.DatabaseFile)
	if err != nil {
		return nil, err
	}
	for _, reply := range replies {
		if reply.Reply == store.ReportReplyRelease {
			out[reply.Path] = reply
		}
	}
	return out, nil
}

func releaseOwnerAttribution(ctx context.Context, policy config.Policy, releases map[string]store.ReportReply) ownerLookup {
	paths := make([]string, 0, len(releases))
	for path := range releases {
		paths = append(paths, path)
	}
	return lookupOwners(ctx, policy, paths)
}

// releaseStillEffective refuses an archive whose release was superseded by
// a later reply while the copy ran.
func releaseStillEffective(ctx context.Context, paths config.Paths, reply store.ReportReply) error {
	replies, err := store.ReadReportReplies(ctx, paths.DatabaseFile)
	if err != nil {
		return fmt.Errorf("release recheck refused archive: %w", err)
	}
	for _, latest := range replies {
		if latest.Path == reply.Path && latest.Sequence == reply.Sequence {
			return nil
		}
	}
	return fmt.Errorf("release reply %d for %s was superseded by a later reply; original retained", reply.Sequence, reply.Path)
}

// staleSuggestion is the advice for one entry: never archive an item whose
// owner is unknown; keep unsaved Git work; archive only what would pass every
// archive-category check today; otherwise ask.
func staleSuggestion(policy config.Policy, entry core.Entry, verdict core.Verdict, owner, git, gitDetail string, now time.Time) (string, []string) {
	if owner == config.UnknownOwner {
		return staleSuggestAsk, []string{"owner unknown: no registration or producer evidence names an owning role; the coordinator must find the owner, and nothing is archived on inference"}
	}
	if git == staleGitDirty || git == staleGitUnpushed {
		return staleSuggestKeep, []string{"unsaved Git work: " + gitDetail}
	}
	kind, reason := categoryKindOf(entry)
	if reason != "" {
		return staleSuggestAsk, []string{reason}
	}
	category := config.WorkspaceArchiveCategory{Name: config.ReportReleaseCategory, Kind: kind, Roots: policy.Report.Roots,
		Idle: policy.Report.Idle, MaxBytesPerItem: policy.Report.MaxBytesPerItem}
	if refusals := categoryRefusals(policy, category, entry, verdict, now); len(refusals) != 0 {
		return staleSuggestAsk, refusals
	}
	return staleSuggestArchive, nil
}

// observeStale runs one fresh, deep, depth-1 observation of the report roots
// and builds the report.
func observeStale(ctx context.Context, e *env, paths config.Paths, policy config.Policy) (staleObservation, error) {
	now := time.Now().UTC()
	r := policy.Report
	obs := staleObservation{candidates: map[string]staleEntry{}, excluded: map[string]string{}}
	obs.report = staleReport{Mode: "stale_report", GeneratedAt: now, Idle: r.Idle.String(), Roots: r.Roots,
		CoordinatorRole: r.CoordinatorRole, ReleaseAction: string(r.ReleaseAction),
		Groups: []staleGroup{}, Released: []staleReleased{}, Kept: []staleKept{}, Unmeasured: []staleUnmeasured{},
		Attribution: "Owners come only from registration and producer evidence. Unknown-owner items go to the coordinator and are never treated as disposable. Sizes are local bytes; remote archive space is never counted as local headroom."}
	if !r.Enabled {
		return obs, errors.New("the stale-workspace report is off: set report.enabled in the policy")
	}
	var specs []collect.RootSpec
	for _, root := range r.Roots {
		for _, configured := range policy.Roots {
			if configured.Path == root {
				spec := rootSpec(configured, scanOptions{})
				spec.MaxDepth = 1
				specs = append(specs, spec)
				break
			}
		}
	}
	engine := cleanupEngine(e, nil, paths, policy)
	options := engine.Collect
	options.Roots, options.DeepSize = specs, true
	observed, err := collect.Run(ctx, options)
	if err != nil {
		return obs, err
	}
	safetyPolicy := enginePolicy(paths, policy)
	records, err := store.ReadCategoryArchives(ctx, paths.DatabaseFile)
	if err != nil {
		return obs, fmt.Errorf("category archive receipts: %w", err)
	}
	// Receipts of configured categories exclude their unchanged items; the
	// receipts of released items are reported with their release instead.
	archivedBy := make(map[string]store.CategoryArchive, len(records))
	for _, record := range records {
		if record.Category != config.ReportReleaseCategory {
			archivedBy[record.Path] = record
		}
	}
	replyList, err := store.ReadReportReplies(ctx, paths.DatabaseFile)
	if err != nil {
		return obs, fmt.Errorf("stale report replies: %w", err)
	}
	replies := make(map[string]store.ReportReply, len(replyList))
	for _, reply := range replyList {
		replies[reply.Path] = reply
	}
	// Not in use is only established under the same evidence rules as a
	// quarantine or expiry recheck (action.Engine.observeAround).
	obs.report.InUseEvidence = "complete: filesystem, process, service, Gitmoot and registered-agent evidence were observed"
	if gap := collect.EvidenceGap(observed.Reports, len(options.AgentSources) != 0); gap != nil {
		obs.inUseGap = "live-use observation incomplete (" + gap.Error() + ")"
		obs.report.InUseEvidence = obs.inUseGap
	}

	var stale []staleEntry
	for _, entry := range observed.Entries {
		if !slices.Contains(r.Roots, filepath.Dir(entry.Path)) {
			continue
		}
		if entry.Kind != core.EntryKindDirectory {
			obs.excluded[entry.Path] = fmt.Sprintf("only directories are workspace entries, not a %s", entry.Kind)
			continue
		}
		if reason := policy.StaleReportExclusion(entry.Path); reason != "" {
			obs.report.Counts.Policy++
			obs.excluded[entry.Path] = "excluded by policy: " + reason
			continue
		}
		entry.Class = plan.Classify(entry, policy).Class
		verdict := safety.Evaluate(safety.Input{Entry: entry, Policy: safetyPolicy, Now: now})
		if reason := staleInUseReason(entry, verdict); reason != "" {
			obs.report.Counts.InUse++
			obs.excluded[entry.Path] = "in use: " + reason
			continue
		}
		if entry.LatestModifiedAt.IsZero() {
			obs.report.Counts.Unmeasured++
			obs.report.Unmeasured = append(obs.report.Unmeasured, staleUnmeasured{Path: entry.Path, SizeBytes: entry.SizeBytes, SizeMeasure: sizeMeasure(entry)})
			obs.excluded[entry.Path] = "the bounded deep walk could not establish its newest modification"
			continue
		}
		if record, ok := archivedBy[entry.Path]; ok && !entry.LatestModifiedAt.After(record.CreatedAt) {
			if _, inactive := activeCategoryRule(policy, record); inactive == "" {
				// A category archive already decides this unchanged item.
				obs.report.Counts.Archived++
				obs.excluded[entry.Path] = fmt.Sprintf("archived by category %s as %s; its retention and quarantine follow that archive", record.Category, record.Name)
				continue
			}
		}
		idle := now.Sub(entry.LatestModifiedAt)
		if idle < r.Idle.Duration() {
			obs.report.Counts.Recent++
			obs.excluded[entry.Path] = fmt.Sprintf("changed %s ago; the report lists items unchanged for %s", idle.Truncate(time.Second), r.Idle)
			continue
		}
		git, gitDetail := staleGitState(entry.Git)
		item := staleEntry{Path: entry.Path, SizeBytes: entry.SizeBytes, SizeMeasure: sizeMeasure(entry), Git: git, GitDetail: gitDetail,
			NewestModifiedAt: entry.LatestModifiedAt.UTC(), IdleFor: idle.Truncate(time.Second).String(), entry: entry, verdict: verdict}
		stale = append(stale, item)
	}
	candidatePaths := make([]string, 0, len(stale))
	for _, item := range stale {
		candidatePaths = append(candidatePaths, item.Path)
	}
	owners := lookupOwners(ctx, policy, candidatePaths)
	obs.report.OwnerEvidence, obs.ownerErr = owners.status, owners.err

	groups := map[string][]staleEntry{}
	for _, item := range stale {
		if active := owners.active(item.Path); active != "" {
			obs.report.Counts.InUse++
			obs.excluded[item.Path] = "in use: " + active
			continue
		}
		item.Owner = owners.owner(item.Path)
		if item.Owner == "" {
			item.Owner = config.UnknownOwner
		}
		item.OwnerEvidence = owners.evidence(item.Path)
		item.SuggestedAction, item.Reasons = staleSuggestion(policy, item.entry, item.verdict, item.Owner, item.Git, item.GitDetail, now)
		if obs.inUseGap != "" && item.SuggestedAction == staleSuggestArchive {
			item.SuggestedAction, item.Reasons = staleSuggestAsk, []string{obs.inUseGap}
		}
		obs.candidates[item.Path] = item
		if reply, ok := replies[item.Path]; ok {
			// A reply binds the item as its owner saw it: a change of the item
			// or of its owner attribution voids a keep as well as a release.
			void := snapshotChanged(reply, item.entry)
			if void == "" && reply.Owner != item.Owner {
				void = fmt.Sprintf("its owner attribution changed from %s to %s", reply.Owner, item.Owner)
			}
			switch {
			case void != "":
				item.PriorReply = fmt.Sprintf("%s by %s (reply %d) is void: %s", reply.Reply, reply.Role, reply.Sequence, void)
			case reply.Reply == store.ReportReplyKeep && (reply.Until == nil || now.Before(*reply.Until)):
				obs.report.Counts.Kept++
				obs.report.Kept = append(obs.report.Kept, staleKept{Path: item.Path, Role: reply.Role, Reply: reply.Sequence, Until: reply.Until, Note: reply.Note, RepliedAt: reply.RecordedAt})
				continue
			case reply.Reply == store.ReportReplyKeep:
				item.PriorReply = fmt.Sprintf("keep by %s (reply %d) expired at %s", reply.Role, reply.Sequence, reply.Until.Format(time.RFC3339))
			default:
				released := staleReleased{Path: item.Path, Role: reply.Role, Reply: reply.Sequence, Note: reply.Note, RepliedAt: reply.RecordedAt,
					Status: "recorded", SizeBytes: item.SizeBytes}
				if policy.Report.ArchivesReleases() {
					released.Status = "pending_archive"
				}
				for _, record := range records {
					if record.Path == item.Path && record.Category == config.ReportReleaseCategory && record.CreatedAt.After(reply.RecordedAt) {
						released.Status, released.Archive = "archived", record.Name
					}
				}
				obs.report.Counts.Released++
				obs.report.Released = append(obs.report.Released, released)
				continue
			}
		}
		obs.report.Counts.Listed++
		groups[item.Owner] = append(groups[item.Owner], item)
	}
	roles := make([]string, 0, len(groups))
	for role := range groups {
		if role != config.UnknownOwner {
			roles = append(roles, role)
		}
	}
	sort.Strings(roles)
	if _, ok := groups[config.UnknownOwner]; ok {
		roles = append(roles, config.UnknownOwner)
	}
	for _, role := range roles {
		entries := groups[role]
		sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
		addressed := role
		if role == config.UnknownOwner {
			addressed = r.CoordinatorRole
		}
		obs.report.Groups = append(obs.report.Groups, staleGroup{Owner: role, AddressedTo: addressed, Entries: entries})
	}
	return obs, nil
}

// forRole keeps only the groups addressed to role (the coordinator also
// receives the unknown-owner group) and that role's replies.
func (r staleReport) forRole(role string) staleReport {
	out := r
	out.Role = role
	out.Groups = []staleGroup{}
	out.Counts.Listed = 0
	for _, group := range r.Groups {
		if group.AddressedTo == role {
			out.Groups = append(out.Groups, group)
			out.Counts.Listed += len(group.Entries)
		}
	}
	out.Released, out.Kept = []staleReleased{}, []staleKept{}
	for _, released := range r.Released {
		if released.Role == role {
			out.Released = append(out.Released, released)
		}
	}
	for _, kept := range r.Kept {
		if kept.Role == role {
			out.Kept = append(out.Kept, kept)
		}
	}
	out.Counts.Released, out.Counts.Kept = len(out.Released), len(out.Kept)
	return out
}

func runReportStale(ctx context.Context, e *env, role string) error {
	format, err := e.format()
	if err != nil {
		return err
	}
	if role != "" && !config.ValidRole(role) {
		return &usageError{msg: fmt.Sprintf("--role %q is not a role name", role)}
	}
	paths, err := e.resolvePaths()
	if err != nil {
		return err
	}
	policy, err := e.loadFilePolicy()
	if err != nil {
		return err
	}
	obs, err := observeStale(ctx, e, paths, policy)
	if err != nil {
		return err
	}
	report := obs.report
	if role != "" {
		report = report.forRole(role)
	}
	if format == output.FormatJSON {
		return output.WriteJSON(e.stdout, report.Mode, report)
	}
	if role != "" {
		return writeStaleRoleText(e, report)
	}
	return writeStaleText(e, report)
}

func staleSizeText(bytes int64, measure string) string {
	switch measure {
	case "lower_bound":
		return fmt.Sprintf("at least %d bytes (lower bound; the bounded deep walk did not finish)", bytes)
	case "metadata":
		return fmt.Sprintf("%d bytes (top-level metadata only)", bytes)
	}
	return fmt.Sprintf("%d bytes", bytes)
}

func writeStaleEntries(b *strings.Builder, entries []staleEntry) {
	for i, item := range entries {
		fmt.Fprintf(b, "\n%d. %s\n   size %s | git %s | owner %s | idle %s | suggested %s\n",
			i+1, item.Path, staleSizeText(item.SizeBytes, item.SizeMeasure), item.Git, item.Owner, item.IdleFor, item.SuggestedAction)
		if item.GitDetail != "" {
			fmt.Fprintf(b, "   git: %s\n", item.GitDetail)
		}
		for _, reason := range item.Reasons {
			fmt.Fprintf(b, "   - %s\n", reason)
		}
		if item.PriorReply != "" {
			fmt.Fprintf(b, "   note: %s\n", item.PriorReply)
		}
	}
}

// writeStaleRoleText renders the per-role message a host timer can send.
func writeStaleRoleText(e *env, report staleReport) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Stale workspace report for role %s (%s)\n", report.Role, report.GeneratedAt.Format("2006-01-02"))
	if report.Counts.Listed == 0 {
		fmt.Fprintf(&b, "No items unchanged for %s and not in use are waiting for your reply.\n", report.Idle)
	} else {
		fmt.Fprintf(&b, "%d item(s) unchanged for at least %s and not in use. Reply per item:\n", report.Counts.Listed, report.Idle)
		fmt.Fprintf(&b, "  janitor report release <path> --role %s [--note TEXT]\n", report.Role)
		fmt.Fprintf(&b, "  janitor report keep <path> --role %s [--until YYYY-MM-DD] [--note TEXT]\n", report.Role)
		if report.ReleaseAction == string(config.StaleReleaseArchive) {
			b.WriteString("A release is archived (verified copy, then quarantine) by the next cycle if every safety check still passes; any change to the item voids it.\n")
		} else {
			b.WriteString("A release is recorded for the operator; nothing is archived or removed automatically. Any change to the item voids it.\n")
		}
	}
	for _, group := range report.Groups {
		if group.Owner == config.UnknownOwner {
			fmt.Fprintf(&b, "\nOwner unknown (%d), sent to you as coordinator. Find the owner or reply yourself; these are never treated as disposable:\n", len(group.Entries))
		} else {
			fmt.Fprintf(&b, "\nOwned by %s (%d):\n", group.Owner, len(group.Entries))
		}
		writeStaleEntries(&b, group.Entries)
	}
	if len(report.Released) != 0 {
		b.WriteString("\nYour releases still in effect:\n")
		for _, released := range report.Released {
			fmt.Fprintf(&b, "  %s  reply %d  %s\n", released.Path, released.Reply, released.Status)
		}
	}
	_, err := fmt.Fprint(e.stdout, b.String())
	return err
}

func writeStaleText(e *env, report staleReport) error {
	var b strings.Builder
	c := report.Counts
	fmt.Fprintf(&b, "mode: %s\ngenerated: %s\nidle threshold: %s\ncoordinator role: %s\nrelease action: %s\nowner evidence: %s\nin-use evidence: %s\n",
		report.Mode, report.GeneratedAt.Format(time.RFC3339), report.Idle, report.CoordinatorRole, report.ReleaseAction, report.OwnerEvidence, report.InUseEvidence)
	fmt.Fprintf(&b, "listed: %d  in use: %d  changed recently: %d  excluded by policy: %d  already archived: %d  unmeasured: %d  kept: %d  released: %d\n%s\n",
		c.Listed, c.InUse, c.Recent, c.Policy, c.Archived, c.Unmeasured, c.Kept, c.Released, report.Attribution)
	for _, group := range report.Groups {
		if group.Owner == config.UnknownOwner {
			fmt.Fprintf(&b, "\n== owner unknown -> coordinator %s (%d) ==\n", group.AddressedTo, len(group.Entries))
		} else {
			fmt.Fprintf(&b, "\n== %s (%d) ==\n", group.Owner, len(group.Entries))
		}
		writeStaleEntries(&b, group.Entries)
	}
	if len(report.Released) != 0 {
		b.WriteString("\nReleased by owners:\n")
		for _, released := range report.Released {
			fmt.Fprintf(&b, "  %s  by %s (reply %d)  %s  %d bytes\n", released.Path, released.Role, released.Reply, released.Status, released.SizeBytes)
		}
	}
	if len(report.Kept) != 0 {
		b.WriteString("\nKept by owners:\n")
		for _, kept := range report.Kept {
			until := "until it changes"
			if kept.Until != nil {
				until = "until " + kept.Until.Format(time.RFC3339) + " or it changes"
			}
			fmt.Fprintf(&b, "  %s  by %s (reply %d)  %s\n", kept.Path, kept.Role, kept.Reply, until)
		}
	}
	if len(report.Unmeasured) != 0 {
		b.WriteString("\nNot listed, newest modification unknown (bounded deep walk incomplete):\n")
		for _, item := range report.Unmeasured {
			fmt.Fprintf(&b, "  %s  %s\n", item.Path, staleSizeText(item.SizeBytes, item.SizeMeasure))
		}
	}
	_, err := fmt.Fprint(e.stdout, b.String())
	return err
}

type staleReplyReport struct {
	Mode   string            `json:"mode"`
	Reply  store.ReportReply `json:"reply"`
	Effect string            `json:"effect"`
}

// parseUntil accepts a date (end of that day, UTC) or an RFC 3339 time.
func parseUntil(value string, now time.Time) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}
	until, err := time.Parse(time.RFC3339, value)
	if err != nil {
		day, dayErr := time.Parse("2006-01-02", value)
		if dayErr != nil {
			return nil, fmt.Errorf("--until %q: use YYYY-MM-DD or an RFC 3339 time", value)
		}
		until = day.Add(24*time.Hour - time.Second)
	}
	until = until.UTC()
	if !until.After(now) {
		return nil, fmt.Errorf("--until %s is not in the future", until.Format(time.RFC3339))
	}
	return &until, nil
}

// runReportReply records a release or keep reply after validating, against a
// fresh observation, that path is a current stale report entry and role is
// its owner (or the coordinator for an unknown-owner entry).
func runReportReply(ctx context.Context, e *env, kind, path, role, note, untilText string) error {
	format, err := e.format()
	if err != nil {
		return err
	}
	if !config.ValidRole(role) {
		return &usageError{msg: fmt.Sprintf("--role %q is not a role name", role)}
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return &usageError{msg: fmt.Sprintf("%q is not an absolute, cleaned path", path)}
	}
	if len(note) > 1024 {
		return &usageError{msg: "--note exceeds 1024 bytes"}
	}
	now := time.Now().UTC()
	until, err := parseUntil(untilText, now)
	if err != nil {
		return &usageError{msg: err.Error()}
	}
	paths, err := e.resolvePaths()
	if err != nil {
		return err
	}
	policy, err := e.loadFilePolicy()
	if err != nil {
		return err
	}
	obs, err := observeStale(ctx, e, paths, policy)
	if err != nil {
		return err
	}
	item, ok := obs.candidates[path]
	if !ok {
		reason := obs.excluded[path]
		if reason == "" {
			reason = "it is not a depth-1 entry of a report root"
		}
		return fmt.Errorf("%s is not a current stale report entry: %s", path, reason)
	}
	switch {
	case obs.ownerErr != nil:
		return fmt.Errorf("owner evidence is unavailable, so the owner of %s cannot be verified: %w", path, obs.ownerErr)
	case obs.inUseGap != "":
		return fmt.Errorf("%s cannot be verified as not in use: %s", path, obs.inUseGap)
	case item.Owner == config.UnknownOwner && role != policy.Report.CoordinatorRole:
		return fmt.Errorf("%s has no known owner; only the coordinator role %s may reply for it, not %s", path, policy.Report.CoordinatorRole, role)
	case item.Owner != config.UnknownOwner && role != item.Owner:
		return fmt.Errorf("%s is owned by %s; %s may not reply for it", path, item.Owner, role)
	}
	reply := store.ReportReply{Path: path, Reply: kind, Role: role, Owner: item.Owner, Note: note, Until: until,
		NewestModifiedAt: item.entry.LatestModifiedAt, SizeBytes: item.entry.SizeBytes, SizeIsLowerBound: item.entry.SizeIsLowerBound,
		Device: item.entry.FilesystemID.Device, Inode: item.entry.FilesystemID.Inode, RecordedAt: now}
	if err := config.EnsureDir(paths.StateDir); err != nil {
		return err
	}
	db, err := store.Open(ctx, paths.DatabaseFile)
	if err != nil {
		return err
	}
	defer db.Close()
	err = db.Write(ctx, func(tx *store.Tx) error {
		var err error
		reply.Sequence, err = tx.RecordReportReply(ctx, reply)
		return err
	})
	if err != nil {
		return err
	}
	if reply.Until != nil {
		normalized := reply.Until.UTC()
		reply.Until = &normalized
	}
	reply.NewestModifiedAt, reply.RecordedAt = reply.NewestModifiedAt.UTC(), reply.RecordedAt.UTC()
	report := staleReplyReport{Mode: "stale_report_reply", Reply: reply}
	switch {
	case kind == store.ReportReplyKeep && until != nil:
		report.Effect = fmt.Sprintf("kept: left out of stale reports until %s or until it changes", until.Format(time.RFC3339))
	case kind == store.ReportReplyKeep:
		report.Effect = "kept: left out of stale reports until it changes"
	case policy.Report.ArchivesReleases():
		report.Effect = fmt.Sprintf("released: the next cycle archives it through the verified category path (at most %d per cycle) if it is unchanged and every safety check still passes; a change voids the release", policy.Report.MaxItemsPerCycle)
	default:
		report.Effect = "released: recorded and listed for the operator; report.release_action is none, so nothing is archived or removed automatically"
	}
	if format == output.FormatJSON {
		return output.WriteJSON(e.stdout, report.Mode, report)
	}
	_, err = fmt.Fprintf(e.stdout, "mode: %s\nreply: %d\npath: %s\n%s by %s (owner %s)\n%s\n", report.Mode, reply.Sequence, reply.Path, reply.Reply, reply.Role, reply.Owner, report.Effect)
	return err
}

func reportCommand() *command {
	return &command{
		name:    "report",
		usage:   "janitor report <subcommand>",
		summary: "Weekly stale-workspace report routed to owning roles, and their release/keep replies",
		subcommands: []*command{
			{
				name:    "stale",
				usage:   "janitor report stale [--role ROLE]",
				summary: "List items unchanged for report.idle and not in use, grouped by owning role",
				long: "Owners come only from registration and producer evidence; unknown-owner items are\n" +
					"addressed to report.coordinator_role and never suggested for archiving.\n" +
					"--role ROLE --format text renders the message a host timer can send to that role.",
				register: func(fs *flag.FlagSet) func(ctx context.Context, e *env, args []string) error {
					role := fs.String("role", "", "only the entries addressed to this role")
					return func(ctx context.Context, e *env, args []string) error {
						if len(args) > 0 {
							return &usageError{msg: "report stale takes no arguments"}
						}
						return runReportStale(ctx, e, *role)
					}
				},
			},
			reportReplyCommand(store.ReportReplyRelease, "Release a stale report entry: recorded, and archived by the next cycle only with report.release_action archive"),
			reportReplyCommand(store.ReportReplyKeep, "Keep a stale report entry out of later reports until --until or until it changes"),
		},
	}
}

func reportReplyCommand(kind, summary string) *command {
	usage := "janitor report " + kind + " <path> --role ROLE [--note TEXT]"
	if kind == store.ReportReplyKeep {
		usage = "janitor report keep <path> --role ROLE [--until YYYY-MM-DD] [--note TEXT]"
	}
	return &command{
		name:    kind,
		usage:   usage,
		summary: summary,
		register: func(fs *flag.FlagSet) func(ctx context.Context, e *env, args []string) error {
			role := fs.String("role", "", "the replying role: the entry's owner, or the coordinator for an unknown-owner entry (required)")
			note := fs.String("note", "", "free-text note recorded with the reply")
			until := new(string)
			if kind == store.ReportReplyKeep {
				until = fs.String("until", "", "keep until this date (YYYY-MM-DD, end of day UTC) or RFC 3339 time; default: until the item changes")
			}
			return func(ctx context.Context, e *env, args []string) error {
				// Flags may follow the path.
				if len(args) > 1 {
					if err := fs.Parse(args[1:]); err != nil {
						return &usageError{msg: err.Error()}
					}
					args = append([]string{args[0]}, fs.Args()...)
				}
				if len(args) != 1 {
					return &usageError{msg: fmt.Sprintf("report %s takes exactly one path", kind)}
				}
				if *role == "" {
					return &usageError{msg: "--role is required"}
				}
				return runReportReply(ctx, e, kind, args[0], *role, *note, *until)
			}
		},
	}
}
