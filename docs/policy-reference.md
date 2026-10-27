# Policy reference and isolated examples

Start with the [annotated policy](policy.example.yaml); run `janitor policy check` against the intended config. [Safety boundaries](threat-model.md) apply regardless of policy, and [recovery](recovery.md) covers mutations. This reference is for policy **version 1**.

## Resolution and validation

The policy defaults to `<config-dir>/policy.yaml`; `--policy` overrides `JANITOR_POLICY`. Config, state, and cache directory precedence is CLI flag, `JANITOR_*_DIR`, `XDG_*_HOME`, then the home-based default (see [README configuration](../README.md#configuration)). A missing policy uses built-in defaults; a present but unreadable, empty, malformed, multi-document, unknown-field, or invalid policy fails rather than falling back. The YAML is decoded over defaults: omitted keys retain defaults, while explicit zero/false/empty values are validated as written. Paths beginning `~` expand against the resolved home; absent home plus fully overridden directories requires an explicit root in a policy. Use `janitor status` to inspect resolved sources.

| Section | Meaning |
| --- | --- |
| `roots` | Discovery paths, `max_depth`, symlink and filesystem traversal, `report_only` (no mutations under that root). With `cross_filesystem: false`, a mount point inside a root is listed but neither the metadata walk nor deep sizing enters it; its size is reported as unknown, never zero. Do not use a mounted archive or network share as part of a local root. |
| `protect` | Additive protected paths and basename patterns; built-in credential names, Gitmoot home, state and effective quarantine remain protected. |
| `retention` | Default quarantine period (`none`, `3d`, `7d`, `30d`, `90d`, `permanent`), quarantine directory, and separate deletion opt-in. |
| `prevention` | Deep-scan interval, disk alert thresholds/cooldown, per-filesystem capacity targets, and opt-in automatic quarantine and expiry; a policy never installs a timer. |
| `canonical_roots`, `classification`, `ownership`, `gitmoot` | Canonical project locations, literal project markers and name signals, foreign ownership checks, and read-only Gitmoot ledger location. |
| `caches` | Exact declared cache roots; `action` is `keep`, `quarantine`, `delete_candidate`, or `investigate`. Omitted action means `investigate`; TTL/size bounds need complete evidence for directories. Dedicated irreversible prune has further restrictions. |
| `jev` | Disabled by default; model, endpoint, key **environment variable name**, request bounds, thresholds, caching and redaction. See [privacy](privacy.md). |
| `collectors`, `limits`, `safety` | Explicit collector sources, bounded work/timeouts, and destination headroom. `allow_cross_filesystem_quarantine` does not enable a copy path: the Linux action engine still refuses cross-filesystem quarantine. |

Safety is a first-precedence veto. Protected paths/canonical roots precede explicit cache rules, then built-in classification and investigate fallback. Within a tier, safer action wins, independently of YAML order. No policy field waives a core protection or enables generic direct deletion. `follow_symlinks` changes discovery, not symlink-containment safety. `delete_candidate` needs an exact cache rule and, for official pruning, a dedicated owned/idle cache plus an approved action, configured absolute supported executable, and a distinct confirmed `apply --prune` call. `retention.delete_enabled` alone never expires an item; a confirmed expiry also needs elapsed retention and fresh complete checks.

## Capacity targets

`prevention.targets` is empty by default. Each target names an existing configured
inventory root exactly once; at most 64 targets are accepted. Targets on one
filesystem combine the strongest thresholds, not their sum.

| Field | Meaning |
| --- | --- |
| `path` | Root path, expanded using the same home/path rules as `roots`. |
| `target_free_bytes` | Positive desired available bytes. For this host's planned 50 GiB target: `53687091200`; configuration does not establish achievement. |
| `reserve_free_bytes` | Nonnegative critical reserve, no greater than the configured target. Effective reserve is at least 5% of filesystem capacity; effective target is at least the reserve. |
| `recovery_margin_bytes` | Positive hysteresis margin above the effective target; target plus margin must fit a signed 64-bit byte count. |

`prevention.capacity_interval` defaults to `1m` and accepts `1s` through `1h`.
Persisted scans, cycles, and watcher timer ticks share a serialized due check and
sample. `scan --no-store` does not sample or update pressure. The snapshot uses
one SQLite row, survives restart, and expires after twice the interval.
The watcher samples even without directory events; restart it after policy changes.

States are `target_recovered`, `cleanup_needed`, `critical`,
`no_safe_reclaim`, and `measurement_unknown`. Below reserve is critical; below
target requests cleanup. Once pressure begins, recovery requires target plus
margin. Critical, unknown, or exhausted bounded recovery sets `admission_hold`;
the hold remains until verified hysteresis recovery.
`available_bytes` excludes filesystem-reserved blocks. Unreadable roots,
inconsistent volume observations, stale snapshots, and backward clocks cannot
report healthy capacity. Unknown byte values are JSON `null`, never zero.

`janitor --format json status` returns `data.capacity` with `sampled_at`,
`valid_until`, `policy_hash`, and `volumes`; each volume includes its device/root
identity, thresholds, state, `admission_hold`, and reason. Status is read-only;
missing data or a changed policy returns unknown until a fresh sample exists.
`cycle`, stored `scan`, and watcher reports also include the snapshot. This is
an advisory contract, not deletion authority or an enforced job admission gate.
No target relaxes the existing independent 5% dispatch floor.

## Bounded cache recovery

Automatic official pruning is off by default. `prevention.recovery.enabled`
requires capacity targets and enabled Git, process, and service collectors.
It does not authorize arbitrary deletion, Docker pruning, or backup cleanup.
Each eligible cache must already have an exact `delete_candidate` rule,
`dedicated: true`, and an absolute supported `official_binary`, plus:

| Cache `recovery` field | Required authority/bound |
| --- | --- |
| `owner` | Responsible artifact owner; unknown ownership stays protected. |
| `approval` | Owner's saved approval reference for this exact retired cache. |
| `rebuild_cost` | Human-readable consequence of losing cached objects. |
| `max_prune_bytes` | Positive whole-store allocated-byte ceiling. |
| `min_idle` | At least `1h`; complete recursive modification evidence is required. |

Supported automatic providers are offline uv/npm and a dedicated retired Go
build cache (`.cache/go-build`). Go runs `go -C <cache> clean -cache` with that
exact `GOCACHE`, local toolchain selection, and disabled Go environment/network
configuration. Module caches, active shared caches, source, credentials, and
backup repositories are not added as cleanup classes.

| `prevention.recovery` field | Default and bound |
| --- | --- |
| `enabled` | `false`; separate from quarantine/expiry opt-ins. |
| `max_stores` | `1`; at most 16 stores considered for allocated-byte measurement per pass. |
| `max_bytes` | `1073741824`; cumulative charged whole-store upper bounds, not provider promises. |
| `interval` | `24h`; at least `1h` between attempts at a store, persisted across restarts. |
| `time_budget` | `1m`; positive, at most `1h`, for recovery planning and provider work. Inventory retains its existing collector bounds. |

Recovery-enabled cycles request deep inventory. Oldest eligible stores are
considered first. Shared inodes, incomplete measurements, oversized stores,
active references, and exhausted budgets are refusals, not invitations to
switch to generic deletion. The ordinary plan/approval/apply path rechecks
safety and the allocated-byte ceiling immediately before provider execution.
Fresh capacity is measured before recovery and after each attempted provider;
reaching the recovery threshold stops the pass.

Process arguments and environments remain unread. As a conservative substitute
for unavailable per-cache producer leases, any running matching provider holds
its automatic recovery caches, even when its working directory is elsewhere.
Go holds include `gopls` and auxiliary tool processes, not only the `go` driver
or compiler; a long-lived language server can conservatively keep a cache held.
Any nonterminal Gitmoot job/task or an unreadable existing ledger also holds
automatic recovery caches: completion cannot be guessed from an unmatched
worktree path. A narrower producer-owned release contract is required before
loosening these holds.

The cycle's `recovery` report records owner, approval, rebuild cost, skips,
budget charges, stop reason, before/after store allocation, and before/after
filesystem availability. Net filesystem change may include concurrent writers;
it is not attributed solely to Janitor. Quarantine on the same filesystem is
not counted as reclaim. Official-prune receipts remain in
`official-prunes.jsonl`; a bounded SQLite row per attempted cache records its
cooldown and outcome. Failed/interrupted attempts require reconciliation and
a new owner approval; changing approval does not bypass cooldown.
If safe candidates or budgets end below target, `no_safe_reclaim` retains an
admission hold until measured recovery. These observations do not themselves
enforce admission in another service.

## Capacity reporting

`status` and `history` expose `data.inventory_report` in JSON and a bounded
summary in text. The daily `cycle` JSON record includes `inventory_report`
directly. Reporting never approves cleanup or releases a job-admission hold.

| Report field | Meaning and limits |
| --- | --- |
| `growth` | Apparent-size changes between matching deep observations, with scan IDs, timestamps, staleness and per-path reasons for unknown values. At most 64 changed/unknown rows; omitted rows are counted. |
| `store_budgets` | Declared logical-size thresholds, allocated prune caps, export-file caps, retention, owners and approval gaps. These have different units/scopes and must not be added or substituted for each other. |
| `activities` | Recent quarantine, expiry, official prune, verified archive/restore and recovery-decision outcomes. Fresh completions and replayed receipts have separate counts. |
| `unresolved_decisions` | Missing owners, approvals and other declared-policy decisions. Existing recovery reports and activity `skipped` rows identify why actions stopped and who owns each decision. |

Metadata-only scans do not displace the latest deep observation. A growth
baseline needs the same roots, traversal settings, limits and sizing version,
non-overlapping observation windows, known matching identity/kind, and complete
size evidence. `configured_scope_mismatch` includes both changed configuration
and scans made with different CLI roots or bounds. Missing/incomplete evidence
is unknown, not zero growth. The two most recently completed deep scans remain
pinned during history reduction; a matching older baseline is not guaranteed.
Directory rows may overlap, so do not sum them.

Inventory measurements describe the scan, before any subsequent cycle actions.
Operation records describe later effects; they do not rewrite an old inventory
as if it were a fresh measurement. Concurrent writers can affect both.

`available_before_bytes`, `available_after_bytes` and `available_change_bytes`
are actual filesystem observations, **not recovery attributable to Janitor**.
`store_removed_allocated_bytes` is scoped namespace reduction, not proof that
physical blocks were returned. `estimated_reclaim_bytes` remains conditional on
safety revalidation. Move/copy activities report zero actual reclaim; expiry
and prune leave `actual_reclaimed_bytes` null when attribution is unproved.
A null measurement is unknown, never zero. An activity left `starting` has no
confirmed outcome: consult the authoritative cleanup/provider/archive receipt
before retrying.

The reporting journal retains at most 256 activities of at most 64 KiB each;
text output shows 16 and discloses the retained count. Recovery decisions retain
up to eight skipped-path/owner/reason rows and count omissions. This reporting
bound does not delete authoritative audit records or shrink the SQLite file.
Schema 10 adds reporting metadata; old observations without a recorded scope
cannot establish growth.

## Admission consumer hook

The read-only hook is `janitor --format json status`: require the supported
envelope schema, `kind: status`, and `data.capacity`. A consumer must validate
the configured policy hash, timestamps/cadence and every device needed by new
heavy work. Missing, stale, future, unsupported, unknown or incomplete coverage
must hold that work rather than assume health. Honour `admission_hold`,
including `no_safe_reclaim`; do not infer release from an increase in free space.
Release only after a fresh producer observation verifies hysteresis recovery.

This is a contract for an external consumer, not enforcement by Janitor.
Gitmoot integration is tracked in `gitmoot/gitmoot#2359` and remains default-off
pending real producer/consumer verification and staged approval. A consumer
must preserve urgent native messages and read-only diagnostics, never cancel
running jobs or stop unrelated services, and retain the existing independent
disk guard. A read-only label on an arbitrary executable is not an exemption.



## Worked fixture-only policies

Use a disposable fixture root and private config/state/cache directories, **not** your home or a real repository. These are separate minimal documents, not snippets to paste together. Replace `/tmp/janitor-fixture` only with another controlled absolute fixture location; no command below runs a mutation.

**Read-only inventory of a fixture:**

```yaml
version: 1
roots:
  - path: /tmp/janitor-fixture/repos
    max_depth: 2
    follow_symlinks: false
    cross_filesystem: false
    report_only: true
jev:
  enabled: false
```

With `report_only: true`, scan and plan can describe a path but cannot authorize its mutation. A symlink escaping this root remains unsafe even if symlink discovery is later enabled.

**Separately, an explicitly named regenerable fixture cache:**

```yaml
version: 1
roots:
  - path: /tmp/janitor-fixture/cache
    max_depth: 1
    follow_symlinks: false
    cross_filesystem: false
    report_only: false
caches:
  - name: fixture-build
    path: /tmp/janitor-fixture/cache/build
    action: quarantine
    retention: 7d
    max_bytes: 1048576
retention:
  quarantine_dir: /tmp/janitor-fixture/state/quarantine
  delete_enabled: false
jev:
  enabled: false
```

The cache rule only proposes quarantine when the logical-size bound is met; a directory needs a **complete deep-size scan** to satisfy that bound. Unknown/partial evidence leads to investigation, not approval. Even a matching rule requires a safe verdict, a stored approved action, and explicit confirmed apply. Keep the state directory outside discovery roots in a real configuration; this fixture path is separate from the cache root. Avoid reusing any fixture path that points into a real home, provider cache or Gitmoot tree.

## Ignored contents inside whole worktrees

Git-clean and published does not prove that ignored files can be recreated.
Before whole-worktree quarantine or expiry, Janitor walks descendants without
following links and compares each file with the Git index. Every untracked
file, including ignored credentials, evidence and lockfiles, preserves the
whole object unless a current explicit `caches` rule proves its location
regenerable. Directory names such as `node_modules` are not proof.

An approval must name a canonical path strictly **inside** the original
worktree and explicitly use `action: quarantine` or `action: delete_candidate`.
It must have neither `max_bytes` nor `ttl`: a bound-induced KEEP must not turn
into permission to delete the enclosing worktree. Rules for the worktree
itself, its parents or its quarantine destination do not approve descendants.
Overlapping preserving/bounded cache rules, report-only roots, protected paths
and credential/evidence name patterns take precedence, including inside an
otherwise approved cache. An ignored symlink, nested Git repository, gitlink,
special file or filesystem crossing refuses cleanup.
The existing potentially-live database extension veto also applies to regular
descendant files, even tracked files or files inside an approved cache.

For example, only after independently establishing that **all** contents of a
synthetic build directory are disposable, an isolated fixture policy may use:

```yaml
caches:
  - name: explicitly-disposable-fixture-build
    path: /tmp/janitor-fixture/repos/app/build
    action: quarantine
    retention: 7d
```

Do not copy that assertion onto a real cache without establishing its contents
are regenerable. Unapproved content elsewhere in the tree still preserves it.
This does not change normal cache scheduling or enable deletion by itself.

The proof is bounded to 100,000 index records and traversed entries, depth 64,
16 MiB of Git output, and the configured Git timeout. Errors, unreadable
directories, cancellation and exceeded bounds preserve the object; no content
secret scanning occurs. Old inventories without a successful proof are
unknown. Actual quarantine and expiry always recompute under current policy,
including receipts created by older binaries. Receipt descendants retain their
original policy paths after Git-aware relocation; removing a cache approval
revokes expiry permission. Restore remains available after a proof refusal.

## Reviewed source-name exceptions

`source_name_approvals` is absent by default. A tracked, published file such as
`credentials.go` can still match a protected name. Tracking, a source extension,
or a secret scan never creates permission to remove it. Without an exact
authorized review record, the name remains protected.

This optional policy adjudicates **one protected-name match**, not the containing
workspace's lifecycle or disposal permission. The operator must explicitly
authorize each reviewer's source-content scope and record the determination
that the exact bytes are ordinary source/documentation, not credential or
evidence payloads. A reviewer may be an authorized agent; do not describe that
as human review. Janitor neither authenticates the external review record nor
generates approvals. Protect the policy file as an administrative authority.

| Field | Contract |
| --- | --- |
| `source_name_approvals.generation` | Nonempty policy generation, at most 128 bytes. |
| `source_name_approvals.reviewers` | Explicit authorized issuer identities; at most 64 unique entries. |
| `source_name_approvals.files` | At most 64 exact file/pattern records; no directory, glob or repository-wide approvals. |
| `files[].repository`, `remote`, `path` | Canonical absolute **original checkout** path, exact credential-free HTTPS origin URL or canonical local origin path, and exact relative source/documentation file path. SSH origin forms are not supported for these records. |
| `commit`, `blob`, `sha256` | Full lowercase commit/blob IDs and SHA-256 of reviewed file bytes. The commit must be published according to local origin-tracking refs; its path's blob, current index blob and actual Git object hash must agree. No fetch occurs. |
| `name_pattern` | One configured `protect.name_patterns` rule matching this basename. Every matching protected-name rule needs its own record. |
| `reviewer`, `record`, `generation` | Authorized issuer, reference to the exact content review, and current policy generation. Store references, not credential contents. |
| `reviewed_at`, `expires_at` | Explicit timestamps; review must not be in the future and expiry must be strictly later than the current evaluation time. |

Only ordinary source/documentation extensions are eligible, and that is only
a negative filter. The file must be Git-tracked, regular, non-hardlinked, at
most 1 MiB, and match the index executable/type mode. Hidden path components,
secret containers such as `.env`, keys and credential JSON, databases, evidence
name matches, links, special files and mount crossings cannot be approved.
Explicit protected paths, report-only roots and preserving/bounded cache rules
still win. Dirty/stashed/unpublished state, consumers, lifecycle and capacity
gates remain independent.

Quarantine and expiry reopen and hash the actual file without following links,
check its identity before and after reading, and revalidate the record. The
complete approval policy is included in the safety fingerprint whenever used;
changing even another record invalidates an existing approval snapshot.
Unknown, missing, changed, ambiguous, revoked or expired approval preserves the
workspace. Restore remains available after refusal. No live approval entries
are installed by enabling this feature.

A protected-name refusal is reported as `policy_protected`, with a path and
rule but no file contents. It is not reported as broken Git metadata or a
collector failure. Actual metadata, I/O and bounded-proof failures retain their
existing fail-closed reporting.


## Exact evidence exports

`evidence_exports` is empty by default. Each rule names one completed, inactive,
owner-confirmed credential-free **regular export file**, not a directory,
checkout, raw session store or database. Existing protections remain blocking;
an export rule cannot release them. Unknown/live stores remain report-only.
Credential-free is an owner's declaration, not an automatic secret detector.

| Field | Contract |
| --- | --- |
| `name`, `class`, `path` | Unique name and canonical exact file inside an inventory root. Classes: `completed_report`, `review_evidence`, `session_export`, `evidence_export`. At most 64 rules. |
| `owner`, `approval`, `completed_at`, `credential_free` | Explicit owner/decision, verified completion timestamp and positive credential-free declaration. A file modified after completion is held. |
| `source_container`, `source_lifetime` | Exact containing directory and its disposal lifetime. Never infer these from an entire checkout or raw session tree. |
| `local_retention`, `local_expiry_enabled` | Defaults to `30d` from verified completion. Stricter `90d` or `permanent` retention is accepted; `permanent` forbids expiry. Local expiry is independently opt-in, and the normal quarantine grace period and deletion permissions still apply. |
| `max_bytes` | Per-file ceiling; omitted/zero defaults to 1 GiB. Positive overrides may not exceed 1 GiB; oversized exports remain retained. |
| `archive.directory`, `archive.owner`, `archive.approval`, `archive.lifetime` | An existing approved directory outside every export source container, with independent ownership/lifetime. Same-lifetime, cache/quarantine overlap, symlinks and ambiguous same-device mount aliases are refused. No storage is provisioned. |
| `archive.retention`, `archive.delete_enabled` | `permanent` and `false`. Archive deletion is unsupported, regardless of local expiry permission. |
| `archive.manifest`, `archive.manifest_sha256` | Exact immutable manifest path and hash returned by successful archival. Pin both in policy before local cleanup can become eligible. |

The archive directory must also have an independent `protect.paths` entry;
removing an export rule must not silently remove the archive's protection.
The manifest records owner/lifetime decisions, source and compressed hashes,
file metadata, allocation, and actual restore proof. Creation uses exclusive
descriptor-anchored files, checks available space, restores and verifies a
temporary copy, syncs the bundle and publishes without replacing anything.
Unsupported extended metadata, special permissions, multiple hard links,
incomplete archives and failed checks preserve the source.

Active processes/open descriptors, queued producer work and unknown producer
state hold the export. Mutation-time collection verifies source content and
archive integrity again. The binding persists in quarantine snapshots: removing
a rule, revoking expiry, changing the archive root or losing its payload cannot
turn the local copy into ordinary disposable data. Ancestor cleanup rules cannot
remove an export container wholesale.

`janitor archive` copies only; `local_freed_bytes` is therefore zero. Archive
allocation and shared-volume available-byte change are distinct observations,
not attributable cleanup credit. `same_filesystem_at_archive_creation` describes
the recorded creation topology, not an assertion about a later recovery host.
See [the archive workflow](recovery.md#verified-export-archives) before enabling
any local expiry.

## Workspace archives

`workspace_archives` and `workspace_archive_keep` are empty by default; with
neither configured Janitor behaves exactly as before (report/quarantine only).
A workspace archive is an **opt-in, copy-only** verified tar of one released
directory, written to any directory you already mounted (external disk, NAS,
SSHFS/NFS, rclone mount). No storage is provisioned or assumed. `janitor
archive --workspace NAME` never removes the source or an archive and reports
`local_freed_bytes: 0`. Local removal remains with the ordinary
quarantine/expiry workflow and is permitted only through
[local expiry](#workspace-archive-local-expiry), which binds it to a pinned
archive that exactly matches the local tree.

| Field | Contract |
| --- | --- |
| `name` | Unique; 1-128 letters, digits, `.`, `_` or `-`, starting with a letter or digit. Names the outputs `<name>.tar`, `<name>.manifest.json` and `<name>.bundle`. At most 64 rules. |
| `path` | Canonical absolute directory strictly inside an inventory root. Refused when it equals, contains or lies inside another rule's path, a `protect.paths` entry, a `report_only` root, a `workspace_archive_keep` path, or a raw runtime/credential store (`.git`, `.ssh`, `.gitmoot`, ...). |
| `owner`, `release` | The releasing owner and a reference to the release decision (for example a message ID). Both required. |
| `dependent_roots` | Optional canonical directories searched for external dependents. Empty means every inventory root. |
| `archive.directory` | Existing canonical directory outside every workspace archive source and evidence export container, not overlapping the quarantine, Gitmoot home, a cache rule or Janitor's state, and covered by an independent `protect.paths` entry. Every path component is opened without following symlinks. |
| `archive.expect_mount_source`, `archive.expect_fstype` | Optional `/proc/self/mountinfo` source and filesystem type of the destination mount. A mismatch, including an unmounted destination that shows the parent filesystem, refuses creation, verification and restore; nothing is ever written to a local fallback. |
| `local_retention`, `local_expiry_enabled` | `local_retention` defaults to `30d`, measured from the pinned manifest's `created_at`; stricter `90d` or `permanent` is accepted and `permanent` forbids expiry. `local_expiry_enabled` defaults to `false`; enabling it requires a pinned `archive.manifest`/`manifest_sha256` and the Git, process and service collectors. Neither field is part of the archive's rule hash, so enabling expiry never invalidates an existing archive. |
| `archive.manifest`, `archive.manifest_sha256` | Empty before creation. Pin the exact `<directory>/<name>.manifest.json` path and SHA-256 returned by a successful creation. |

`workspace_archive_keep` records an owner's KEEP decision: `path`, `owner` and
`reference` are all required. Any workspace archive at, inside or containing a
kept path is an unresolved KEEP/release conflict and the whole policy is
refused before any archive work. Only the custodian or an authorized
coordinator resolves it, by removing the keep record or the release.

Creation refuses, leaving the source and destination untouched, when:

- any name in the tree is secret-like: the built-in screen (`.env`, `.env.*`
  except `.env.example`/`.sample`/`.template`, `id_rsa*`, `id_ed25519*`,
  `.netrc`, `.pgpass`, `.npmrc`, `.pypirc`, `credentials.json`,
  `service-account.json`, `token.json`, `*.pem`, `*.key`, `*.p12`, `*.pfx`,
  `*.kdbx`, `*.keystore`, `*.jks`; certifi's public `cacert.pem` is exempt) or
  any `protect.name_patterns` entry matches;
- a process has its working directory, root, executable or an open descriptor
  inside the path, or a process cannot be inspected (`collectors.proc_root`);
- a gitdir file, `objects/info/alternates` file or symlink outside the path
  (searched to depth 6 on each search root's filesystem) resolves into it, a
  gitdir or alternates file there exceeds 64 KiB, or a search exceeds
  `limits.deep_size_max_entries`. Symlinks are followed as the kernel would,
  through chained links and symlinked directories; one that reaches the path at
  any step is a dependent, and one that loops, chains more than 40 links or
  cannot be examined also refuses;
- the tree crosses a mount, holds anything but directories, regular files and
  symlinks, carries extended attributes, exceeds `limits.deep_size_max_entries`
  members, borrows Git objects from outside via alternates, has a nested
  worktree whose history lives outside, or has a `.git` symlink anywhere
  (including the root) that does not resolve to a directory inside the tree;
- the destination mount differs from its expectation, or any output name
  already exists (an interrupted run's published names are never reused).

The tar is written with Go's `archive/tar` (PAX, numeric owners, nanosecond
modification times) into a private staging directory under the destination
while every byte written and every file read is hashed. The written file is
then read back: its SHA-256 must equal the stream SHA-256, its member list,
types, sizes, modes, owners, mtimes, link targets and per-file SHA-256 must
equal the local tree, and every source member must still have its recorded
identity, metadata and change time. A linked worktree (a root `.git` file,
never a symlink, pointing outside) additionally gets a `git bundle` of `HEAD`,
verified with `git bundle verify` and `git bundle list-heads`; the manifest
records the
worktree's admin entry and whether it is locked. Janitor does not lock or
otherwise modify the admin entry. Policy, live-process, dependent, mount and
source checks run again immediately before publication, which renames the
outputs without replacement, manifest last. See
[restoring a workspace archive](recovery.md#workspace-archives).

### Workspace archive local expiry

Local expiry mirrors [exact evidence exports](#exact-evidence-exports) and adds
no second deletion path: the ordinary plan, approval, quarantine, grace period
and `apply --expire` workflow removes the local copy, and only while the pinned
archive still stands in for it. Every entry at a rule's path, and a quarantined
copy mapped back to it, is held by a blocking `durable_evidence` protection
("released workspace remains retained") unless all of the following hold:

- `local_expiry_enabled: true`, no `workspace_archive_keep` record overlaps the
  path, the path is an ordinary directory and no other blocking protection,
  `protect.paths` or `protect.name_patterns` match applies;
- the pinned manifest's SHA-256 matches, it belongs to this rule, and the
  destination mount matches its expectation;
- the **current local tree equals the manifest member list exactly**: the same
  paths, types, sizes, modes, owners, nanosecond modification times and link
  targets, with no extra or missing member. Any local change made after
  archiving would be lost, so it holds the workspace;
- the creation-time refusals still pass against the local tree: secret-like
  names, extended attributes, mount crossings, unsupported types, outbound Git
  history, and live process references and external dependents of both the
  local tree and the rule's original path. A linked worktree's `HEAD` must
  still equal the bundled `HEAD`;
- `local_retention` has elapsed since the manifest's `created_at`.

Then the entry carries a `workspace_archive` binding (manifest, manifest
SHA-256, member count, member-list digest, creation time), which participates
in the entry fingerprint, and the `policy.workspace_archive:NAME` rule proposes
`quarantine` at the explicit tier. Otherwise it proposes `keep`. Safety
refusals, protected and canonical locations, Git dirty/unpublished state, live
references, `report_only` roots and KEEP records still win.

Inventory scans compare file sizes and modification times. Mutation-time
recollection, both before the quarantine move and immediately before expiry
deletes the quarantined copy, re-reads and re-hashes the whole archive, the
history bundle and every local file, and requires every per-file SHA-256 to
match. A binding that cannot be re-established (archive corrupted, missing or
unmounted, manifest re-pinned or unpinned, rule removed, file changed inside
the quarantined copy) changes the fingerprint and refuses the move or the
expiry; `janitor restore` remains available. Ancestor directories of a
released workspace are protected so a broader rule cannot remove it wholesale.
Full verification runs inside `limits.command_timeout`; a timeout holds the
workspace. After expiry, recover with
[`archive --workspace NAME --restore-to`](recovery.md#workspace-archives).

### Workspace archive categories

`workspace_archive_categories` is empty by default. Each entry is an
owner-approved category whose matching items Janitor archives itself, with the
same copy-only, verified `janitor archive --workspace` machinery. The manifest
pins are not written to this policy. Janitor records them as immutable receipts
in its state database. Every active receipt becomes a pinned workspace archive
rule with local expiry enabled, so the collectors, `plan`, `apply --quarantine`
and `apply --expire` treat it exactly like a pinned `workspace_archives` rule.
Binding is full before the quarantine move and before expiry.

| Field | Contract |
| --- | --- |
| `name` | Unique; 1-48 letters, digits, `_` or `-`. Item archives are named `<name>-<base>-<hash12>` (hash of path and run). |
| `kind` | `merged_worktrees` (linked Git worktree), `pushed_clones` (standalone non-bare checkout) or `root_scratch` (no `.git` at the item root). One category per kind and root. |
| `roots` | Exact configured inventory roots. A root may not be `report_only`, inside `protect.paths`, or inside a `workspace_archive_keep` path. Only depth-1 entries are candidates. |
| `idle` | Minimum age of the newest modification anywhere in the tree, measured by a bounded deep walk. Use `Nd` or Go syntax. At least `14d` for `merged_worktrees` and `30d` otherwise (also the defaults). |
| `archive.directory`, `expect_mount_source`, `expect_fstype` | Same approval rules as `workspace_archives` destinations. The directory must also be outside every inventory root. |
| `local_retention` | `none`, `30d` (default) or `90d`, measured from archive creation. `none` proposes quarantine as soon as the verified archive binds the local tree. The quarantine retention (`retention.default`) still applies before deletion, and deletion still re-binds the quarantined copy. |
| `max_items_per_cycle` | Default 20, at most 200. Extra candidates are `deferred`, oldest first. |
| `max_bytes_per_item` | Default 10 GiB. Larger or unmeasured trees are refused. |

Categories require the Git, process and service collectors. A candidate must
be a directory directly inside a category root. It is refused by any of these:

- dot-named entries, raw runtime/credential stores and KEEP records
- overlap with `protect.paths`, explicit `workspace_archives` or
  `evidence_exports` rules, cache rules, `report_only` roots, other inventory
  roots, the quarantine directory, Gitmoot's managed state or an archive
  directory
- any blocking safety-engine protection: live process, registered agent,
  Gitmoot job, service reference, Git state, sensitive name, unknown evidence
  or durable evidence
- for Git kinds: dirty files, stashes, a Git lock, unmeasured publication,
  commits that are not on a remote-tracking branch, degraded metadata, or
  ignored contents that are unproven
- an unknown or partial deep size or newest mtime, or a size above the bound
- every archive-time refusal: secret-like names, mount crossings, external
  gitdir, alternates or symlink dependents, unsupported file types, and the
  destination mount expectations

A recorded path that is unchanged since archiving reports `already_archived`.
A path that changed after archiving fails Bind, so it is retained. It is
archived again, under a new name, only after it is idle again. A receipt loses
its expiry authority while any of these hold:

- its category is removed, or its kind, root or archive directory changes
- the policy now refuses its path
- the owner restored its quarantine with `janitor restore`

`janitor archive --categories` previews by default and writes nothing.
`--dry-run=false --confirm` creates the archives under the apply lock and
records a capacity activity per item. It re-reads the policy file before and
after each copy. `janitor cycle` runs the same step before its scan whenever
categories are configured, so `local_retention: none` items can be
auto-quarantined in that cycle. Item failures are reported in
`category_archives` and fail the cycle only after quarantine and expiry have
run. See [recovery](recovery.md#category-archive-items).
