# Recovery and restore (Linux)

Quarantine is a same-filesystem rename, **not** a backup. Keep independent backups and retain the configured state directory (`janitor.db` plus quarantine manifests/objects) when diagnosing any failure. See [threat model](threat-model.md) and [policy reference](policy-reference.md). Commands below describe the workflow; do not run them against an unreviewed real workspace.

## Before a mutation

1. Inspect `janitor scan`, `janitor plan`, and `janitor explain /absolute/path`; examine unknown, Git, service/process and symlink evidence. Approve an individual action with `janitor plan --approve <action-id|path>` only after reviewing it. `--approve-all` is possible but broad.
2. Preview with `janitor apply --quarantine` (dry-run by default). Review source/destination, reclaim estimate, and any refused item. A changed scan, policy or target needs a fresh plan and approval.
3. Only an intentional mutation uses `janitor apply --quarantine --confirm --dry-run=false`. Record the **cleanup id** from its output. Cross-filesystem moves and `relocate` actions are refused; no copy fallback is used.

## Restore or resume

1. Stop writers to the affected path. Preserve the cleanup id, action id, CLI output and journal/quarantine contents. Check `janitor status` to locate the state directory; do not edit SQLite rows or move manifest files by hand.
2. Preview `janitor restore <cleanup-id>`. Inspect every item's status and original path. If it is safe to restore and the original is vacant, run `janitor restore --confirm <cleanup-id>`. Restore refuses an occupied original rather than overwriting it. A prepared receipt whose move never occurred can be cancelled by restore.
3. For an interrupted quarantine batch, repeating the same confirmed apply can reconcile receipts and continue. Prefer restoring already moved items if the original cleanup intent no longer holds. Per-item journal transitions mean one failure does not erase evidence of earlier successful moves. The scheduled cycle repeats unsettled session artifact batches by itself: their prepared receipts are reconciled on the next run. It does not repeat an earlier cycle's plan, and once a newer scan exists that plan's apply is refused, so a prepared receipt of a plan quarantine stays until `janitor restore --confirm <cleanup-id>` resolves it. If source and destination both exist, identities disagree, a worktree link is broken, or the journal/manifest is missing or corrupt, **stop** and investigate from backups rather than forcing paths or deleting the object.
4. Re-scan and re-plan only after resolving the underlying refusal. A second janitor process cannot concurrently perform confirmed Linux apply/restore while the mutation lock is held; that lock does not stop external writers.

An `investigate` receipt is not a successful cleanup. For a failed path-swap
attempt where the original source is safely back in place and the destination
was never created, preview then confirm `janitor restore <cleanup-id>` to close
the prepared receipt. The store rejects a new active receipt for that source
until this is resolved. Only then scan, plan and approve again. Do not use
retry flags or manual database edits to bypass an unresolved receipt.

A quarantine whose workspace archive verification ran out of
`limits.archive_verify_timeout` needs none of this: nothing moved, so its
prepared receipt is closed as `restored` ("left in place: archive
verification deferred …") and the next cycle verifies and moves the item
again. Repeating the same confirmed apply also retries it, under a fresh
cleanup id, and replays the rest of its batch. An expiry deferred the same
way leaves its receipt `quarantined`.

## Expiry and irreversible paths

Retention reaching its date alone never deletes an object. With `retention.delete_enabled: true`, `janitor apply --expire` previews eligible receipts; `janitor apply --expire --confirm --dry-run=false` separately requests deletion after fresh receipt, original-path, Git and live-reference checks. A changed or newly referenced item enters `investigate` and remains recoverable; address the evidence and re-run a separately confirmed evaluation, or restore it. Automatic expiry also requires `prevention.auto_expire: true` and an operator-installed timer; it uses the guarded path but is irreversible when it succeeds. `prevention.auto_quarantine: true` additionally lets that timer approve and move rule-based quarantine actions without an operator; restore them with `janitor restore <cleanup-id>` before their retention expires. Keep these switches off unless explicitly authorized.

If the original path holds an object again at expiry (an archive restore, a
copy made outside Janitor), expiry compares it with the quarantined copy.
They are identical when the trees have the same shape and entry names, and
every entry has the same type, permission bits, owner and group, every
symlink the same target, and every regular file the same size and bytes.
Modification times, extended attributes and ACLs are not compared; symlinks
are never followed, mounts never crossed, and a tree with more than
`limits.deep_size_max_entries` entries is not compared. An identical original
makes the copy redundant: expiry removes only the copy, never touching the
original, and records the receipt `superseded_by_original` rather than
`deleted`. References to and protections of the original path do not hold the
copy, since nothing happens there, but every guard on the copy itself still
applies (open descriptors, processes, Git state, protected names, mounts and
its identity, apart from a workspace archive binding that the restore
withdrew). A workspace archive rule still configured for the original path
does not bind the copy; instead its live-process and external-dependent
checks run against the copy's own names (a category rule through its shared
dependent index, bounded by `limits.dependent_index_max_entries`, as when it
binds), so a process using only the original does not hold the copy, while
one using the copy, or one that cannot be inspected, does. Just before
removal both trees must still show, for every entry,
the inode, change time and size the comparison saw. A unit with a bound
companion is never superseded. Any other original (changed bytes, a symlink or
file where a directory was, an unreadable entry, a tree changed meanwhile)
gets the usual original-path checks, so a referenced one is still refused. A
copy removed before its receipt was updated is recorded from its removal
marker on the next expiry. A `superseded_by_original` receipt, like
`restored`, withdraws a category archive's local-expiry authority for that
path. Superseded items do not fail `janitor cycle`; any other expiry refusal
still does.

An `identity_changed` refusal after upgrading can also mean that an older
receipt used a different fingerprint format; it is not proof of replacement.
Janitor recognizes the pre-Git-activity format only when the saved digest
matches its immutable snapshot and that snapshot includes a known Git activity
baseline. It compares that saved snapshot with fresh evidence under the current
algorithm, without changing historical receipts. Unknown formats or incomplete
legacy evidence still refuse; so do changed identity, activity, content and
live protections. Never copy current metadata into an old receipt to make it pass.

A refusal always lists each blocking protection with its reason, because one
kind covers several checks: `identity_changed` can be the path, the device
and inode, the planned action's identity, the open handle, or the metadata
fingerprint. A fingerprint refusal names every input that differs (for
example `changed: size 0 -> 58473656, latest_modified absent -> ...`). While
a receipt stays `prepared`, `janitor explain <path>` shows the check that
currently refuses its move.

Use `janitor apply --expire --cleanup <cleanup-id>` to preview one cleanup
batch. This scope includes every item in that batch; expiry does not support
`--action`. Review the whole batch before separately approving execution.
Deploying an expiry fix with automatic expiry already enabled can retry eligible
items at the next scheduled cycle, even without a manual command. Keep any
explicit retry hold in force when planning that deployment.

Official provider `apply --prune` is a separate irreversible command. It does not create a quarantined copy; restore does not undo it. Do not treat a provider-reported success or a cleanup receipt as a backup. In a partial failure, preserve evidence, do not retry an irreversible provider call blindly, and reconcile the provider's actual state before any new approval.

## Verified export archives

This workflow requires an owner-approved exact `evidence_exports` rule and an
existing independently retained destination. It does not provision storage,
approve a live path, disable protections or archive credentials. Raw session
trees/databases and credential-bearing checkouts are not export inputs.

1. Keep `local_expiry_enabled: false`. Check the policy and preview
   `janitor archive --rule NAME`. Creation defaults to dry-run.
2. Run `janitor archive --rule NAME --dry-run=false --confirm`. Success means
   the new compressed bundle was actually restored and its hash, size, mode,
   UID/GID and nanosecond modification time verified. The source is untouched.
   Preserve the returned manifest path and SHA-256 outside the disposable
   source container; pin them as `archive.manifest`/`archive.manifest_sha256`.
3. Run `janitor archive --rule NAME --verify`. To recover independently, preview
   `janitor archive --rule NAME --restore-to /approved/new/file`, then add
   `--dry-run=false --confirm`. The destination must be vacant. Recovery needs
   the approved rule, manifest and payload, not the original source container
   or Janitor's old database. A changed archive-root identity blocks local
   expiry but does not prevent hash-verified recovery into a new file.
4. Only with the owner's separate local-removal permission, set
   `local_expiry_enabled: true`. Re-scan, plan and approve the exact export's
   quarantine action after its configured completion window (30 days by default).
   Use the ordinary quarantine/expiry workflow above; its grace period and deletion gates remain.
   Corrupt/unavailable archives, changed sources, live/queued users and revoked
   rules preserve the local copy.

Archives never expire through this feature. An interrupted creation may leave
an unpublished `.partial-export-*` bundle for diagnosis; it grants no deletion
permission. Retain the source and inspect the failure rather than treating a
partial bundle as a backup. No archive rule or destination is enabled by the
shipped example policy.

## Workspace archives

Workspace archives are opt-in and copy-only; see
[the policy contract](policy-reference.md#workspace-archives). They never
delete the source, and removing the local copy still goes through the ordinary
quarantine/expiry workflow above. A released workspace under a rule is held
until [local expiry](policy-reference.md#workspace-archive-local-expiry) is
enabled, its retention has elapsed since archive creation, and the pinned
archive exactly matches the local tree.

1. Add the `workspace_archives` rule with an empty manifest, check the policy
   and preview `janitor archive --workspace NAME`. The preview runs every
   refusal check and writes nothing.
2. Run `janitor archive --workspace NAME --dry-run=false --confirm`. Success
   means `<name>.tar` (and `<name>.bundle` for a linked worktree) was read
   back and matched the stream hash, member list and per-file contents. Pin the
   returned manifest path and SHA-256 as `archive.manifest` and
   `archive.manifest_sha256`.
3. Run `janitor archive --workspace NAME --verify` at any time; it re-reads
   every archived byte and the bundle without needing the source.
4. To recover, preview `janitor archive --workspace NAME --restore-to
   /new/path`, then add `--dry-run=false --confirm`. The destination must not
   exist and must not be inside or contain the original workspace path; the
   original path itself is a valid destination once it is gone. The tree is
   extracted into a private staging directory beside the destination, renamed
   into place without replacement, and walked again to confirm every member,
   mode, owner, mtime, link target and content hash. A restore that fails
   before publication leaves nothing; one that fails verification after
   publication says so and leaves the tree for inspection.
5. A linked worktree's restored `.git` file still points at its original admin
   entry. If that entry is gone, recover the history with
   `git -C <main repository> fetch <archive>/<name>.bundle HEAD` or
   `git clone <archive>/<name>.bundle <dir>`.
6. To let expiry remove the local copy, keep the pin and set
   `local_expiry_enabled: true` (and optionally `local_retention: 90d`). Scan
   and plan: once the retention has elapsed and the tree still matches, the
   workspace is proposed for quarantine; approve and `apply --quarantine` as
   usual. Until expiry, `janitor restore <cleanup-id>` moves the quarantined
   copy back. `apply --expire` re-hashes the archive, bundle and quarantined
   tree immediately before deleting; any mismatch refuses expiry (the receipt
   goes to investigation) and `janitor restore` still works.
7. After expiry, the original path is gone and the archive is the copy:
   `janitor archive --workspace NAME --restore-to <original path> --dry-run=false
   --confirm` restores it in place. Do not remove or re-pin the archive before
   then; the archive directory's `protect.paths` entry keeps Janitor from
   touching it.

Without Janitor, the same tar extracts with
`tar -C /new/path --numeric-owner -xpf <archive>/<name>.tar`; compare against
the manifest before relying on it. An interrupted creation may leave an
unpublished `.partial-workspace-*` directory, or published outputs without a
manifest. Neither is a verified archive. A rerun never reuses them: it refuses
while any `<name>.*` output exists, so inspect and remove those first.

### Category archive items

Items Janitor archived for a
[workspace archive category](policy-reference.md#workspace-archive-categories)
use the same archive format and the same quarantine/expiry receipts; their
manifest pins live in Janitor's state (`category_archives` table), not in the
policy.

- `janitor archive --categories` previews candidates, sizes, idle ages and every
  refusal; `--dry-run=false --confirm` creates the archives. The daily
  `janitor cycle` runs the same step before it scans whenever categories are
  configured.
- Until expiry, `janitor restore <cleanup-id>` moves a quarantined item back
  (the 3-day quarantine undo on this host). That restore is the owner's undo:
  the item's archive loses local expiry authority, so it is not quarantined
  again; it is archived anew only after it changes and is idle again.
- After expiry, `janitor archive --restore-category-item <original path>
  --restore-to <original path>` previews and, with `--dry-run=false --confirm`,
  restores the newest archive of that path. `--verify` re-reads it without
  restoring. `janitor archive --workspace <synthesized name> --verify` or
  `--restore-to` also works while the item's archive is active; the name is in
  the category report and the cycle report. A confirmed restore first records
  an immutable withdrawal of that archive's expiry authority, so the restored
  tree is never quarantined or expired again on that archive; it is archived
  anew only after it changes and is idle again.
- An `omp_sessions` unit is the session directory plus its `<session>.jsonl`
  transcript, and every step above handles both: `janitor restore` moves the
  quarantined `item` and `item.jsonl` back to `<session>` and
  `<session>.jsonl` (it refuses if either original name is occupied), and
  `--restore-category-item <session dir> --restore-to <session dir>` restores
  the directory and writes the transcript beside it as `<dest>.jsonl`. A
  `gitmoot_job_logs` unit is a single file restored to its original name.
  Both use the unit tar layout, whose member names are the original base
  names, so a manual restore is
  `tar -C <original parent> --numeric-owner -xpf <archive>/<name>.tar`.
- An `omp_session_artifacts` batch is one session folder's archived files.
  Its quarantine journals every moved file as its own item under the batch's
  cleanup id (shown as `quarantine receipt` in the category report and as
  `cleanup_id` in the `apply --quarantine --artifacts` report), each in
  `<quarantine>/<cleanup-id>/file-NNNNN/item`. `janitor restore --confirm
  <cleanup-id>` moves the whole batch back; `janitor restore --confirm
  <cleanup-id> <original path> ...` moves back only those files. A restored,
  unchanged file is never batched again; it is archived anew only after it
  changes and is idle again. After expiry, restore from the batch tar, whose
  member names are paths relative to the sessions root:
  `tar -C <sessions root> --numeric-owner -xpf <archive>/<name>.tar
  <project>/<session>/<file>` (omit the member to restore the batch). The
  tar keeps each file's mtime, so a file restored this way is not batched
  again either.

## Scratch cleanup

Each acting [scratch cleanup](policy-reference.md#scratch-cleanup) run that
archived anything leaves `scratch-<run>.tar` and `scratch-<run>.manifest.json`
in the configured archive directory. Run and deletion receipts are in
Janitor's state (`scratch_runs`, `scratch_deletions`). A run receipt pins its
manifest by path and SHA-256; the manifest names every archived entry, and
`scratch_deletions` has one row per deleted entry. The run id is shown in
the `janitor scratch` and `janitor cycle` reports. Regenerable entries were
deleted without an archive and cannot be restored.

- `janitor scratch restore <run> <entry>` reads the run's receipt, checks
  that its pinned manifest (SHA-256 verified) names the entry, re-reads the
  whole archive and verifies it without writing anything. Janitor's state is
  only read; a database from before the scratch receipts holds no runs and
  is not migrated.
- `janitor scratch restore <run> <entry> --dry-run=false --confirm` restores
  the entry to its original path under the apply/restore lock. `--restore-to PATH` restores it elsewhere.
  The destination must not exist; nothing is ever overwritten. The entry is
  extracted into a private staging directory next to the destination. Every
  file is checked against its manifest SHA-256 and the restored tree is
  re-walked and compared, and only then is the entry renamed into place.
- Without Janitor, the tar is a plain POSIX tar whose members start with the
  entry name: `tar -xf scratch-<run>.tar -C /tmp <entry>`. Compare the files
  with the manifest checksums yourself.

An interrupted run may leave a `.partial-scratch-*` staging directory, or a
published tar without its manifest. Neither is a verified archive, and nothing
was deleted on its account. Remove them after inspection.
