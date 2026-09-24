# Recovery and restore (Linux)

Quarantine is a same-filesystem rename, **not** a backup. Keep independent backups and retain the configured state directory (`janitor.db` plus quarantine manifests/objects) when diagnosing any failure. See [threat model](threat-model.md) and [policy reference](policy-reference.md). Commands below describe the workflow; do not run them against an unreviewed real workspace.

## Before a mutation

1. Inspect `janitor scan`, `janitor plan`, and `janitor explain /absolute/path`; examine unknown, Git, service/process and symlink evidence. Approve an individual action with `janitor plan --approve <action-id|path>` only after reviewing it. `--approve-all` is possible but broad.
2. Preview with `janitor apply --quarantine` (dry-run by default). Review source/destination, reclaim estimate, and any refused item. A changed scan, policy or target needs a fresh plan and approval.
3. Only an intentional mutation uses `janitor apply --quarantine --confirm --dry-run=false`. Record the **cleanup id** from its output. Cross-filesystem moves and `relocate` actions are refused; no copy fallback is used.

## Restore or resume

1. Stop writers to the affected path. Preserve the cleanup id, action id, CLI output and journal/quarantine contents. Check `janitor status` to locate the state directory; do not edit SQLite rows or move manifest files by hand.
2. Preview `janitor restore <cleanup-id>`. Inspect every item's status and original path. If it is safe to restore and the original is vacant, run `janitor restore --confirm <cleanup-id>`. Restore refuses an occupied original rather than overwriting it. A prepared receipt whose move never occurred can be cancelled by restore.
3. For an interrupted quarantine batch, repeating the same confirmed apply can reconcile receipts and continue. Prefer restoring already moved items if the original cleanup intent no longer holds. Per-item journal transitions mean one failure does not erase evidence of earlier successful moves. If source and destination both exist, identities disagree, a worktree link is broken, or the journal/manifest is missing or corrupt, **stop** and investigate from backups rather than forcing paths or deleting the object.
4. Re-scan and re-plan only after resolving the underlying refusal. A second janitor process cannot concurrently perform confirmed Linux apply/restore while the mutation lock is held; that lock does not stop external writers.

An `investigate` receipt is not a successful cleanup. For a failed path-swap
attempt where the original source is safely back in place and the destination
was never created, preview then confirm `janitor restore <cleanup-id>` to close
the prepared receipt. The store rejects a new active receipt for that source
until this is resolved. Only then scan, plan and approve again. Do not use
retry flags or manual database edits to bypass an unresolved receipt.

## Expiry and irreversible paths

Retention reaching its date alone never deletes an object. With `retention.delete_enabled: true`, `janitor apply --expire` previews eligible receipts; `janitor apply --expire --confirm --dry-run=false` separately requests deletion after fresh receipt, original-path, Git and live-reference checks. A changed or newly referenced item enters `investigate` and remains recoverable; address the evidence and re-run a separately confirmed evaluation, or restore it. Automatic expiry also requires `prevention.auto_expire: true` and an operator-installed timer; it uses the guarded path but is irreversible when it succeeds. Keep both switches off unless explicitly authorized.

Official provider `apply --prune` is a separate irreversible command. It does not create a quarantined copy; restore does not undo it. Do not treat a provider-reported success or a cleanup receipt as a backup. In a partial failure, preserve evidence, do not retry an irreversible provider call blindly, and reconcile the provider's actual state before any new approval.
