# workspace-janitor

Safe, Jev-assisted workspace hygiene for developer and AI-agent machines.

`janitor` inventories what is on a machine, applies deterministic safety
rules, and produces reversible cleanup plans. It is not an autonomous
deleter: generic deletion requires quarantine and a separate confirmed
expiry; a dedicated provider cache may instead use an explicitly approved,
confirmed official prune.

## Status

This repository implements inventory, safety, planning, the optional Jev
advisor, and reversible quarantine and restore. The local SQLite journal and
manifest retain a record of each move; deletion is separate and disabled by
default.

| Command | State |
| --- | --- |
| `janitor scan` | implemented (reports safety verdicts) |
| `janitor watch` | Linux top-level watcher; inventory and guidance only |
| `janitor cycle` | Linux daily one-shot metadata scan, weekly deep scan when due, disk alerts; expiry opt-in |
| `janitor service generate` | writes user service/timer files to an explicit directory; never installs them |
| `janitor status` | implemented |
| `janitor policy check` | implemented |
| `janitor doctor` | implemented |
| `janitor version` | implemented |
| `janitor plan` | implemented |
| `janitor explain` | implemented |
| `janitor apply --quarantine` | implemented (dry-run by default) |
| `janitor apply --prune --action <id>` | implemented for explicitly dedicated uv/npm caches (dry-run by default, Linux only) |
| `janitor apply --expire` | implemented (deletion disabled by default) |
| `janitor restore <cleanup-id>` | implemented (preview by default) |

## Inventory

`janitor scan` records what is on the machine and what is using it. It makes
no decisions and mutates nothing.

| Collector | What it reads | Bounds |
| --- | --- | --- |
| `filesystem` | `lstat` metadata for each root's children | per-root depth, per-directory entries, total entries |
| `deep_size` | recursive directory sizes, opt-in via `--deep-size` | entry budget, depth, stays on the filesystem |
| `git` | common dir, remote, branch, HEAD, dirty count, stashes, upstream, worktree metadata, locks | per-command timeout, read-only verbs only |
| `processes` | `cwd` and `exe` links plus `comm` from procfs | directory-entry bound |
| `agents` | registered-agent directories from an adapter | command timeout per adapter |
| `gitmoot` | read-only Gitmoot job, task, and cleanup-obligation ledger for exact paths | command timeout, entry bound; missing or uncertain state fails closed |
| `services` | systemd `WorkingDirectory`/`Exec*`, cron command paths, PM2 `pm_cwd`/`pm_exec_path` | per-file byte bound, per-directory entries |

Three properties hold across all of them:

- **Filesystem discovery is top-level and metadata-only by default.** No
  discovered directory is walked recursively unless `--deep-size` asks for it.
  Reference collectors may read local Gitmoot and service metadata.
- **Unknown state fails closed.** A collector that cannot observe something
  records `unknown:` evidence and, where the safety contract requires it, a
  blocking protection. A Git command that times out protects the path; it
  never reports the repository clean. An unlistable directory protects its
  parent. A symlink the policy may not resolve is ambiguous, so it is
  protected.
- **No secrets are read.** The process collector reads neither `cmdline` nor
  `environ`; the service collectors skip `Environment`, `EnvironmentFile`,
  and crontab assignments; and no Git command may touch the network — the
  collector runs a fixed allowlist of local read-only subcommands.

`--no-store` makes a scan reporting-only: it creates no database, and when
one already exists it is opened strictly read-only — no migration, no
permission change, no journal-mode change. A database this build cannot read
that way is reported in `prior_comparison` and the comparison is skipped
rather than upgraded silently.

Every reference collector is bounded by `limits.command_timeout` in wall
clock, enforced by the scan rather than by the collector's cooperation, so a
stalled filesystem or an adapter that ignores cancellation cannot hang a
scan; it becomes a partial report with an unknown.

## Safety

The safety engine is the only authority on whether a path may be mutated.
Classification, policy, and any model answer are inputs to planning; none of
them can clear a protection. `janitor scan` reports a typed verdict per
entry, and every refusal carries its evidence and the remedy that would
clear it.

| Guard | Refuses when |
| --- | --- |
| `collected_protections` | a collector observed an active process, registered agent, or service reference |
| `unknown_evidence` | any collector left an `unknown:` observation |
| `filesystem_identity` | device and inode are unknown, so nothing can be revalidated |
| `git_state` | dirty files, stashes, unpublished or unverifiable commits, broken metadata, or a lock |
| `symlink_containment` | a symlink is unresolved or resolves outside its root |
| `protected_paths` | the entry overlaps a protected path, the state directory, or the quarantine directory |
| `sensitive_names` | the name matches a protected pattern, without ever reading the value |
| `live_databases` | the file looks like a database that may have an open writer |
| `durable_evidence` | the entry is classified as durable evidence |
| `job_ownership` | a running, queued, or blocked job claims the path |
| `quarantine_filesystem` | the destination is on another filesystem with no copy policy, or cannot be inspected |
| `free_space` | a cross-filesystem copy would exceed the destination's headroom, or its size is unmeasured |

Space is only checked where it can be spent: a same-filesystem quarantine
is a rename and consumes none. A cross-filesystem copy needs a real size, so
a directory whose size was never measured — the default, since deep sizing
is opt-in — is refused rather than approved against its four-kilobyte
directory entry.

Four properties hold:

- **Deterministic and typed.** The same evidence always yields the same
  verdict, with protections in the same order, in JSON and in the terminal.
- **Fail closed.** Unknown, degraded, or unobserved state protects the path.
  Absence of a signal is never read as absence of risk.
- **Model output cannot weaken a protection.** A recommendation for a
  refused path is clamped to `investigate` with the refusal recorded in its
  reasons. Policy is the same: it can add protection, never remove it, and
  there is no switch that disables a core invariant.
- **Revalidated before mutation.** A verdict describes one moment. Apply
  must re-run every guard against a fresh observation immediately before
  mutating, and anything that changed since planning refuses outright.

### Why revalidation uses an open handle

Comparing paths and metadata is not enough to close the time-of-check to
time-of-use window. Measured on ext4 while building this engine: removing a
directory and recreating it under the same name reused the inode and
reported identical device, inode, and all three timestamps, so every
metadata comparison saw no change. A handle opened with `O_PATH` refers to
one kernel object and reports it as unlinked, which is how a replacement is
caught. Apply is expected to open the object, revalidate through the handle,
and mutate relative to it.

Each scan stores its inventory, the metadata fingerprint of every entry, and
a report per collector saying whether it ran, was partial, failed, or was
skipped. A later scan compares fingerprints with the previous one and marks
each entry unchanged, changed, or new.


## Build

```sh
make build        # dist/janitor, static, CGO_ENABLED=0
make check        # gofmt check, vet, build, test
```

The SQLite driver is pure Go (`modernc.org/sqlite`), so the binary is static
and needs no C toolchain.

## Usage

```sh
janitor --help
janitor doctor                 # create directories, open the store, report checks
janitor status                 # resolved paths, policy source, stored state
janitor policy check           # validate the policy, print the effective policy
janitor scan                   # inventory the configured roots
janitor scan /repos --deep-size    # one root, with bounded recursive sizes
janitor scan --no-git --no-processes --no-services   # filesystem metadata only
janitor --format json scan     # machine-readable inventory and collector reports
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | the command completed |
| `1` | the command ran and failed |
| `2` | the invocation or configuration was rejected before any work |
| `3` | the command exists in the contract but is not implemented in this build |

## Planning

`janitor plan` turns one scan into typed actions: `keep`, `relocate`,
`quarantine`, `investigate`, and — only where an operator wrote a rule
saying so — `delete_candidate`. The built-in policy never recommends a
direct deletion.

Provider adapters recognize selected uv, npm, pnpm, Bun, Gradle, Go,
Playwright, and Puppeteer cache roots, plus project-local virtualenvs,
dependencies, and derived outputs. Plans name the reinstall or rebuild cost.
Shared provider caches default to `investigate`; a mutating recommendation
needs an exact operator cache rule. `max_bytes` applies only above the stated
logical byte count; `ttl` requires the newest content to be old enough. Either
bound requires a complete `scan --deep-size` for directories. Unmeasured or
partial evidence is not treated as expired. Gitmoot-managed paths stay under
Gitmoot's cleanup ledger: even a final owner with a live obligation is only
reclaimable through Gitmoot, never by a generic janitor action.

Rules run in precedence order, and the first tier that has an opinion
decides:

| Tier | Source |
| --- | --- |
| `safety` | a refusal from the safety engine; nothing overrides it |
| `protected` | protected paths and canonical roots |
| `explicit` | rules the operator wrote, such as cache rules |
| `builtin` | the built-in classification defaults |
| `fallback` | investigate, when nothing else applied |

Within a tier, the **safer** action wins and the losing rule is reported as
a conflict. File order is never consulted: rules sort by tier, then
specificity, then name, so reordering a policy file cannot change a
decision.

A plan is bound to the scan, evidence digest, policy digest, advisor, and
well-formed advice considered (even if rejected), and is immutable once stored.
Re-planning unchanged inputs produces the same plan id and reuses the
stored plan; using a plan whose evidence or policy has changed is refused.
Approval is recorded beside the plan:

```sh
janitor plan                              # build and store a plan
janitor plan --approve <action-id|path>   # approve one mutating action
janitor plan --approve-all                # approve every mutating action
janitor explain /path/to/thing            # trace one decision
```

`explain` prints the winning rules and their reasons, the alternatives that
were rejected and why, the collected evidence, the safety verdict, and
whether the action is approved.

### Quarantine, restore, and expiry

`apply` requires a stored plan with individually approved mutating actions.
It checks the latest scan and policy binding, then recollects each target and
reruns the safety guards immediately before moving it. Approved overlapping
paths are refused as a batch. A destination on another filesystem is always
refused in this version; there is no copy-and-delete fallback.
Filesystem mutation currently runs on Linux; other platform builds refuse
the action because their no-replace and anchored-delete primitives are not
implemented.
An approved `relocate` action is refused rather than silently sent to
quarantine; relocation is not part of this command.

```sh
janitor apply --quarantine                         # preview approved moves
janitor apply --quarantine --confirm --dry-run=false
janitor restore <cleanup-id>                       # preview recovery
janitor restore --confirm <cleanup-id>             # refuse occupied originals
janitor apply --expire                             # inspect retained receipts
```

The cleanup id appears in apply output. Each action has a manifest beside its
quarantined object and a durable SQLite transition journal. A stopped batch
can resume by repeating the confirmed apply, or restore each completed move
with the cleanup id. Linked worktrees move through Git so its administrative
links remain valid. Renames preserve item permissions, timestamps, and symlink
identity; no destination or restored source is overwritten.
A prepared receipt that never moved can be cancelled with the same restore
command, releasing its source for a new plan.

### Official provider pruning

An approved `delete_candidate` for an exact, dedicated cache may use
`janitor apply --prune --action <id>` instead of generic quarantine. This
irreversible operation is limited to the configured absolute `uv` or `npm`
binary on Linux. Set `dedicated: true` and `official_binary` only when the
cache is exclusively owned and idle. Preview is the default; confirmed
execution requires `--confirm --dry-run=false`, prints the exact argv before
execution, takes a lock, journals the attempt and outcome, and enforces
`limits.command_timeout` on the provider process group. The provider receives
offline settings and no inherited credential environment (not a network
isolation boundary); janitor does not infer ownership from a cache-shaped
path. Other provider commands are guidance only.

Quarantine dry-runs show an expected physical reclaim estimate where it can
be measured. Sparse holes, external hardlinks, and nested selected roots do
not count as independently reclaimable bytes; unavailable estimates are
reported as unavailable, not zero.

Expiry is not deletion. To explicitly enable it, set
`retention.delete_enabled: true`, wait for the item's retention period, then
run `janitor apply --expire --confirm --dry-run=false` as a **separate**
invocation. It rechecks the quarantined object, original source, live
references, Git state, and recorded fingerprint before anchored deletion.
Changed or newly referenced items enter `investigate`; they are not deleted.
Once the blocking evidence is resolved, a separately confirmed expiry retries
the full safety evaluation before returning an `investigate` item to quarantine
and considering deletion. It can also be restored while under investigation.

### Prevention without autonomous cleanup

`janitor watch` monitors only the immediate children of configured roots. It
coalesces create, rename, and delete events into bounded whole-root inventory
scans; no event directly moves or deletes anything. A newly discovered review
clone gets canonical-location guidance, not relocation. Newly created
directories are revisited after two seconds so a clone whose `.git` metadata
arrives after its directory can receive guidance. Startup and inotify overflow
trigger full reconciliation; partial collector results remain unknown rather
than proving a deletion. Event-triggered scans are metadata-only and never
advance the deep-scan clock.

`janitor cycle` is a one-shot timer target: each invocation records a metadata
scan, or a deep scan if `prevention.deep_interval` has elapsed since the last
successful scheduled deep scan (default seven days). `collectors.deep_size`
controls ad-hoc `scan`, not the scheduled `cycle`: a due cycle explicitly runs
deep-size collection even when that collector is false in policy. To avoid
scheduled deep scans, do not install the timer; use `janitor scan --no-deep-size`
for metadata-only inventory. `prevention.min_free_bytes`
or `prevention.min_free_percent` triggers a per-filesystem alert. It reports
potential physical bytes by reclaimable, protected, and unknown class; a
bounded or uncertain estimate is **unmeasured**, not zero. Alerts are
deduplicated per filesystem by a durable SQLite cooldown, default 24 hours.
Only configured inventory roots are measured.

Automatic expiry is **off** by default. To opt in, set both
`retention.delete_enabled: true` and `prevention.auto_expire: true`. The cycle
then calls the same confirmed `apply --expire` path as an operator: process
lock, fresh reference collection, original-path and receipt checks, and
anchored deletion. It reports each expiry outcome; an expired timestamp alone
is not permission. All confirmed apply and restore operations share one
cross-process lock on Linux; a second process fails closed instead of racing.
On other platforms confirmed apply remains unsupported, while confirmed
restore retains its prior behavior without this Linux-only lock.

`janitor service generate --output /absolute/private/directory --binary
/absolute/janitor` writes three units without installing or enabling them:
`janitor-watch.service`, `janitor-cycle.service`, and
`janitor-cycle.timer` (`OnCalendar=daily`). Review the generated paths and
policy before installing them yourself. Both generated services clear
`OPENROUTER_API_KEY` and request `IPAddressDeny=any`; watch and cycle never
call the model. The service restriction is an OS-level network boundary when
systemd enforces it; direct manual invocations do not acquire that sandbox.

### Jev advice

Rules-only planning is the default and is complete on its own. With
`jev.enabled: true` and an OpenRouter key in the environment variable
named by `jev.api_key_env` (`OPENROUTER_API_KEY` by default), `plan`
offers entries the rules left **ambiguous** — and only those, after
every rule has run — to pinned Jev `typesafe/jev-1.13` through
`https://openrouter.ai/api/v1/systemone`. The direct TypeSafe endpoint
is rejected. A missing key is not an error: the plan is built from rules
alone and says so. The CLI reads process environment; it does not load
dotenv files itself. Supply only the named variable to a future live
process through the host's secure environment mechanism.

What is sent is an allowlisted projection, never the entry itself: a
`<root>/`-relative path with configured, protected, and secret-looking
segments redacted; kind, depth, a size bucket, and age in days; Git counts
and booleans; evidence signal names; and protection kinds. Remotes,
branches, commit ids, evidence details, symlink targets, owners, and
absolute paths are never sent.

Each entry gets four typed questions: its class, an action, a retention,
and the probability that moving it would lose work. The action options are
only `keep`, `quarantine`, and `investigate`. A missing, malformed, or
low-confidence answer, or one judged unsafe, becomes `investigate`. Every
answer then goes through the safety engine and is applied only if it is
safer than the rules' decision; a rejected proposal is recorded in the
trace.

```sh
janitor plan --jev-dry-run   # print the exact requests; send and store nothing
janitor plan --jev-debug     # also print the requests that were sent
janitor plan --no-jev        # rules only for this run
```

Requests are batched within `max_batch` and `max_state_tokens` and
under a conservative 28k-token total estimate for Jev's 32k context.
They are paced by `min_interval`, bounded by `timeout`, and retried up
to `max_retries` times on 429, 529, 5xx, and transport errors, honoring
`Retry-After`. Redirects are refused; a rejected key or request is not
retried. After `breaker_failures` consecutive failures the run stops
calling the model and plans the rest from rules.
Well-formed answers are cached by entry fingerprint, request schema,
model, and policy for `cache_ttl`, so re-planning unchanged entries sends
nothing; malformed answers are retried on the next plan.

Usage is recorded for every answered request, even with `--no-store`.
`plan` shows the run's tokens and estimated cost, and `status` shows the
totals. Cost is an estimate: reported input tokens times
`price_per_mtok_usd`.

## Configuration

Locations follow the XDG base directory specification, and each one can be
overridden explicitly:

| Path | Default | Overrides, highest first |
| --- | --- | --- |
| config dir | `$XDG_CONFIG_HOME/workspace-janitor` or `~/.config/workspace-janitor` | `--config-dir`, `JANITOR_CONFIG_DIR`, `XDG_CONFIG_HOME` |
| state dir | `$XDG_STATE_HOME/workspace-janitor` or `~/.local/state/workspace-janitor` | `--state-dir`, `JANITOR_STATE_DIR`, `XDG_STATE_HOME` |
| cache dir | `$XDG_CACHE_HOME/workspace-janitor` or `~/.cache/workspace-janitor` | `--cache-dir`, `JANITOR_CACHE_DIR`, `XDG_CACHE_HOME` |
| policy file | `<config dir>/policy.yaml` | `--policy`, `JANITOR_POLICY` |

The state directory holds `janitor.db` and the quarantine directory. All of
them, including the quarantine directory, are created by `janitor doctor`
with owner-only permissions. `janitor status` reports which source each path
came from.

If no home directory and no overrides are available, the run fails with
field-level errors rather than guessing a location.

A run with **every** path overridden needs no home directory, but the
built-in defaults derive their single discovery root from the home
directory. Such a run therefore requires a policy file that declares at
least one root; without one it fails and says so.

## Policy

See [`docs/policy.example.yaml`](docs/policy.example.yaml) for a documented
example. Three rules govern loading:

- **Unknown fields are rejected.** A typo must fail loudly rather than
  silently disable a protection.
- **Omitted keys keep their default; written keys are used as written.** An
  explicit `max_batch: 0` fails validation instead of being corrected.
- **A broken policy file never falls back to defaults.** A missing file does.

Protections are additive: paths and name patterns in the document are added
to the built-in credential protections, never replace them. The state
directory and the effective quarantine directory are always protected,
wherever `retention.quarantine_dir` puts the latter.

## Output contracts

Every JSON document is wrapped in a versioned envelope and is byte-stable for
identical input:

```json
{
  "schema_version": 1,
  "kind": "status",
  "data": { }
}
```

`schema_version` is the domain contract version, which also governs persisted
records. The database carries its own schema version, migrated forward on
open. `janitor version` prints the build, contract, and schema versions.

## Development

```
cmd/janitor          entrypoint
internal/cli         command tree, global flags, exit codes
internal/config      XDG path resolution and strict YAML policy loading
internal/core        versioned domain types: entries, evidence, protections,
                     recommendations, scans, plans, actions, retention, usage
internal/collect     bounded, fail-closed collectors and fingerprints
internal/safety      deterministic protections, remediation, and apply-time
                     revalidation
internal/store       SQLite schema, migrations, and transactional persistence
internal/output      deterministic JSON and terminal rendering
internal/buildinfo   version and build metadata
```

Tests run against isolated fixture homes and never read the operator's real
configuration, state, process table, or service definitions: path resolution
takes an injected environment lookup, the CLI has no implicit fallback to the
process environment, and every collector location — procfs root, systemd
directories, cron paths, PM2 dumps, and the `git` binary itself — is an
explicit option a test points at a fixture.

## License

Apache 2.0. See [LICENSE](LICENSE).
