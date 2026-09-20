# workspace-janitor

Safe, Jev-assisted workspace hygiene for developer and AI-agent machines.

`janitor` inventories what is on a machine, applies deterministic safety
rules, and produces reversible cleanup plans. It is not an autonomous
deleter: nothing is mutated without an explicit, confirmed apply step, and
deletion is always preceded by quarantine.

## Status

This repository contains the **foundation** (issue #2), the **inventory
collectors** (issue #6), and the **safety engine** (issue #3): the command
tree, configuration and policy loading, the versioned domain contracts, the
local SQLite store, the output contracts, a bounded fail-closed `scan`, and
the deterministic protections that decide whether a path may ever be
mutated.

| Command | State |
| --- | --- |
| `janitor scan` | implemented (reports safety verdicts) |
| `janitor status` | implemented |
| `janitor policy check` | implemented |
| `janitor doctor` | implemented |
| `janitor version` | implemented |
| `janitor plan` | not implemented (issue #7) |
| `janitor explain` | not implemented (issue #7) |
| `janitor apply` | not implemented (issue #4) |
| `janitor restore` | not implemented (issue #4) |

Commands that are not implemented exit with status `3` and say so. They never
report success they cannot deliver.

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
| `services` | systemd `WorkingDirectory`/`Exec*`, cron command paths, PM2 `pm_cwd`/`pm_exec_path` | per-file byte bound, per-directory entries |

Three properties hold across all of them:

- **A default scan is top-level and metadata-only.** No file contents are
  read and no directory is walked recursively unless `--deep-size` asks for
  it.
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
