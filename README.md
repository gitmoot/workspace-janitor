# workspace-janitor

Safe, Jev-assisted workspace hygiene for developer and AI-agent machines.

`janitor` inventories what is on a machine, applies deterministic safety
rules, and produces reversible cleanup plans. It is not an autonomous
deleter: nothing is mutated without an explicit, confirmed apply step, and
deletion is always preceded by quarantine.

## Status

This repository contains the **foundation** (issue #2) and the **inventory
collectors** (issue #6): the command tree, configuration and policy loading,
the versioned domain contracts, the local SQLite store, the output
contracts, and a bounded, fail-closed `scan`.

| Command | State |
| --- | --- |
| `janitor scan` | implemented |
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
