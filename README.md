# workspace-janitor

Safe, Jev-assisted workspace hygiene for developer and AI-agent machines.

`janitor` inventories what is on a machine, applies deterministic safety
rules, and produces reversible cleanup plans. It is not an autonomous
deleter: nothing is mutated without an explicit, confirmed apply step, and
deletion is always preceded by quarantine.

## Status

This repository currently contains the **foundation** (issue #2): the command
tree, configuration and policy loading, the versioned domain contracts, the
local SQLite store, and the output contracts.

| Command | State |
| --- | --- |
| `janitor status` | implemented |
| `janitor policy check` | implemented |
| `janitor doctor` | implemented |
| `janitor version` | implemented |
| `janitor scan` | not implemented (issue #7) |
| `janitor plan` | not implemented (issue #4) |
| `janitor explain` | not implemented (issue #3) |
| `janitor apply` | not implemented (issue #5) |
| `janitor restore` | not implemented (issue #5) |

Commands that are not implemented exit with status `3` and say so. They never
report success they cannot deliver.

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
janitor --format json status   # deterministic machine-readable output
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

The state directory holds `janitor.db` and the quarantine directory. Both are
created with owner-only permissions. `janitor status` reports which source
each path came from.

If no home directory and no overrides are available, the run fails with
field-level errors rather than guessing a location.

## Policy

See [`docs/policy.example.yaml`](docs/policy.example.yaml) for a documented
example. Three rules govern loading:

- **Unknown fields are rejected.** A typo must fail loudly rather than
  silently disable a protection.
- **Omitted keys keep their default; written keys are used as written.** An
  explicit `max_batch: 0` fails validation instead of being corrected.
- **A broken policy file never falls back to defaults.** A missing file does.

Protections are additive: paths and name patterns in the document are added
to the built-in credential protections, never replace them.

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
internal/store       SQLite schema, migrations, and transactional persistence
internal/output      deterministic JSON and terminal rendering
internal/buildinfo   version and build metadata
```

Tests run against isolated fixture homes and never read the operator's real
configuration or state: path resolution takes an injected environment lookup,
and the CLI has no implicit fallback to the process environment.

## License

Apache 2.0. See [LICENSE](LICENSE).
