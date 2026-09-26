# Policy reference and isolated examples

Start with the [annotated policy](policy.example.yaml); run `janitor policy check` against the intended config. [Safety boundaries](threat-model.md) apply regardless of policy, and [recovery](recovery.md) covers mutations. This reference is for policy **version 1**.

## Resolution and validation

The policy defaults to `<config-dir>/policy.yaml`; `--policy` overrides `JANITOR_POLICY`. Config, state, and cache directory precedence is CLI flag, `JANITOR_*_DIR`, `XDG_*_HOME`, then the home-based default (see [README configuration](../README.md#configuration)). A missing policy uses built-in defaults; a present but unreadable, empty, malformed, multi-document, unknown-field, or invalid policy fails rather than falling back. The YAML is decoded over defaults: omitted keys retain defaults, while explicit zero/false/empty values are validated as written. Paths beginning `~` expand against the resolved home; absent home plus fully overridden directories requires an explicit root in a policy. Use `janitor status` to inspect resolved sources.

| Section | Meaning |
| --- | --- |
| `roots` | Discovery paths, `max_depth`, symlink and filesystem traversal, `report_only` (no mutations under that root). |
| `protect` | Additive protected paths and basename patterns; built-in credential names, Gitmoot home, state and effective quarantine remain protected. |
| `retention` | Default quarantine period (`none`, `7d`, `30d`, `90d`, `permanent`), quarantine directory, and separate deletion opt-in. |
| `prevention` | Deep-scan interval, disk alert thresholds/cooldown, and opt-in automatic quarantine and expiry; a policy never installs a timer. |
| `canonical_roots`, `classification`, `ownership`, `gitmoot` | Canonical project locations, literal project markers and name signals, foreign ownership checks, and read-only Gitmoot ledger location. |
| `caches` | Exact declared cache roots; `action` is `keep`, `quarantine`, `delete_candidate`, or `investigate`. Omitted action means `investigate`; TTL/size bounds need complete evidence for directories. Dedicated irreversible prune has further restrictions. |
| `jev` | Disabled by default; model, endpoint, key **environment variable name**, request bounds, thresholds, caching and redaction. See [privacy](privacy.md). |
| `collectors`, `limits`, `safety` | Explicit collector sources, bounded work/timeouts, and destination headroom. `allow_cross_filesystem_quarantine` does not enable a copy path: the Linux action engine still refuses cross-filesystem quarantine. |

Safety is a first-precedence veto. Protected paths/canonical roots precede explicit cache rules, then built-in classification and investigate fallback. Within a tier, safer action wins, independently of YAML order. No policy field waives a core protection or enables generic direct deletion. `follow_symlinks` changes discovery, not symlink-containment safety. `delete_candidate` needs an exact cache rule and, for official pruning, a dedicated owned/idle cache plus an approved action, configured absolute supported executable, and a distinct confirmed `apply --prune` call. `retention.delete_enabled` alone never expires an item; a confirmed expiry also needs elapsed retention and fresh complete checks.

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
