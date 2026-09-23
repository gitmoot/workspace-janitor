# Privacy and outbound Jev advice

No telemetry is sent by default. With `jev.enabled: false` (the default), planning runs from local rules without provider credentials or network calls to Jev; `watch` and `cycle` do not call the model. Local scans, plans, receipts, and optional model usage accounting live in the configured state directory. See [policy reference](policy-reference.md) for configuration and [threat model](threat-model.md) for trust limits.

When an operator explicitly enables Jev, `plan` sends only **ambiguous** entries after deterministic rules. The policy names an environment variable (`OPENROUTER_API_KEY` by default), not a key value. Hosted requests go to `https://openrouter.ai/api/v1/systemone` with model `typesafe/jev-1.13`; a loopback HTTP endpoint is permitted for isolated testing. The key is sent as a bearer header to the configured endpoint. No dotenv file is loaded by the CLI. Missing credentials leave rules-only planning in place. Direct manual `plan` calls are not given the network sandbox of generated systemd services.

The following is a **synthetic illustration** of the JSON request shape, not a captured request, real workspace name, secret, or copy-paste payload. The actual request has four fully specified questions per entry (class, action, risk, retention), not ellipses; use `janitor plan --jev-dry-run` in an isolated fixture for the exact bytes without sending or storing a request.

```json
{
  "model": "typesafe/jev-1.13",
  "state": {
    "task": "Classify workspace directories on a developer machine for a cleanup tool. Each entry is sanitized metadata only: no file contents are available. Answers are advisory; a deterministic safety engine makes every final decision.",
    "entries": [{
      "ref": "entry-1", "path": "<root>/[redacted]/scratch-cache",
      "name": "scratch-cache", "kind": "directory", "depth": 2,
      "size": "under_1MiB", "size_measured": false, "modified_days_ago": 14,
      "signals": [], "protections": []
    }]
  },
  "questions": {
    "entry-1_action": {
      "type": "choice",
      "instructions": {
        "entry": "entry-1",
        "question": "What should a cautious cleanup tool do with the item in `entries` whose `ref` equals `entry`?"
      },
      "criteria": {
        "keep": "Leave it where it is; it is in use or worth keeping",
        "quarantine": "Move it aside reversibly; it looks regenerable or abandoned",
        "investigate": "A human should look before anything happens"
      }
    }
  }
}
```

Only a root-relative path and name (with configured/protected/secret-looking segments redacted), kind, depth, size bucket, whether size was measured, age in days, Git counts/booleans if present, signal names, and protection kinds can appear in the entry projection. Absolute paths, file contents, evidence detail, symlink targets, owner IDs, Git remotes, branches and commits are omitted. Redaction is heuristic: **ordinary path segments, counts and ages can still identify private work**. Inspect dry-run output locally and do not post it publicly. `--jev-debug` prints sent requests; protect terminal history/logs and avoid debug on sensitive trees. `--no-jev` forces rules-only for one plan. Model advice cannot approve a refused mutation; invalid, low-confidence, or unsafe answers become `investigate`.

After an answered request, local usage is recorded even with `--no-store`; `plan` reports run token/cost estimates and `status` aggregates them. These are not independent billing guarantees. The remote provider's handling of intentionally sent data is outside janitor's control; consult its current terms before enabling it. For incident response, disable Jev, inspect the exact dry-run projection in an isolated environment, rotate any key suspected of exposure, and preserve local state for investigation.
