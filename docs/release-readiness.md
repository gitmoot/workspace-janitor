# Linux release-readiness checklist

This is a **preparation checklist**, not a release announcement or authorization. CI is intended to prepare `dist/janitor-linux-amd64` and `dist/SHA256SUMS` as an artifact; there is no GitHub release publication, deployment, live service, real provider call or credential use in this workflow. See [threat model](threat-model.md), [privacy](privacy.md), [recovery](recovery.md), and [contribution/security reporting](contributing-security.md).

## Evidence to record for the exact candidate commit

- [ ] Record source commit, Go toolchain/dependency versions and build commands. `make release-linux-amd64` uses `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`, read-only modules, trimmed paths, disabled VCS stamp and build ID, and commit-derived version/commit metadata (no wall-clock build date). Compare two builds and verify `dist/SHA256SUMS` against the binary.
- [ ] Verify ELF x86-64 architecture and absence of an ELF interpreter/shared-library dependencies; smoke-run that **artifact** with `--help` and `version`. Record the actual output and CI run link/status, not an assumed pass.
- [ ] Run format/vet/build and project tests for the candidate, including isolated fixture-home end-to-end scan, plan, approval, quarantine, restore and adverse cases (dirty worktrees, references, caches, backups, symlink attacks). No real HOME, Gitmoot ledger, repository, provider command or host cleanup should enter a fixture. Preserve observed results and any unresolved failures.
- [ ] Benchmark both metadata top-level and deep scans. Publish actual hardware, filesystem/storage, input item counts and sizes, collector configuration, cache state, command, duration distribution and I/O scope alongside the observed numbers. **No benchmark results are recorded here; performance remains unmeasured until that evidence is attached.**
- [ ] Review outbound `--jev-dry-run` projection with synthetic entries; ensure default policy makes no Jev request. Check recovery/restore, stale plan, concurrent writer, expiry and provider-prune safeguards against current code. Record limitations rather than converting an untested property into a claim.
- [ ] Obtain an independent review of the **exact head commit** and resolve its findings; archive its approval and the final CI/artifact/checksum evidence with the candidate PR.

**Owner approval hold:** preparing or uploading a CI artifact is not authorization to publish a release, deploy a binary/service/timer, invoke a live provider, enable Jev against a live endpoint, or use real credentials. Each remains held for explicit owner approval after the candidate evidence and exact-head review. Do not infer approval from a green CI job, an artifact download, or this checklist.
