# Linux release-readiness checklist

This is a **preparation checklist**, not a release announcement or authorization. CI is intended to prepare `dist/janitor-linux-amd64` and `dist/SHA256SUMS` as an artifact; there is no GitHub release publication, deployment, live service, real provider call or credential use in this workflow. See [threat model](threat-model.md), [privacy](privacy.md), [recovery](recovery.md), and [contribution/security reporting](contributing-security.md).

## Evidence to record for the exact candidate commit

- [ ] Record source commit, Go toolchain/dependency versions and build commands. CI tests GitHub's temporary PR merge ref, then checks out and verifies the **full submitted head** separately for the artifact; otherwise it would embed an ephemeral merge SHA. `make release-linux-amd64` uses `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`, read-only modules, trimmed paths, disabled VCS stamp/build ID, and commit-derived version metadata. Compare two builds; verify the manifest in both the local `dist/` and downloaded artifact root with `sha256sum -c SHA256SUMS`.
- [ ] Verify ELF x86-64 architecture and absence of an ELF interpreter/shared-library dependencies; smoke-run that **artifact** with `--help` and `version`. Record the actual output and CI run link/status, not an assumed pass.
- [ ] Run format/vet/build and project tests for the candidate, including isolated fixture-home end-to-end scan, plan, approval, quarantine, restore and adverse cases (dirty worktrees, references, caches, backups, symlink attacks). No real HOME, Gitmoot ledger, repository, provider command or host cleanup should enter a fixture. Preserve observed results and any unresolved failures.
- [ ] Benchmark both metadata top-level and deep scans. Publish actual hardware, filesystem/storage, input item counts and sizes, collector configuration, cache state, command, duration distribution and I/O scope alongside the observed numbers. A local candidate measurement follows; repeat against the final release candidate.
- [ ] Review outbound `--jev-dry-run` projection with synthetic entries; ensure default policy makes no Jev request. Check recovery/restore, stale plan, concurrent writer, expiry and provider-prune safeguards against current code. Record limitations rather than converting an untested property into a claim.
- [ ] Obtain an independent review of the **exact head commit** and resolve its findings; archive its approval and the final CI/artifact/checksum evidence with the candidate PR.

**Owner approval hold:** preparing or uploading a CI artifact is not authorization to publish a release, deploy a binary/service/timer, invoke a live provider, enable Jev against a live endpoint, or use real credentials. Each remains held for explicit owner approval after the candidate evidence and exact-head review. Do not infer approval from a green CI job, an artifact download, or this checklist.

## Local scan measurement (candidate `8de643aaf33e`)

Command: `go test ./internal/cli -run '^$' -bench '^BenchmarkScan(TopLevel|Deep)$' -benchtime=5x -count=3 -benchmem`. Go 1.25.0, Linux/amd64, AMD Ryzen 5 3600 (6 cores / 12 threads). The temporary benchmark directory reported an `ext2/ext3` filesystem type; the physical storage medium and cold-cache throughput were **not measured**.

The fixture has 64 top-level directories, 16 subdirectories per top-level directory, and four 16-byte files in each subdirectory: 1,024 nested directories, 4,096 files, 65,536 bytes of file contents. The top-level run has `max_depth: 1` and inspects the 64 immediate children. The deep run additionally traverses the descendants for size metadata. Both use the real `scan` command path with fixture HOME/policy, one warm-up before timing, output discarded, `--no-store --no-compare --no-git --no-processes --no-services`; the deep run adds `--deep-size`. Timings include policy parsing, traversal and safety classification, but exclude fixture creation, SQLite persistence, Git/process/service collectors, provider calls, network and file-content reads. Cache is warm but not pinned.

| Operation | Three samples, 5 scans each | Median | Median allocations / allocated bytes |
| --- | --- | --- | --- |
| Top-level | 2.198, 2.864, 3.662 ms/scan | 2.864 ms/scan | 5,324 allocations; 570 KB/scan |
| Deep size | 32.540, 31.514, 32.185 ms/scan | 32.185 ms/scan | 33,815 allocations; 2.68 MB/scan |

These are **local candidate** measurements, not a performance guarantee for real workspace trees, network filesystems or cold caches. No byte-level disk I/O counter or energy consumption was measured. Re-run and attach results at the exact release candidate before any owner-authorized publication.

## Offline privacy check

An isolated-home `janitor scan` followed by `janitor --format json plan --jev-dry-run` with a synthetic `mystery` directory, a loopback endpoint with no listener and **no provider key** exited successfully. The preview contained one root-relative `<root>/mystery` entry, four typed questions, `Authorization: Bearer [redacted]`, and zero requests, attempts, tokens and cost. This proves only the dry-run route did not invoke the provider for that fixture; a live outbound call remains untested and held for owner approval.
