# Repository rules

- RO Doctor is a standalone public tool. Never copy proprietary client binaries, GRFs, server credentials, or ValkiRO assets into this repository.
- Read-only by default. Do not launch executables, connect to databases, mutate game folders, or contact the network during scanning.
- Prefer explicit evidence over guessed compatibility. Mark uncertain checks as unknown/informational.
- Stdlib-first Python. Tests with synthetic fixtures before release.
- M1/M2 checks live in an explicit registry. Never auto-load third-party Python packages during scans. Binary hashing, deep decompression and compatibility catalogs require explicit opt-in.
- Treat mapcache, map_index, catalogs and test-case artifacts as untrusted: enforce strict byte/record/output limits; do not execute assets, fetch URLs or claim runtime compatibility from reports or hashes.
- Prefer scripts/verify_release.py for offline release QA (no GitHub Actions, no game binaries). Keep generated logs under ignored .qa/.
- M4: explicitly supplied case logs may be SHA-256 checked in bounded streaming reads; matching bytes are never interpreted as proof of game execution. Never echo raw log contents or absolute paths in reports.
- Explicit custom map-index providers must be relative .txt paths resolved inside the selected server root; never auto-discover outside paths.
- Before editing: inspect branch, status, worktrees, HEAD, and concurrent work. Never overwrite other worktrees.
- Keep durable progress only in STATE.md; do not duplicate checkpoints.
- QA: python -m unittest discover -s tests -v; python -m compileall -q src; CLI smoke test.
- Commit with narrow scope; use isolated feature branches for future substantial work.
