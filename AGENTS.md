# Repository rules

- RO Doctor is a standalone public tool. Never copy proprietary client binaries, GRFs, server credentials, or ValkiRO assets into this repository.
- Read-only by default. Do not launch executables, connect to databases, mutate game folders, or contact the network during scanning.
- Prefer explicit evidence over guessed compatibility. Mark uncertain checks as unknown/informational.
- Stdlib-first Python. Tests with synthetic fixtures before release.
- Before editing: inspect branch, status, worktrees, HEAD, and concurrent work. Never overwrite other worktrees.
- Keep durable progress only in STATE.md; do not duplicate checkpoints.
- QA: python -m unittest discover -s tests -v; python -m compileall -q src; CLI smoke test.
- Commit with narrow scope; use isolated feature branches for future substantial work.
