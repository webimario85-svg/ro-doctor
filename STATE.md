# RO Doctor — current checkpoint

## Project
Standalone, public, reusable diagnostic CLI for rAthena and Ragnarok Online clients. Repository: https://github.com/webimario85-svg/ro-doctor . Never copy code, binaries or assets into ValkiRO branches.

## Baseline
M0 released as v0.1.0, commit d2f2c5ef82cb. Original local checkout D:\ro-doctor on main.

## M1 — completed 2026-11-21
- Independent feature worktree D:\ro-doctor-m1, branch feat/m1-detector-registry, based on d2f2c5ef82cb.
- New Check/Registry API, eight explicitly registered checks: seven default and one on-demand (EXE SHA-256/PE fingerprint).
- CLI --list-checks, --only-check and --skip-check. Custom checks require explicit in-process registration, never automatic loading of third-party code.
- Conservative ItemDB partial import advisories (rAthena #10098); sparse mapcache metadata (rAthena #10099).
- GRF signature/minimum header, bounded load-order duplicate/gap checks and non-authoritative client/server date evidence.
- Optional SHA-256 fingerprint for Ragexe-named executables, with 200 MiB limit and PE linker metadata; not a version assertion.
- Docs: docs/checks.md, docs/upstream-regressions.md, README, SECURITY and AGENTS.md.
- Package version: 0.2.0. JSON report schema remains v1.
- QA PASS on NoteNitro5 Windows/Python 3.13: 44/44 unit tests; compileall; CLI JSON and HTML smoke; opt-in fingerprint smoke; wheel build; isolated venv install and CLI; 8 listed detectors; scanned fixtures unchanged by SHA-256.
- QA logs and synthetic smoke inputs are local ignored .qa/ only. No GH Actions and no dependency on external services.
- No changes to ValkiRO.
- PR and merge revision: consult current GitHub PR for feat/m1-detector-registry and git log -1 (the checkpoint must not predict its own SHA).

## Known limitations
- No runtime handshake or proven effective PACKETVER; filename dates and PE timestamps are not proof of client version.
- Partial ItemDB parser is intentionally limited (max 256 KiB read); some valid YAML forms are not inspected, and warnings are not runtime price proofs.
- Sparse attributes and logical size cannot alone prove cache corruption; no binary map-count parser.
- GRF header checks do not decode contents or prove archive integrity. No custom executable names handled by fingerprint check.
- No real proprietary client assets or real server binary execution were used in the M1 test matrix.

## Next priority — M2
Improve bounded safe parsing and version evidence with documented fixture corpus, actual mapcache header count validation against format, optional SHA-256 compatibility catalog with provenance and explicit test status, and cross-platform packaging QA. Do not auto-update files or use unverified compatibility claims.
