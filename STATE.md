# RO Doctor — single current checkpoint

## Project and rules
Public, standalone rAthena/Ragexe diagnostic tool: https://github.com/webimario85-svg/ro-doctor .
Do not mix with ValkiRO source or branches. No copyrighted assets, secret configs, automatic client execution, DB access, game patching, or GitHub Actions. Scans are offline/read-only; release preflight only writes generated wheel into ignored .qa/ when explicitly requested. See AGENTS.md for concise developer rules.

## Prior releases
- M0 v0.1.0: offline diagnostics, JSON v1, text/HTML.
- M1 v0.2.0, PR #1: detector registry, ItemDB/GRF checks and Ragexe fingerprints.
- M2 v0.3.0, PR #2: bounded binary mapcache parsing, deep zlib check, local compatibility catalog.
- M3 v0.4.0, PR #3: map-index correlation, external QA case schema, provenance auditing. Last known main before M4: 114ecbbd7830135f37a36f732de9e5b43be06f2c.

## M4 completed — 2026-11-21
- Branch: feat/m4-evidence-log-and-map-index, worktree: D:\ro-doctor-m4, based on 114ecbbd7830135f37a36f732de9e5b43be06f2c.
- The original main is D:\ro-doctor. The older M1/M2/M3 worktrees were left untouched. Confirm the merged PR, tag and current main HEAD with Git rather than storing speculative SHAs in the feature commit.
- Version 0.5.0, 14 registered detectors unchanged, diagnostic JSON schema v1 unchanged, no extra install dependencies.
- --case-log adds explicit bounded SHA-256 verification of a local sanitized QA log against a case manifest. This reads at most 128 MiB in 1 MiB chunks, avoids reporting user paths/log contents, and does not touch scanned directories. A missing/invalid/mismatched checksum suppresses the case's reported pass/fail; a matching checksum only confirms byte identity, not actual test execution or protocol support.
- --map-index accepts up to 16 extra relative .txt providers resolved within --server. Rejects traversal, absolute paths, missing or out-of-root files. Adds names to standard index paths and preserves all M3 custom-map informational semantics.
- Athena TestLab interoperability: docs/athena-testlab-contract.md provides ready-to-implement file exchange with the M3 case schema and local log verification. No Athena TestLab binary or live integration was installed/tested; independent runner execution is outside M4.
- Deterministic adversarial tests: 250 seeded random mapcache byte strings (0-255 bytes), invalid provider paths, nonstring case statuses and log tampering. Input hashes checked for mutation.
- Offline release preflight now compiles Python source in memory without writing pycache to a read-only worktree. Scripts: scripts/verify_release.py; docs: docs/m4-validation.md and updated SECURITY, AGENTS, README and M3 reference notes.

## Actual M4 QA
- Windows 11 NoteNitro5 / Python 3.13.15: 134/134 unittest PASS; in-memory compile (19 files), JSON parse, offline universal wheel build and structure PASS.
- Windows isolated venv / Python 3.13.15: pip install v0.5.0 universal wheel and installed CLI PASS; matching and tampered case logs and custom map-index smoke PASS. Input hashes unchanged.
- WSL Ubuntu / Python 3.14.4: 134/134 tests and offline in-memory preflight PASS (wheel intentionally skipped, no pip).
- Docker python:3.10-alpine / Python 3.10.22: 134/134 tests and preflight PASS with --network none and read-only source; installed wheel into ephemeral filesystem PASS; installed CLI case-log and custom index smoke PASS.
- An initial Python 3.10 preflight run failed due to compileall writing pycache to a read-only filesystem; script was corrected and final runs passed. This was a release preflight QA issue, not a diagnostic failure.
- All QA inputs, logs, wheel files and fixtures are in ignored .qa/; no real game client was launched.

## Remaining limitations
- A matching SHA-256 digest is not evidence of a real game connection, trusted runner, authorship or authenticity. The server hash is provided by the operator, and test-case source URLs are not fetched.
- Mapindex providers must be explicitly listed under the server root; no arbitrary external locations, no client patching or mapcache repair.
- The deterministic random-input corpus is bounded regression fuzzing, not comprehensive coverage.

## Next priority — M5
- Establish a separate Athena TestLab repository and runner with actual, authorized isolated execution, status observations and sanitized log generation; do not falsely claim existing live integration.
- Add test-case bundle verification/signature or provenance trust with independently verifiable local logs and clear runtime test evidence.
- Evaluate richer map-index/mapcache consistency contracts against upstream rAthena while keeping custom content warnings informational.
- Resume with Git state, current branch/worktrees, PR and this single checkpoint. No replay or parallel overwrite.
