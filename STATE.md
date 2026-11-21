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
- Branch: feat/m4-evidence-log-and-map-index, worktree: D:\ro-doctor-m4, based on 114ecbbd7830135f37a36f732de9e5b43be06f2c. Feature commit: 5d905d7727fe3647ee0d8767f2f6d99a6b5cf34f.
- PR #4: https://github.com/webimario85-svg/ro-doctor/pull/4 (merged); squash merge to main: a2e590e83459f975980fd4465d2076af4ac9b1bb. The original main is D:\ro-doctor, older M1/M2/M3 worktrees left untouched.
- Post-merge main QA confirmed Windows 134/134 tests and offline v0.5.0 release preflight PASS, 14 detectors listed. Release tag: v0.5.0 (verify current Git tag and HEAD; checkpoint text predates its own commit).
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

## Linked standalone Athena TestLab — M5 completed 2026-11-21
- New independent public repository: https://github.com/webimario85-svg/athena-testlab ; tag v0.1.0; commit 7c55a04d24bdc862addb58b4d1b9f3574830b26b. Separate codebase, package, AGENTS.md and STATE.md; never copied into RO Doctor or ValkiRO branches.
- Athena TestLab implements real, explicitly authorized loopback TCP and process-exit tests with sanitized, hashed local logs. No Ragnarok protocol handshake implementation yet.
- Independently installed Athena TestLab v0.1.0 and RO Doctor v0.5.0 wheels: Windows Python 3.13 and offline Linux Python 3.10 cross-tool evidence exchange PASS. Synthetic localhost TCP bytes produced a case v1; RO Doctor independently returned CASE_LOG_SHA256_MATCH and CASE_REPORTED_PASS strictly for tcp-exchange. This is not a game login.
- Separately, Athena TestLab executed upstream rAthena login-server, char-server, map-server --run-once in a disposable DB/container lab: 3/3 PASS. Docker image and hash, SQL import, and accurate limitations are recorded in the TestLab docs/real-rathena-qa.md. No client Ragexe participated; no protocol compatibility claim. Temporary DB was removed, ValkiRO containers unchanged.
- RO Doctor JSON output and source code are unchanged. This M5 update is documentation/checkpoint only; v0.5.0 remains the RO Doctor code release.

## Next priority — M6
- Implement an independently verified rAthena packet/login test adapter in Athena TestLab, with safe isolated credentials and explicit client/version behavior. Do not equate a TCP-open test with real gameplay.
- Decide how to verify provenance signatures and runner identity without misrepresenting self-reported SHA-256 log checksums.
- Keep RO Doctor compatibility schema stable until a separately designed v2 contract is justified. Cross-project integration should use published packages only.
- Continue from this checkpoint, the standalone Athena TestLab STATE.md, and real Git/worktree/PR state; never overwrite parallel work.
