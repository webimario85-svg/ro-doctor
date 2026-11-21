# RO Doctor — current checkpoint

## Goal and guardrails
Public, independent read-only diagnostics for rAthena/Ragexe. Repo: https://github.com/webimario85-svg/ro-doctor .
Never copy private server files, executables or ValkiRO assets into this repository. No GitHub Actions, no automatic game execution, network fetch during scans, DB writes, binary patches or invented protocol compatibility claims. Keep one current checkpoint in this file, and concise rules in AGENTS.md.

## Release history
- M0 v0.1.0: conservative offline client/server checks; reports text/JSON v1/HTML.
- M1 v0.2.0, merged PR #1: explicit detectors, ItemDB/mapcache advisories, GRF checks and optional EXE fingerprint.
- M2 v0.3.0, merged PR #2: bounded binary mapcache parsing, opt-in zlib validation and local SHA-256 compatibility evidence. Previous main checkpoint d1bb4b13682274b5c57ae57ab080fc279d0130b0.

## M3 delivered — 2026-11-21
- Feature branch feat/m3-mapindex-provenance in D:\ro-doctor-m3; base main d1bb4b13682274b5c57ae57ab080fc279d0130b0. Feature commit 75c878e647e5f833260d8e4793d424e5190f1714. PR #3 https://github.com/webimario85-svg/ro-doctor/pull/3 merged via squash to main fb2ea43a7a5e0aef03e277055b3ae78ea753f902. Main worktree D:\ro-doctor. Older worktrees retained untouched; resume new work on a new branch, not the merged M3 worktree.
- Post-merge main Windows release preflight: PASS (version sync, JSON documents, 109 unit tests, compileall, offline universal wheel and structure), 14 detectors listed. Release tag v0.4.0; check current main and release tag with Git, since the checkpoint's own commit follows the text.
- 14 registered detectors total. New default server-map-index compares cached names with local db/map_index.txt, db/import/map_index.txt and root map_index.txt. Parses bounded maps/indexes and treats custom, truncated and missing names conservatively as INFO only. It never requires all indexed maps to be in the cache.
- New optional case-evidence detector and --case-file: portable JSON Schema v1 for external QA records, with case/scenario/runner, exact client and server build SHA-256, reported pass/fail/unverified, date, log SHA-256 and HTTPS provenance text. A log digest is mandatory for reported pass/fail but is never independently verified. The tool never certifies protocol compatibility.
- New optional catalog-provenance detector audits local catalog SHA-256, duplicates, conflicting outcomes and future dates. Case versus catalog contradictions are flagged for the exact binary pair.
- Offline scripts/verify_release.py checks version sync, JSON documents, unit tests, compileall and a universal wheel build/structure when pip is available. No tag, commit, release or other Git mutations by the script.
- Docs: docs/m3-map-index-provenance.md; docs/test-case.schema.json and synthetic unverified example; updated README/AGENTS/SECURITY/checks.
- Version 0.4.0; report JSON schema remains v1. No new external runtime dependencies.

## Actual M3 QA
- Windows NoteNitro5 / Python 3.13.15: 109/109 unittest PASS, compileall PASS, schema JSON parse PASS, offline wheel build & structure PASS; isolated venv wheel installation and installed CLI PASS.
- Windows smoke: public upstream map_cache.dat (28232 bytes, 8 maps) versus public db/map_index.txt (13341 bytes); all 8 cache names matched, no warning/error; synthetic case CLI reported CASE_UNVERIFIED, input binary SHA-256 unchanged.
- WSL Ubuntu / Python 3.14.4: 109/109 tests and offline preflight (wheel skipped because pip unavailable) PASS.
- Docker python:3.13-alpine with --network none, read-only repo/root and tempfs: 109/109 unit tests PASS, actual wheel install into ephemeral /tmp PASS, installed CLI comparison against public upstream files PASS.
- Upstream public mapcache and index copied only into ignored .qa/ for local QA, not Git; all test suite fixtures synthetic. All QA stdout/logs and build wheel kept under ignored .qa/.
- VPS was unreachable during M2; M3 Linux QA did not require it. No changes to ValkiRO.

## Important limits
- Map index paths are explicitly recognized local files, not a discovery of arbitrary custom map servers; cached-only names are informational.
- Neither a catalog SHA nor a test-case log hash establishes authorship or real execution. Source URL contents are never fetched. Users must perform authorized isolated handshake tests independently.
- Real QA versions: Windows 3.13, Linux 3.13 and 3.14. Python 3.10 remains declared supported but untested in this session.
- No automatic mapcache remediation, GRF extraction, client patching, or server instrumentation.

## Next priority — M4
1. Reproducible evidence exchange between Athena TestLab and RO Doctor, with independently verifiable local log checksum when explicitly supplied.
2. Inter-server index policy and custom map configuration providers, informed by upstream rAthena behavior; avoid false positive errors.
3. Larger adversarial corpus, fuzz/property tests and Python 3.10 compatibility with isolated local executors.
4. Resume from STATE.md plus real Git/worktrees/PR and last QA; do not replay or overwrite parallel branches.
