# RO Doctor — current checkpoint

## Goal and guardrails
Standalone public rAthena/Ragexe diagnostics. Remote: https://github.com/webimario85-svg/ro-doctor . Never put its code or proprietary assets in ValkiRO branches. Scans and fixtures are offline, bounded, read-only; no executable launch, DB connection, automatic plugin import, URL fetch or GitHub Actions.

## Completed releases
- M0 (v0.1.0): original CLI, conservative static checks, text/JSON v1/HTML.
- M1 (v0.2.0): 8 explicit detectors, ItemDB/import and sparse mapcache advisories (#10098/#10099), GRF header/load order, Ragexe optional fingerprints. PR #1 merged (9670702b5b8fe4aff55b2fb1b622399b234c9681). Main checkpoint before M2: cb5a2eae8c9a05c773f4d1892601f64c3404614b.

## M2 — 2026-11-21
Worktree: D:\ro-doctor-m2, branch feat/m2-cache-catalog, based on main cb5a2eae8c9a. Existing worktrees D:\ro-doctor (main) and D:\ro-doctor-m1 (merged M1 branch) kept untouched. Actual feature/merge SHAs and PR number: check current Git, PR and release tag rather than guessing the commit SHA in its own contents.

Implemented:
- 11 explicitly registered checks: 8 default, 3 opt-in. New server-mapcache-structure (default), server-mapcache-deep (opt-in), catalog-evidence (opt-in via --catalog).
- Actual binary mapcache bounds: 8-byte C++ aligned header and documented 6-byte historical fallback, 20-byte map entry; file size, declared count, entry boundaries, dimensions and duplicate map names. Deep zlib check bounds compressed and decompressed byte counts, never writes data.
- Verified against public rAthena master db/re/map_cache.dat: 28,232 bytes, 8 maps, SHA-256 e871cb73bae86d4be6e32d35ed34cc0456920203f3ffa4687bdba8eedaf627fd. All eight maps' compressed payloads validated. Public reference file is ONLY in ignored .qa, not Git.
- Local SHA-256 compatibility evidence catalog v1 with explicit client binary hash and user-supplied deployed server binary hash, reported pass/fail/unverified statuses, ISO observation date, test method and HTTPS source (not fetched). Ambiguous clients and conflicting reports flagged, never certified as verified protocol compatibility.
- New CLI --catalog, --server-build-sha256 and --client-exe; new mapcache docs, empty catalog example, JSON catalog schema, security notes, version 0.3.0. Machine-readable diagnostic report schema remains v1.
- All new tests are synthetic: no proprietary GRFs, server binaries or ValkiRO files committed.

## M2 actual QA
- Windows NoteNitro5 Python 3.13.15: 76/76 unit tests PASS, compileall PASS, schema JSON parse PASS, universal wheel build PASS.
- Windows isolated venv: pip install of v0.3.0 wheel PASS. CLI JSON/HTML, real upstream mapcache deep zlib, opt-in catalog (unverified result) and SHA-256 read-only fixture integrity PASS.
- WSL Ubuntu Python 3.14.4: 76/76 unit tests PASS, compileall PASS, 11 checks enumerated. WSL did not have pip; do not claim pip-based install in WSL.
- Docker python:3.13-alpine, network disabled, read-only filesystem/repository: 76/76 tests PASS; universal wheel zipimport version 0.3.0 and 8-map deep-zlib smoke PASS.
- VPS alta-dev SSH was unreachable (connection timeout); Linux tests were performed locally via WSL and Docker instead.
- Complete QA logs, wheel and reference fixture in ignored .qa/; no GitHub Actions.

## Remaining limitations
- Catalog records are self-reported, source URLs are not checked and user-provided server SHA is not attested. A hash match alone is not a successful handshake.
- Mapcache parser handles 8-byte and 6-byte layouts only; supports at most 8192 maps, 512 MiB file, 8 MiB uncompressed cells per entry and 16 MiB compressed payload for deep verification.
- No full GRF decoding, no authenticated client/server protocol tests, no automated cache repairs or binary patching.
- Minimum declared supported Python is 3.10; real QA covered Windows 3.13 and Linux 3.13/3.14, not Python 3.10.

## Next priority — M3
1. Improve provenance and test-case interoperability for recorded compatibility, without claiming verified support until a real authorized test passes.
2. Cross-check mapcache names against map index with bounded parser and avoid false positives for custom maps.
3. Add Linux wheel-install smoke where pip is available and release automation through trusted local executors (no GitHub Actions).
4. Continue from this checkpoint plus current branch/worktree/PR and upstream state; do not replay prior milestones or overwrite parallel work.
