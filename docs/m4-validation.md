# M4 reproducible QA and safety matrix

M4 version: 0.5.0. Reproduce on a fresh checkout with Python 3.10+.

    python scripts/verify_release.py

This offline preflight performs: release version synchronization, JSON document parse, full unittest suite, in-memory source compilation (no pycache writes), and universal wheel build/structure in ignored .qa/release. Add --skip-wheel when pip/setuptools are unavailable or when the checkout is read-only.

The installed-wheel smoke is run separately on synthetic fixtures. Test log contents, path names, hashes, case JSON and mapcache inputs are intentionally fabricated for QA and must never be represented as successful Ragnarok client/server sessions.

## Actual tests executed November 21, 2026

| Environment | Execution | Outcome |
| --- | --- | --- |
| Windows 11 / Python 3.13.15 | 134 unit tests, source compilation, JSON parse, offline wheel build | PASS |
| Windows 11 / Python 3.13.15 isolated venv | Install ro_doctor-0.5.0 universal wheel; CLI match/mismatch log and custom map index smoke | PASS |
| WSL Ubuntu / Python 3.14.4 | 134 tests, JSON parse, in-memory compile; wheel intentionally skipped | PASS |
| Docker Alpine / Python 3.10.22 | --network none, read-only source filesystem; 134 tests, JSON and in-memory compile; wheel intentionally skipped in preflight | PASS |
| Docker Alpine / Python 3.10.22 | Install wheel into temporary filesystem without network; installed CLI case-log and custom map index smoke | PASS |

Fuzz regression test uses a fixed RNG seed to produce 250 synthetic mapcache byte strings from 0 to 255 bytes. It checks bounded parser behavior and SHA-256 non-mutation. This is not comprehensive fuzzing of every possible mapcache format.

## Trust boundaries

The map index provider is a user-specified relative .txt file inside the selected server root. Traversal, absolute or external paths are rejected. Up to 16 explicit providers may be supplied, and each file remains subject to the 2 MiB/65,536-line limits.

The optional case log is a user-supplied file outside the client/server roots, read in 1 MiB chunks with a 128 MiB cap. A hash mismatch prevents a reported pass/fail from being emitted. Matching bytes are not an independently verified handshake, signature or source attestation.

No client game processes were started. No private, copyrighted or real client assets were used. No GitHub Actions were configured. Previous worktrees and ValkiRO projects remain outside this tool's scope.

For a future independent Athena TestLab, see the [exchange contract](athena-testlab-contract.md).
