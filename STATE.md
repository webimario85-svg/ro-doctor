# RO Doctor — current checkpoint

## Goal
Standalone, public, reusable diagnostic CLI for rAthena and Ragnarok clients, with no code or assets stored on ValkiRO branches.

## M0 decisions
- Python 3.10+ standard library, installable with setuptools.
- Scan only explicitly selected directories, offline and read-only.
- Conservative interpretation: report declarations/filenames as evidence, never prove runtime compatibility.
- Reports: text, JSON v1, self-contained HTML; protect absolute paths and credentials.
- Synthetic, self-contained unittest fixtures. No GitHub Actions.

## M0 completed — 2026-11-21
- CLI, rAthena source/PACKETVER checks, mapcache heuristics.
- Client root, candidate executable, data.ini GRF load-order checks.
- Text, JSON v1 (docs/report.schema.json), and standalone HTML.
- 20 synthetic unit tests PASS on NoteNitro5; compileall PASS.
- JSON and HTML CLI smoke PASS; source fixtures and output kept in ignored .qa/.
- Wheel build PASS; install into isolated Python venv PASS; installed CLI smoke PASS.
- Local workspace: D:\ro-doctor. Remote: https://github.com/webimario85-svg/ro-doctor.
- Branch: main, initial M0 commit; read exact revision with git log -1.
- PR: none (initial repository bootstrap).
- No source or asset from ValkiRO copied or modified.

## Known limitations
- No executable version, effective compiled PACKETVER, or handshake verification.
- No MySQL/network access, binary execution, mapcache parsing, or GRF binary parsing.
- "Unusually large" mapcache threshold is a heuristic only.

## Next priority
M1: plugin-style detectors with stable fixtures based on real upstream bug classes, stronger data.ini/GRF checks, and independent client/server compatibility evidence; keep all operations offline/read-only.
