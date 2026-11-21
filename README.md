# RO Doctor

Offline, read-only diagnostics for **rAthena servers** and **Ragnarok Online (Ragexe) clients**.

RO Doctor helps discover actionable configuration and asset problems without launching the game, contacting a database, or modifying the selected environment.

## M0 features

- Detects evidence of an rAthena source layout.
- Finds explicit PACKETVER declarations in selected source headers (does **not** claim effective build or runtime compatibility).
- Flags empty or unusually large map cache files; large size is a heuristic, not a corruption verdict.
- Detects candidate Ragexe/Ragnarok executables by filename only.
- Parses numbered GRF entries from data.ini [Data], including UTF-16 input.
- Detects missing or duplicate GRF references, with case-insensitive path checks.
- Exports deterministic text, JSON schema v1, and standalone HTML reports.
- Reports only relative file paths and selected directory names; never secret-bearing config contents.
- No network, game process, proprietary assets, or external Python dependencies.

## M1: extensible checks and compatibility evidence

The M1 release adds an explicit detector registry, non-invasive GRF header checks, data.ini load-order quality checks, sparse mapcache metadata, and partial ItemDB import advisories. It also adds untrusted date hints for PACKETVER comparisons and an **opt-in** SHA-256 + PE header fingerprint for Ragexe executables.

    rodoctor --list-checks
    rodoctor --server "D:\rathena" --client "D:\Ragnarok" --skip-check client-grf-header
    rodoctor --client "D:\Ragnarok" --only-check client-exe-fingerprint --format json --output report.json

Details: [checks and extension API](docs/checks.md) and [upstream regression evidence](docs/upstream-regressions.md).

Fingerprint hashes identify file content, **not** Ragexe version or protocol compatibility. The new ItemDB and mapcache checks only flag suspicious patterns and never assert observed runtime bugs. Reports do not include full configuration files, but can include relative names and hashes; review output before making it public.

## M2: binary mapcache checks and local compatibility evidence

M2 verifies actual mapcache binary layout (current 8-byte aligned or documented 6-byte legacy header), declared map count, record offsets and bounds. Opt-in deep verification checks zlib payloads with bounded decompression. It was tested on synthetic fixtures and a public upstream rAthena cache without committing any game data.

It also supports an optional local, reviewable evidence catalog keyed by exact client and server binary SHA-256 hashes. The catalog reports **claims** (pass, fail, unverified), never independently certifies a working login/packet protocol. No source URL is fetched and no executable runs.

    rodoctor --server "D:\rathena" --only-check server-mapcache-deep --format json
    rodoctor --client "D:\Ragnarok" --catalog "D:\reports\evidence.json" --server-build-sha256 YOUR_64_CHARACTER_SHA256 --only-check catalog-evidence

Full instructions: [M2 mapcache and evidence catalog](docs/m2-mapcache-and-catalog.md). Sample catalogs are intentionally empty; no guessed successful combinations are distributed.

## Install

Python 3.10+ required. From the repository root:

    python -m pip install -e .

## Run

    rodoctor --server "D:\path\to\rathena"
    rodoctor --client "D:\path\to\Ragnarok"
    rodoctor --server "D:\path\to\rathena" --client "D:\path\to\Ragnarok" --format html --output ".\report.html"
    rodoctor --client ".\my-client" --format json --output ".\report.json" --fail-on warning

Without installation:

    set PYTHONPATH=src
    python -m rodoctor --server "D:\path\to\rathena"

The output location must be outside directories being scanned.

## Exit codes

- 0: completed; no findings at configured failure threshold.
- 1: completed; errors (default) or warnings (when --fail-on warning).
- 2: invalid arguments or report-output failure.

## Test

    python -m unittest discover -s tests -v
    python -m compileall -q src

For running tests without installing, use PYTHONPATH=src or install the package first.

## Scope and accuracy

Static findings are intentionally conservative. An executable filename does not prove a compatible build, and a PACKETVER declaration does not prove what a compiled binary uses. Client/server handshake validation is reserved for future isolated test environments.

RO Doctor does not parse credential files, connect to MySQL, run binaries, patch executable files, or touch private assets. No ValkiRO code is included.

## Development

See AGENTS.md for repository rules and STATE.md for the single current checkpoint. Contributions should include synthetic regression fixtures and reproduce the failure before fixing it. The public issue tracker should not contain proprietary GRFs, executables, account data, or credentials.

MIT licensed. Independent community project; not affiliated with Gravity or rAthena maintainers.
