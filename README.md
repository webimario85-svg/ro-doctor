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

M0 does not parse credential files, connect to MySQL, run binaries, patch executable files, or touch private assets. No ValkiRO code is included.

## Development

See AGENTS.md for repository rules and STATE.md for the single current checkpoint. Contributions should include synthetic regression fixtures and reproduce the failure before fixing it. The public issue tracker should not contain proprietary GRFs, executables, account data, or credentials.

MIT licensed. Independent community project; not affiliated with Gravity or rAthena maintainers.
