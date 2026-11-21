# M1–M2: checks and extension API

RO Doctor operates only on directories passed to --server and/or --client. Built-in detectors are registered explicitly, with a documented target and a stable check ID.

## Discover and select

    rodoctor --list-checks
    rodoctor --server "D:\rathena" --client "D:\Ragnarok" --skip-check client-grf-header
    rodoctor --client "D:\Ragnarok" --only-check client-load-order
    rodoctor --client "D:\Ragnarok" --only-check client-exe-fingerprint --format json --output report.json

Check IDs can be repeated. Unknown IDs terminate with exit 2. The CLI does not auto-import or execute third-party code. The on-demand client-exe-fingerprint check reads and SHA-256 hashes up to 200 MiB per candidate Ragexe/Ragnarok-named EXE, with optional PE header metadata. It does **not** execute the file, and an EXE hash alone cannot prove compatibility.

## Built-in checks

| Check ID | Scope | Default | What it can and cannot prove |
| --- | --- | --- | --- |
| server-static | server | yes | Layout and source declarations; not runtime health |
| server-itemdb | server | yes | Potential partial ItemDB overrides; not an observed price regression |
| server-sparse-cache | server | yes | Sparse allocation metadata; not certain cache corruption |
| server-mapcache-structure | server | yes | Actual bounded mapcache structure/count validation; no game execution |
| server-mapcache-deep | server | no | Bounded zlib map payload validation; not an in-game test |
| client-static | client | yes | data.ini GRF references, executable filenames and root files |
| client-grf-header | client | yes | Standard GRF signature and minimum header length; not archive integrity |
| client-load-order | client | yes | Duplicate/gapped numeric data.ini indices; gaps are not always errors |
| client-exe-fingerprint | client | no | SHA-256 and optional PE linker metadata; never client release proof |
| protocol-evidence | combined | yes | Untrusted filename date hints vs source PACKETVER declarations; not a packet handshake |
| catalog-evidence | client | no (yes if --catalog) | Locally supplied exact client/server SHA-256 pair and reported status, never certification |

M2 format details and the optional catalog schema: [mapcache & compatibility evidence](m2-mapcache-and-catalog.md).

## Embedding custom checks

The registry is an explicit Python API, not automatic plugin discovery:

    from rodoctor.checks import Check
    from rodoctor.scan import build_registry, scan

    registry = build_registry()
    registry.register(Check(
        id="my-safe-check",
        target="client",
        description="My local read-only evidence check",
        run=lambda server, client, report: report.add(
            "MY_SAFE_CHECK", "info", "client", "Checked.", "Review locally."
        ),
        default=False,
    ))
    result = scan(client="./client", registry=registry, only=["my-safe-check"])

run(server, client, report) receives absolute Path roots or None and a report object. Public extensions must be explicitly loaded by the embedding application. Do not execute game assets, use the network, or expose credentials; catch unrecoverable problems as CHECK_EXECUTION_FAILED without leaking exception text. The core cannot guarantee the behavior of third-party code that a caller explicitly imports.

## Machine-readable reports

JSON maintains report schema version 1; see report.schema.json. Check IDs are stable, findings have stable code values, and new codes may be added in minor versions. The report is deterministic for unchanged inputs and no scan timestamps are injected.

## Safety and limits

- No executable patching, launch, database connections, or network during checks.
- Only source files in a fixed allowlist are inspected for PACKETVER declarations.
- YAML inspection is deliberately narrow, bounded and not a general parser.
- data.ini paths are checked against traversal and symlink escape.
- Root GRF headers are examined without expanding archive contents.
- Reports may contain relative asset names, client file basenames, content hashes, and directory basenames. Review output before sharing publicly.
