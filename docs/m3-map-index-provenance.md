# M3: map index correlation and portable test evidence

All checks are read-only, bounded and offline. Source URLs are recorded as text; RO Doctor never follows them. Report schema stays at version 1.

## Map index correlation

Upstream rAthena map index: https://github.com/rathena/rathena/blob/master/db/map_index.txt

The map_index.txt file describes inter-server map IDs. Valid entries are bare map names, optionally followed by a numeric ID. The original header says IDs must not change. It is not a manifest of every map that must be present in a particular mapcache.

Default server-map-index checks local db/map_index.txt, db/import/map_index.txt and root map_index.txt when they exist, alongside standard map_cache.dat locations. It first runs the bounded M2 binary structure parser; malformed caches are skipped, not compared.

Name matches are case-insensitive. Twelve-byte cached names without a NUL terminator can be truncated by the C++ producer. If such a cache name only shares a prefix with an indexed longer name, the detector labels it ambiguous, not a confirmed match. It does not modify map index files, assign IDs, read proprietary assets, or require that every indexed map is cached.

A map in cache but not in the checked indexes is an informational MAP_INDEX_CACHE_ONLY_NAMES, not a failure: it may be a custom map or use a map index not present at one of those local paths. Missing index or cache files are not reported as errors. No filenames or map IDs are emitted in this advisory.

Checks also report informational repeated names and incompletely parsed index lines without leaking file contents. Each index file is bounded at 2 MiB and 65,536 lines.

### Real upstream verification

On 2026-11-21, RO Doctor compared a public rAthena mapcache (28,232 bytes, 8 maps, described in the M2 guide) with public db/map_index.txt (13,341 bytes). All eight cache names matched. The upstream cache and map index were held in ignored .qa/ only; neither is distributed in the source repository.

## Portable test-run evidence

The case-evidence detector consumes a local JSON artifact produced by any independent authorized test runner. See [JSON Schema v1](test-case.schema.json) and [synthetic example](test-case.example.json).

Required fields:
- case_id, scenario, runner: bounded identifiers identifying the test, scenario and producer.
- client_sha256, server_build_sha256: exact bytes of the client EXE and deployed server build, not date guesses.
- status: reported pass, fail or unverified. A pass/fail report requires an external log SHA-256 digest; an unverified report may have null log digest.
- observed_at: local ISO date; future-dated reports are flagged.
- log_sha256: SHA-256 of a test log provided by the reporter. RO Doctor does not access the log and does not validate it against actual test execution.
- source_url: HTTPS evidence reference, never fetched or authenticated.

Example in PowerShell (use the SHA-256 of the actual deployed server binary, which RO Doctor does not independently attest):

    (Get-FileHash C:\rathena\map-server.exe -Algorithm SHA256).Hash
    rodoctor --client C:\Ragnarok --server-build-sha256 ACTUAL_SERVER_HASH --case-file C:\reports\case.json --only-check case-evidence --format json

The case artifact must be outside the scanned client/server directories. If a catalog is also supplied, M3 compares statuses for the exact binary pair and warns when they disagree. A matching case is reported evidence, not proof of a completed connection. Real client/server handshake testing remains for separately authorized test environments.

No automation in RO Doctor creates, fakes or signs reports of passed tests. A future Athena TestLab can emit this format when it has real, verified execution logs.

## Catalog provenance audits

When --catalog is provided, catalog-provenance runs by default. It reports the local catalog's SHA-256 (revision tracking), a count of self-reported pass/fail/unverified claims, possible duplicate claim combinations, conflicting reported statuses for the same binary hash pair and future dates.

RO Doctor never fetches source URLs, checks authorship, signs records, or treats a catalog checksum as authentication. It does not modify the catalog or copy evidence into the repository.

If the catalog is malformed, the audit avoids echoing its contents or local filesystem path. Catalog reporting still follows the M2 strict size/record bounds.

## M3 limits

- Tests are metadata and static checks, not execution of a game client.
- Only recognized local map index paths are parsed; custom/other index file locations are not automatically discovered.
- Custom map names and mismatches are informational to minimize false positives.
- An observed_at date and user-supplied test log digest cannot prove authenticity. M4 optionally reads an explicitly supplied local log via --case-log to verify its bytes against the digest; this still cannot prove a real handshake.
- No GitHub Actions. Cross-platform QA uses Windows, WSL and isolated local Docker when available.
