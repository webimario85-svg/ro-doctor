# M2: binary mapcache verification and evidence catalog

## Ground truth

The historical [rAthena map cache documentation](https://github.com/rathena/rathena/blob/master/doc/map_cache.txt) describes a little-endian 6-byte logical header: uint32 byte length and uint16 map count. The [current C++ mapcache generator](https://github.com/rathena/rathena/blob/master/src/tool/mapcache.cpp) writes the entire native struct including two alignment bytes, so its actual on-disk header is **8 bytes**. Each map entry contains a 12-byte map name, int16 X/Y, int32 compressed byte length (20-byte entry header), and a zlib payload.

On 2026-11-21, this M2 was checked against the public upstream db/re/map_cache.dat from rAthena's master branch. Reference observation: 28,232 total bytes, header declares 8 maps, all 8 entries end exactly at EOF, all 8 payloads decompress to X*Y cells; observed SHA-256 e871cb73bae86d4be6e32d35ed34cc0456920203f3ffa4687bdba8eedaf627fd. This reference asset is *not* checked into RO Doctor.

The parser attempts the observed 8-byte layout first and falls back to the documented 6-byte legacy layout only if it parses cleanly. Both are bounded, read-only checks, not universal format detection. An unsupported future format may be reported as structurally invalid.

## Examples

    rodoctor --server /home/user/rathena --only-check server-mapcache-structure
    rodoctor --server /home/user/rathena --only-check server-mapcache-deep --format json

- server-mapcache-structure (default): checks header file size, map count (max 8192), dimensions, compressed payload offsets, duplicate map names, truncation and trailing bytes.
- server-mapcache-deep (on demand): repeats the structural checks and additionally reads each compressed payload of at most 16 MiB and validates its zlib stream and decompressed X*Y size. Limits output to X*Y+1 bytes (at most 8 MiB).
- Cache files over 512 MiB are not traversed. Oversized files are reported as structurally uninspected/invalid rather than silently accepted.
- Empty mapcache files, invalid lengths, impossible dimensions, over-counts, damaged zlib streams, and tail data are flagged.
- Nothing is repaired, regenerated, decompressed to disk, or executed. If an invalid file is found, make a backup and use upstream-approved tooling.

This helps diagnose symptoms discussed in [rAthena #10099](https://github.com/rathena/rathena/issues/10099), but does not prove the reported root cause for any individual cache.

## SHA-256 pair evidence catalog

There is **no public compatibility assertion in the package**. Catalogs are strictly opt-in, local JSON files using [schema v1](compatibility-catalog.schema.json). The [sample](catalog.example.json) is empty on purpose: fabricating successful client/server tests would mislead developers.

A catalog record requires:
- client_sha256: actual bytes of selected client executable, computed by RO Doctor (max 200 MiB).
- server_build_sha256: SHA-256 of the *deployed* map-server executable, supplied explicitly by the operator. RO Doctor does not read or launch servers to establish its identity.
- status: exactly pass, fail, or unverified, describing a **reported**, not independently confirmed, test outcome.
- evidence: ISO observation date, local test method identifier, and public-style HTTPS source URL. RO Doctor never fetches that URL, only validates the text.

Example on Linux:

    sha256sum ./map-server
    rodoctor --client /path/to/client --catalog /path/to/reviewed-catalog.json --server-build-sha256 YOUR_64_CHARACTER_SHA256 --only-check catalog-evidence --format json

Example on Windows PowerShell:

    (Get-FileHash C:\rathena\map-server.exe -Algorithm SHA256).Hash
    rodoctor --client C:\RO\Client --catalog C:\reports\evidence.json --server-build-sha256 YOUR_64_CHARACTER_SHA256 --client-exe Ragexe.exe

The client executable must be uniquely identifiable by name (Ragexe or Ragnarok, including dated builds). With multiple candidates use --client-exe (basename only). The local catalog file must be outside scanned directories. Records are compared only when *both* hashes match, including the explicitly supplied server build hash.

Outputs:
- CATALOG_REPORTED_PASS: self-reported pass, never certified working protocol.
- CATALOG_REPORTED_FAIL: self-reported fail; investigate before assuming incompatibility.
- CATALOG_UNVERIFIED: exact pair with no observed outcome.
- CATALOG_CONFLICT: contradictory outcomes for the exact pair.
- CATALOG_EXACT_PAIR_UNKNOWN: no exact pair in supplied catalog.
- Other codes cover ambiguous client binaries and invalid catalog input.

Catalog JSON is capped at 512 KiB / 2048 records. Malformed input fails conservatively and never inserts source contents into the generated report. Source references are evidence pointers, not proof that the external content is authentic. A server build SHA-256 provided by a user cannot be independently attested by a static scan.

## Security, licensing and cross-platform notes

No GRFs, client executables, copyrighted map contents, or private project settings are committed. Synthetic tests generate tiny zlib payloads. The optional public upstream reference cache is used only for a local QA check and remains in ignored .qa/. Reports may contain fingerprints, relative filenames and target directory basenames; review before sharing.

The stdlib implementation is Python 3.10+ compatible and uses portable little-endian struct parsing and chunked SHA-256. Packaging is a universal py3-none-any wheel. Verification on other platforms is recorded in STATE.md only when actually executed; package metadata alone is not an OS-specific test.
