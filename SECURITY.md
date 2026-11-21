# Security model

RO Doctor examines only paths explicitly supplied by the operator. It does not execute the game, run server commands, open sockets, or alter scanned files. Reports use relative filenames and target directory names, never absolute paths or full config dumps.

The scanner deliberately does not parse credential-bearing rAthena import configurations. M1 parses the bounded, non-credential ItemDB import and optional client binary fingerprints but never executes binaries or unpacks proprietary GRFs. Reports can include relative GRF filenames, hashes and reported test outcomes; review them before sharing. M2/M3 mapcache and index checks bound entry counts, lengths and decompression output; catalog and QA case JSON are opt-in, local, schema-validated and never fetch evidence URLs or read external test logs. User-supplied log hashes are provenance hints, not proof that a test ran. Do not include credential files, proprietary binaries, or private game assets in issues. Use synthetic fixtures to reproduce bugs.

Please report security issues privately to the maintainers before publishing exploits.
