# Security model

RO Doctor examines only paths explicitly supplied by the operator. It does not execute the game, run server commands, open sockets, or alter scanned files. Reports use relative filenames and target directory names, never absolute paths or full config dumps.

The scanner deliberately does not parse credential-bearing rAthena import configurations. M1 parses the bounded, non-credential ItemDB import and optional client binary fingerprints but never executes binaries or unpacks proprietary GRFs. Reports can include relative GRF filenames, hashes and reported test outcomes; review them before sharing. Mapcache and index checks bound entry counts, lengths and decompression output. Catalog and QA case JSON are opt-in, local, schema-validated and never fetch evidence URLs. M4 may read an explicitly supplied local case log (up to 128 MiB, streaming) solely to verify SHA-256; it never executes or prints the log. Any mismatch suppresses reported success/failure findings. Matching bytes, however, do not establish log authorship or prove that a game test ran. Do not include credential files, proprietary binaries, or private game assets in issues. Use synthetic fixtures to reproduce bugs.

Please report security issues privately to the maintainers before publishing exploits.
