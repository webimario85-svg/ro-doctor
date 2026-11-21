# Security model

RO Doctor examines only paths explicitly supplied by the operator. It does not execute the game, run server commands, open sockets, or alter scanned files. Reports use relative filenames and target directory names, never absolute paths or config contents.

The scanner deliberately does not parse credential-bearing rAthena import configurations. Do not include credential files, proprietary binaries, or private game assets in issues. Use synthetic fixtures to reproduce bugs.

Please report security issues privately to the maintainers before publishing exploits.
