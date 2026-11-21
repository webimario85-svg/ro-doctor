# Upstream regression evidence (2026)

All checks here are advisories that use entirely synthetic fixtures. The tool does not claim to reproduce real rAthena runtime bugs or assert that a given revision is vulnerable.

## rAthena issue #10098 — partial ItemDB import

Source: https://github.com/rathena/rathena/issues/10098

Reported scenario: an ItemDB import that changes a name while leaving Buy/Sell unspecified could change the final derived Sell value in a particular revision. Explicit Sell: 0 is a separate case and must remain intentional.

RO Doctor scans only db/import/item_db.yml, requires recognizable Body:, - Id: and Name: fields, and flags entries that omit both price fields. It never predicts the loaded price, makes no assertions about whether the server incorporates a fix, and avoids including the item name in the report. Regression fixtures cover both name-only import and explicitly provided Sell: 0.

## rAthena issue #10099 — sparse mapcache after updates

Source: https://github.com/rathena/rathena/issues/10099
Documentation: https://github.com/rathena/rathena/blob/master/doc/map_cache.txt

Reported symptom: an incremental mapcache operation with new imported maps could produce an implausibly large, sparsely allocated map_cache.dat. Existing RO Doctor size heuristics and new sparse-allocation metadata check can flag suspicious symptoms. Neither detector parses the actual map count or proves corruption; review the cache before regenerating.

## GRF archive signature and load order

Format reference: https://ragnarokresearchlab.github.io/file-formats/grf/
Client discussion: https://rathena.org/board/topic/149264-client-2026-02-19_ragexe

The standard GRF header starts with a 15-byte Master of Magic signature. M1 reads only the minimum file header, not archives' content. data.ini checks cover missing and duplicate GRFs, repeated indices, and numbering gaps. Some loaders ignore data.ini; these checks are evidence, not universal requirements.

## Version and compatibility

Source: https://github.com/rathena/rathena/blob/master/src/config/packets.hpp

An effective server PACKETVER is a build-time property. A date in an EXE filename or a COFF linker timestamp is not independent proof of the Ragexe version. The on-demand SHA-256 check provides a stable file fingerprint for future evidence catalogs. Real protocol support needs a separately authorized client/server handshake test.
