"""Bounded, read-only mapcache structure and compressed-cell validation.

rAthena documentation describes a 6-byte logical header; contemporary C++
mapcache files have an 8-byte on-disk header due to struct alignment.
Map entries are always packed as 12s + int16 + int16 + int32 (20 bytes).
Never trust advertised lengths to allocate memory or seek outside the file.
"""
from dataclasses import dataclass
from pathlib import Path
import struct
import zlib

from .model import Report

MAIN_HEADER = struct.Struct("<IH")
MAP_INFO = struct.Struct("<12shhi")
MAX_MAPS = 8192
MAX_MAP_SIZE_BYTES = 512 * 1024 * 1024
MAX_UNCOMPRESSED_CELLS = 8 * 1024 * 1024
MAX_COMPRESSED_ENTRY = 16 * 1024 * 1024


@dataclass(frozen=True)
class MapCacheResult:
    layout: int
    declared_size: int
    actual_size: int
    declared_maps: int
    parsed_maps: int
    total_offset: int
    errors: tuple[str, ...]
    duplicates: int
    validated_payloads: int
    skipped_payloads: int

    @property
    def ok(self) -> bool:
        return not self.errors


def _inspect_layout(stream, actual_size: int, layout: int, deep: bool) -> MapCacheResult:
    stream.seek(0)
    header = stream.read(layout)
    if len(header) < layout:
        return MapCacheResult(layout, 0, actual_size, 0, 0, 0,
                              ("header-truncated",), 0, 0, 0)
    declared_size, n = MAIN_HEADER.unpack_from(header)
    errors = []
    offset = layout
    parsed = 0
    seen: set[bytes] = set()
    duplicates = validated = skipped = 0
    if n > MAX_MAPS:
        errors.append("map-count-limit")
    elif actual_size > MAX_MAP_SIZE_BYTES:
        errors.append("file-size-limit")
    else:
        for i in range(n):
            if offset + MAP_INFO.size > actual_size:
                errors.append("entry-header-truncated")
                break
            stream.seek(offset)
            raw = stream.read(MAP_INFO.size)
            if len(raw) != MAP_INFO.size:
                errors.append("entry-header-unreadable")
                break
            name, xs, ys, length = MAP_INFO.unpack(raw)
            stripped = name.split(b"\x00", 1)[0]
            if not stripped or b"\x00" in name[:len(stripped)]:
                errors.append("invalid-map-name")
                break
            if stripped.lower() in seen:
                duplicates += 1
            seen.add(stripped.lower())
            if xs <= 0 or ys <= 0 or xs * ys > MAX_UNCOMPRESSED_CELLS:
                errors.append("invalid-map-dimensions")
                break
            if length <= 0:
                errors.append("invalid-compressed-length")
                break
            payload_at = offset + MAP_INFO.size
            next_at = payload_at + length
            if next_at > actual_size:
                errors.append("entry-payload-truncated")
                break
            if deep:
                if length > MAX_COMPRESSED_ENTRY:
                    skipped += 1
                else:
                    stream.seek(payload_at)
                    payload = stream.read(length)
                    if len(payload) != length:
                        errors.append("entry-payload-unreadable")
                        break
                    try:
                        decoder = zlib.decompressobj()
                        decoded = decoder.decompress(payload, xs * ys + 1)
                        valid = (len(decoded) == xs * ys and decoder.eof
                                 and not decoder.unused_data and not decoder.unconsumed_tail)
                    except zlib.error:
                        valid = False
                    if not valid:
                        errors.append("entry-zlib-invalid")
                        break
                    validated += 1
            parsed += 1
            offset = next_at
    if declared_size != actual_size:
        errors.append("advertised-size-mismatch")
    if declared_size < layout:
        errors.append("advertised-size-too-small")
    if not errors and offset != actual_size:
        errors.append("unaccounted-trailing-data")
    return MapCacheResult(layout, declared_size, actual_size, n, parsed, offset,
                          tuple(errors), duplicates, validated, skipped)


def inspect_cache(path: Path, *, deep: bool = False) -> MapCacheResult:
    """Inspect C++ 8-byte aligned header, with strict documented 6-byte fallback."""
    with path.open("rb") as stream:
        size = path.stat().st_size
        eight = _inspect_layout(stream, size, 8, deep)
        if eight.ok:
            return eight
        six = _inspect_layout(stream, size, 6, deep)
        if six.ok:
            return six
        # Prefer aligned format when the byte pair following the 6-byte
        # logical header is zero, or when it advances through more maps.
        stream.seek(6)
        padding = stream.read(2)
        if eight.parsed_maps > six.parsed_maps or padding == b"\x00\x00":
            return eight
        return six


def _run(server: Path | None, report: Report, *, deep: bool) -> None:
    assert server is not None
    paths = ("db/map_cache.dat", "db/re/map_cache.dat",
             "db/pre-re/map_cache.dat", "db/import/map_cache.dat")
    for relative in paths:
        target = server / relative
        try:
            if not target.resolve().is_relative_to(server.resolve()):
                continue
            if not target.is_file():
                continue
            result = inspect_cache(target, deep=deep)
        except OSError:
            report.add("MAPCACHE_PARSE_UNREADABLE", "warning", "server",
                       "Mapcache could not be read safely.",
                       "Review filesystem permissions and file stability.", relative)
            continue
        if result.errors:
            report.add("MAPCACHE_STRUCTURE_INVALID", "error", "server",
                       f"Mapcache structural check failed ({', '.join(result.errors)}); "
                       f"{result.parsed_maps}/{result.declared_maps} entries parsed.",
                       "Compare the mapcache with a clean backup before regeneration. "
                       "Check rAthena #10099.", relative)
            continue
        if result.layout == 6:
            report.add("MAPCACHE_LEGACY_HEADER", "info", "server",
                       "Mapcache uses the documented 6-byte header, not the aligned 8-byte header.",
                       "Confirm this format is supported by your specific map server.", relative)
        if result.duplicates:
            report.add("MAPCACHE_DUPLICATE_MAP_NAMES", "warning", "server",
                       f"Mapcache has {result.duplicates} duplicated map name(s).",
                       "Review the mapcache generation inputs.", relative)
        report.add("MAPCACHE_STRUCTURE_VALID", "info", "server",
                   f"Mapcache size and {result.parsed_maps} map entries are structurally consistent.",
                   "This does not prove game runtime behavior or full asset compatibility.", relative)
        if deep:
            report.add("MAPCACHE_ZLIB_VALIDATED", "info", "server",
                       f"Verified {result.validated_payloads} compressed map payload(s); "
                       f"skipped {result.skipped_payloads} oversized payload(s).",
                       "Inspect skipped payloads separately if full verification is required.",
                       relative)


def structure(server: Path | None, client: Path | None, report: Report) -> None:
    _run(server, report, deep=False)


def deep_payloads(server: Path | None, client: Path | None, report: Report) -> None:
    _run(server, report, deep=True)
