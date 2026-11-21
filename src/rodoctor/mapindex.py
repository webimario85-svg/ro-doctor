"""Conservative cross-check between mapcache and rAthena inter-server map_index.

Uses explicit server root only. Missing *index* entries for cached maps are
informational: a custom map can be usable even without a matching index entry.
Never flags maps listed in map_index but absent from mapcache: the index is
not a mandatory mapcache manifest.
"""
from pathlib import Path
import re

from .mapcache import MAP_INFO, inspect_cache
from .model import Report

INDEX_PATHS = ("db/map_index.txt", "db/import/map_index.txt", "map_index.txt")
CACHE_PATHS = ("db/map_cache.dat", "db/re/map_cache.dat",
               "db/pre-re/map_cache.dat", "db/import/map_cache.dat")
MAX_INDEX_BYTES = 2 * 1024 * 1024
MAX_INDEX_LINES = 65536
INDEX_LINE = re.compile(r"^([A-Za-z0-9_@-]{1,24})(?:\s+(\d{1,8}))?\s*$")
MAX_INDEX_IDS = 200_000
MAX_EXTRA_PATHS = 16


def normalize_extra_index(value: str) -> str | None:
    """Only allow explicit, relative text paths inside the selected server root."""
    if not isinstance(value, str):
        return None
    norm = value.replace("\\", "/")
    parts = norm.split("/")
    if (not norm or len(norm) > 220 or norm.startswith("/") or ":" in norm
            or len(parts) > 12 or any(p in ("", ".", "..") for p in parts)
            or not re.fullmatch(r"[A-Za-z0-9_ @./-]+", norm)
            or not norm.lower().endswith(".txt")):
        return None
    return norm


def _safe_file(root: Path, name: str) -> Path | None:
    path = root / name
    try:
        if not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
            return None
    except (OSError, ValueError):
        return None
    return path


def _read_index(root: Path, paths: list[Path]) -> tuple[set[str], int, int]:
    names: set[str] = set()
    duplicate = invalid = 0
    for path in paths:
        try:
            if path.stat().st_size > MAX_INDEX_BYTES:
                raise ValueError("index too large")
            raw = path.read_bytes()
            if len(raw) > MAX_INDEX_BYTES:
                raise ValueError("index too large")
            lines = raw.decode("utf-8-sig", errors="replace").splitlines()
            if len(lines) > MAX_INDEX_LINES:
                raise ValueError("index has too many lines")
        except (OSError, ValueError):
            invalid += 1
            continue
        for raw_line in lines:
            line = raw_line.split("//", 1)[0].split("#", 1)[0].strip()
            if not line:
                continue
            match = INDEX_LINE.fullmatch(line)
            if not match or (match.group(2) and int(match.group(2)) > MAX_INDEX_IDS):
                invalid += 1
                continue
            name = match.group(1).casefold()
            if name in names:
                duplicate += 1
            names.add(name)
    return names, duplicate, invalid


def _cache_names(path: Path) -> tuple[list[tuple[str, bool]], bool]:
    """Read names only after the cache's structure was validated."""
    details = inspect_cache(path, deep=False)
    if not details.ok:
        return [], False
    result: list[tuple[str, bool]] = []
    offset = details.layout
    with path.open("rb") as stream:
        for _ in range(details.parsed_maps):
            stream.seek(offset)
            name, width, height, length = MAP_INFO.unpack(stream.read(MAP_INFO.size))
            raw_name = name.split(b"\x00", 1)[0]
            try:
                decoded = raw_name.decode("ascii")
            except UnicodeDecodeError:
                return [], False
            if not decoded:
                return [], False
            result.append((decoded.casefold(), b"\x00" not in name))
            offset += MAP_INFO.size + length
    return result, True


def compare(server: Path | None, client: Path | None, report: Report,
            extra_indices: tuple[str, ...] = ()) -> None:
    assert server is not None
    root = server
    if len(extra_indices) > MAX_EXTRA_PATHS:
        report.add("MAP_INDEX_PROVIDER_REJECTED", "warning", "server",
                   "Too many explicit map index providers.",
                   "Provide at most 16 relative index files.")
        return
    wanted = list(INDEX_PATHS)
    for raw in extra_indices:
        name = normalize_extra_index(raw)
        if name is None or _safe_file(root, name) is None:
            report.add("MAP_INDEX_PROVIDER_REJECTED", "warning", "server",
                       "An explicit map index path was invalid, absent or outside the server root.",
                       "Use an existing relative .txt path under --server.")
            continue
        if name not in wanted:
            wanted.append(name)
    indexes = [p for name in wanted if (p := _safe_file(root, name))]
    caches = [p for name in CACHE_PATHS if (p := _safe_file(root, name))]
    if not indexes or not caches:
        return
    names, duplicates, invalid = _read_index(root, indexes)
    if not names:
        report.add("MAP_INDEX_UNREADABLE", "info", "server",
                   "No usable map names were parsed from local map index files.",
                   "Check map index encoding and syntax; this is not a mapcache failure.")
        return
    if invalid:
        report.add("MAP_INDEX_PARTIAL", "info", "server",
                   f"Skipped {invalid} malformed or uninspected map-index line(s)/file(s).",
                   "Review source formatting; name coverage may be incomplete.")
    if duplicates:
        report.add("MAP_INDEX_DUPLICATE_NAME", "info", "server",
                   f"Observed {duplicates} repeated map-index name(s) across local files.",
                   "Review whether these entries are deliberate overrides.")
    missing = ambiguous = checked = skipped = 0
    for file in caches:
        try:
            entries, good = _cache_names(file)
        except OSError:
            good = False
            entries = []
        if not good:
            skipped += 1
            continue
        for name, truncated in entries:
            checked += 1
            if name in names:
                continue
            # Names at capacity are not NUL-terminated and may have been
            # truncated by the source generator. Prefix matches are only hints.
            if truncated and any(candidate.startswith(name) for candidate in names):
                ambiguous += 1
                continue
            missing += 1
    if skipped:
        report.add("MAP_INDEX_CACHE_SKIPPED", "info", "server",
                   f"Skipped name comparison for {skipped} unparseable mapcache file(s).",
                   "Run server-mapcache-structure first; no index conclusion was drawn.")
    if missing:
        report.add("MAP_INDEX_CACHE_ONLY_NAMES", "info", "server",
                   f"{missing} of {checked} cached map name(s) were not declared in checked indices.",
                   "Custom maps or incomplete indexes can be valid; review imports before editing.")
    if ambiguous:
        report.add("MAP_INDEX_TRUNCATED_PREFIX", "info", "server",
                   f"{ambiguous} cached name(s) matched only by a possible truncated prefix.",
                   "Confirm the original map names manually; never assume equality.")
    if checked:
        report.add("MAP_INDEX_COMPARE_COMPLETE", "info", "server",
                   f"Compared {checked} cached map name(s) against local index entries.",
                   "This verifies names only, not whether all indexed maps should be cached.")


def detector(extra_indices: tuple[str, ...] = ()):
    def run(server: Path | None, client: Path | None, report: Report) -> None:
        compare(server, client, report, extra_indices)
    return run
