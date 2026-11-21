"""Conservative, network-free inspection of explicit local targets.

No executables launched. No DB connections. No secret-bearing config parsing.
All reported paths are relative to the user-selected root.
"""
from pathlib import Path
import re

from .model import Report

MAX_TEXT_BYTES = 256 * 1024
SUSPICIOUS_MAPCACHE_BYTES = 256 * 1024 * 1024
PACKETVER_RE = re.compile(r"^\s*#\s*define\s+PACKETVER\s+(\d{8})\b", re.M)
CLIENT_EXE_RE = re.compile(r"ragexe|ragnarok|(?:^20\d{6}.*ro)", re.I)
DATA_ENTRY_RE = re.compile(r"^\s*(\d+)\s*=\s*(.+?)\s*$")


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _safe_read(root: Path, path: Path) -> str | None:
    """Only read small files whose resolved path stays inside the selected root."""
    try:
        if not path.resolve().is_relative_to(root.resolve()):
            return None
        if not path.is_file() or path.stat().st_size > MAX_TEXT_BYTES:
            return None
        raw = path.read_bytes()
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            return raw.decode("utf-16", errors="replace")
        return raw.decode("utf-8-sig", errors="replace")
    except (OSError, ValueError):
        return None


def _lookup_case_insensitive(root: Path, relative: str) -> Path | None:
    """Resolve a relative asset name like the Windows client would."""
    norm = relative.replace("\\", "/")
    if norm.startswith("/") or ":" in norm or any(
        part in {"..", ""} for part in norm.split("/")
    ):
        return None
    current = root
    try:
        for piece in norm.split("/"):
            matches = (p for p in current.iterdir()
                       if p.name.casefold() == piece.casefold())
            current = next(matches, None)
            if current is None or not current.resolve().is_relative_to(root.resolve()):
                return None
        return current if current.is_file() else None
    except (OSError, ValueError):
        return None


def _scan_server(root: Path, report: Report) -> None:
    subject = "server"
    markers = (
        root / "src" / "map" / "map.cpp",
        root / "src" / "map" / "map.c",
        root / "conf" / "map_athena.conf",
        root / "db" / "re",
        root / "db" / "pre-re",
    )
    if not any(p.exists() for p in markers):
        report.add("SERVER_LAYOUT_UNRECOGNIZED", "warning", subject,
                   "Typical rAthena source/configuration paths were not found.",
                   "Check that --server points to the rAthena repository root.")
    else:
        report.add("SERVER_LAYOUT_DETECTED", "info", subject,
                   "Found paths consistent with an rAthena checkout.",
                   "This is not proof of server version or runtime health.")

    candidates = (
        "src/custom/defines_pre.hpp",
        "src/common/packets.hpp",
        "src/map/packets.hpp",
        "src/config/packets.hpp",
        "src/common/packets.h",
    )
    versions = []
    for rel in candidates:
        contents = _safe_read(root, root / rel)
        if contents is None:
            continue
        # Ignore commented-out declarations; conditional branches still need build validation.
        active_source = re.sub(r"/\*.*?\*/|//[^\n]*", "", contents, flags=re.S)
        versions.extend((m.group(1), rel) for m in PACKETVER_RE.finditer(active_source))
    if not versions:
        report.add("PACKETVER_NOT_FOUND", "info", subject,
                   "No explicit PACKETVER declaration found in checked source files.",
                   "Inspect the build configuration and compiler definitions manually.")
    else:
        unique = {value for value, _ in versions}
        if len(unique) > 1:
            report.add("PACKETVER_MULTIPLE", "warning", subject,
                       "Different PACKETVER declarations were found in source files.",
                       "Inspect conditional compilation and the effective build flags.")
        for value, rel in versions:
            report.add("PACKETVER_DECLARATION", "info", subject,
                       f"Source declares PACKETVER {value}.",
                       "Verify the value used by the compiled server; not a client match test.",
                       rel)

    for rel in ("db/map_cache.dat", "db/re/map_cache.dat",
                "db/pre-re/map_cache.dat"):
        file = root / rel
        try:
            if not file.resolve().is_relative_to(root.resolve()):
                report.add("MAPCACHE_OUTSIDE_ROOT", "warning", subject,
                           "A map cache resolves outside the selected directory.",
                           "Review this symlink before scanning external files.", rel)
                continue
            if not file.is_file():
                continue
            size = file.stat().st_size
            if size == 0:
                report.add("MAPCACHE_EMPTY", "error", subject,
                           "A map cache file is empty.",
                           "Regenerate it using the project's supported mapcache procedure.",
                           rel)
            elif size >= SUSPICIOUS_MAPCACHE_BYTES:
                report.add("MAPCACHE_UNUSUALLY_LARGE", "warning", subject,
                           "A map cache exceeds 256 MiB; size alone does not prove corruption.",
                           "Compare logical and allocated size, then verify mapcache tooling.",
                           rel)
        except OSError:
            report.add("MAPCACHE_UNREADABLE", "warning", subject,
                       "Map cache metadata could not be inspected.",
                       "Check read permissions and filesystem integrity.", rel)


def _scan_client(root: Path, report: Report) -> None:
    subject = "client"
    try:
        entries = list(root.iterdir())
    except OSError:
        report.add("CLIENT_UNREADABLE", "error", subject,
                   "Unable to list the client directory.",
                   "Check read permissions.")
        return
    exes = [p for p in entries if p.is_file() and
            p.suffix.casefold() == ".exe" and CLIENT_EXE_RE.search(p.name)]
    if not exes:
        report.add("CLIENT_EXE_NOT_FOUND", "warning", subject,
                   "No Ragexe/Ragnarok-named executable was found in the client root.",
                   "Confirm the client root; custom executable names need manual review.")
    else:
        report.add("CLIENT_EXE_CANDIDATES", "info", subject,
                   f"Found {len(exes)} candidate executable(s) by filename.",
                   "No binary signature, packet version, or license check was performed.")

    grfs = {p.name.casefold() for p in entries
            if p.is_file() and p.suffix.casefold() == ".grf"}
    data_dir = any(p.is_dir() and p.name.casefold() == "data" for p in entries)
    if not grfs and not data_dir:
        report.add("CLIENT_ASSET_ROOT_ABSENT", "warning", subject,
                   "No root GRF files or unpacked data directory were found.",
                   "Check the selected client directory and resource layout.")
    ini = next((p for p in entries if p.is_file() and
                p.name.casefold() == "data.ini"), None)
    if ini is None:
        report.add("DATA_INI_NOT_FOUND", "info", subject,
                   "No data.ini found; custom resource loaders may use another method.",
                   "Inspect the client's configured GRF load order manually.")
        return
    content = _safe_read(root, ini)
    if content is None:
        report.add("DATA_INI_UNREADABLE", "warning", subject,
                   "data.ini is unreadable, too large, or points outside the selected root.",
                   "Check its encoding, size, and filesystem permissions.", ini.name)
        return

    # Only numbered entries in the [Data] section have GRF load-order semantics.
    in_data = False
    found = 0
    seen: set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        if line.startswith((";", "#")) or not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            in_data = line[1:-1].strip().casefold() == "data"
            continue
        if not in_data:
            continue
        match = DATA_ENTRY_RE.match(line)
        if not match:
            continue
        found += 1
        name = match.group(2).split(";", 1)[0].strip().strip('"')
        key = name.replace("\\", "/").casefold()
        norm = name.replace("\\", "/")
        invalid = (not name.casefold().endswith(".grf") or
                   norm.startswith("/") or ":" in norm or
                   any(piece in {"..", ".", ""} for piece in norm.split("/")))
        if invalid:
            report.add("GRF_REFERENCE_INVALID", "error", subject,
                       "data.ini contains an invalid or non-relative GRF reference.",
                       "Use a valid relative GRF path within the client root.", ini.name)
            continue
        if key in seen:
            report.add("GRF_DUPLICATE_REFERENCE", "warning", subject,
                       f"data.ini references '{name}' more than once.",
                       "Remove duplicate load-order entries.", ini.name)
        seen.add(key)
        if _lookup_case_insensitive(root, name) is None:
            report.add("GRF_REFERENCE_MISSING", "error", subject,
                       f"GRF reference '{name}' was not found within the client root.",
                       "Fix the data.ini entry or supply the authorized asset.",
                       ini.name)
    if found == 0:
        report.add("DATA_INI_NO_ENTRIES", "warning", subject,
                   "No numbered entries were found in data.ini [Data].",
                   "Verify section name, encoding, and asset load order.", ini.name)


def build_registry(*, catalog_path=None, server_build_sha256=None, client_exe=None):
    """Return fresh built-ins so users can extend without mutating global state."""
    from .checks import Check, Registry
    from . import catalog, enhanced, mapcache

    registry = Registry()
    registry.register(Check("server-static", "server",
                            "rAthena layout, PACKETVER declarations, mapcache metadata",
                            lambda server, client, report: _scan_server(server, report)))
    registry.register(Check("server-itemdb", "server",
                            "Conservative partial ItemDB override review (#10098)",
                            enhanced.itemdb_partial_import))
    registry.register(Check("server-sparse-cache", "server",
                            "Sparse mapcache metadata review (#10099)",
                            enhanced.mapcache_sparse))
    registry.register(Check("server-mapcache-structure", "server",
                            "Bounded binary mapcache header, entry count and offset validation",
                            mapcache.structure))
    registry.register(Check("server-mapcache-deep", "server",
                            "On-demand bounded zlib payload validation for mapcache",
                            mapcache.deep_payloads, default=False))
    registry.register(Check("client-static", "client",
                            "Client executable, assets, and data.ini GRF references",
                            lambda server, client, report: _scan_client(client, report)))
    registry.register(Check("client-grf-header", "client",
                            "Local GRF archive signatures and minimum header length",
                            enhanced.grf_headers))
    registry.register(Check("client-load-order", "client",
                            "Duplicate or discontinuous data.ini GRF indices",
                            enhanced.load_order))
    registry.register(Check("client-exe-fingerprint", "client",
                            "On-demand SHA-256 and PE header metadata for client executable(s)",
                            enhanced.exe_fingerprint, default=False))
    registry.register(Check("protocol-evidence", "combined",
                            "Non-authoritative client filename vs source PACKETVER hints",
                            enhanced.protocol_evidence))
    registry.register(Check("catalog-evidence", "client",
                            "Opt-in exact client/server build SHA-256 pair evidence catalog",
                            catalog.detector(catalog_path, server_build_sha256, client_exe),
                            default=catalog_path is not None))
    return registry


def scan(server: Path | None = None, client: Path | None = None, *,
         only: list[str] | None = None,
         skip: list[str] | None = None,
         registry=None, catalog_path: Path | None = None,
         server_build_sha256: str | None = None,
         client_exe: str | None = None) -> Report:
    """Read-only scan using explicitly registered checks. Never loads plugins from disk."""
    report = Report()
    selected = (registry if registry is not None else build_registry(
        catalog_path=catalog_path, server_build_sha256=server_build_sha256,
        client_exe=client_exe)).select(only, skip)
    paths = {"server": Path(server).expanduser() if server is not None else None,
             "client": Path(client).expanduser() if client is not None else None}
    valid = {"server": False, "client": False}
    for subject, path in paths.items():
        if path is None:
            continue
        report.targets[subject] = path.name or subject
        try:
            valid[subject] = path.is_dir()
        except OSError:
            pass
        if not valid[subject]:
            report.add("TARGET_NOT_DIRECTORY", "error", subject,
                       "Supplied target does not exist or is not a readable directory.",
                       f"Provide an existing {subject} directory.")
    for check in selected:
        if check.target == "combined":
            enabled = valid["server"] and valid["client"]
        else:
            enabled = valid[check.target]
        if not enabled:
            continue
        try:
            check.run(paths["server"], paths["client"], report)
        except Exception:
            # Do not leak exception text containing local directories or secrets.
            report.add("CHECK_EXECUTION_FAILED", "error", check.target,
                       f"Detector '{check.id}' failed unexpectedly.",
                       "Report a sanitized reproduction to RO Doctor maintainers.")
    return report
