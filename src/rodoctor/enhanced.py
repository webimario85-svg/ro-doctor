"""M1 evidence-only detectors. No executable launching or network I/O."""
from datetime import date
import hashlib
from pathlib import Path
import re
import stat
import struct

from .model import Report
from .scan import _safe_read, _lookup_case_insensitive

GRF_MAGIC = b"Master of Magic"   # 15 byte GRF file signature
GRF_MIN_HEADER = 46
IMPORT_SCAN_LIMIT = 2 * 1024 * 1024
DATE_RE = re.compile(r"(?<!\d)(20\d{2})[-_]?(\d{2})[-_]?(\d{2})(?!\d)")
ITEM_ID_RE = re.compile(r"^(?P<indent>\s*)-\s+Id:\s*(?P<id>\d+)\s*(?:#.*)?$")
ITEM_FIELD_RE = re.compile(r"^\s*(?P<key>[A-Za-z][A-Za-z0-9_]*):(?:\s|$)")
PACKETVER_RE = re.compile(r"^\s*#\s*define\s+PACKETVER\s+(\d{8})\b", re.M)


def grf_headers(server: Path | None, client: Path | None,
                report: Report) -> None:
    assert client is not None
    root = client
    try:
        archives = sorted((p for p in root.iterdir()
                           if p.is_file() and p.suffix.casefold() == ".grf"),
                          key=lambda x: x.name.casefold())
    except OSError:
        return
    # Validate root GRFs and references inside data.ini without unpacking assets.
    ini = next((p for p in root.iterdir()
                if p.name.casefold() == "data.ini" and p.is_file()), None)
    if ini is not None:
        contents = _safe_read(root, ini)
        if contents is not None:
            in_data = False
            for line in contents.splitlines():
                line = line.strip()
                if line.startswith("[") and line.endswith("]"):
                    in_data = line[1:-1].strip().casefold() == "data"
                    continue
                if not in_data or not line or line.startswith((";", "#")):
                    continue
                match = re.match(r"^\d+\s*=\s*(.+)$", line)
                if not match:
                    continue
                relative = match.group(1).split(";", 1)[0].strip().strip('"')
                if not relative.casefold().endswith(".grf"):
                    continue
                file = _lookup_case_insensitive(root, relative)
                if file is not None and file not in archives:
                    archives.append(file)
    for file in archives:
        rel = file.relative_to(root).as_posix() if file.is_relative_to(root) else None
        if rel is None:
            continue
        try:
            if not file.resolve().is_relative_to(root.resolve()):
                continue
            with file.open("rb") as f:
                header = f.read(GRF_MIN_HEADER)
        except OSError:
            report.add("GRF_HEADER_UNREADABLE", "warning", "client",
                       "A GRF header could not be read.", "Check read permissions.",
                       rel)
            continue
        if len(header) < GRF_MIN_HEADER:
            report.add("GRF_HEADER_TRUNCATED", "warning", "client",
                       "A GRF file is smaller than the minimum known header.",
                       "Replace this asset using a legally obtained complete archive.", rel)
        elif not header.startswith(GRF_MAGIC):
            report.add("GRF_HEADER_INVALID", "warning", "client",
                       "A GRF file does not start with the standard GRF signature.",
                       "Validate the archive format; a custom loader may differ.", rel)


def load_order(server: Path | None, client: Path | None,
               report: Report) -> None:
    assert client is not None
    try:
        ini = next((p for p in client.iterdir()
                    if p.name.casefold() == "data.ini" and p.is_file()), None)
    except OSError:
        return
    if ini is None:
        return
    text = _safe_read(client, ini)
    if text is None:
        return
    section = False
    indexes: list[int] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().casefold() == "data"
            continue
        if not section or not line or line.startswith((";", "#")):
            continue
        match = re.match(r"^(\d+)\s*=", line)
        if match:
            indexes.append(int(match.group(1)))
    if not indexes:
        return
    if len(indexes) != len(set(indexes)):
        report.add("GRF_INDEX_DUPLICATE", "warning", "client",
                   "data.ini uses the same numbered GRF load-order index more than once.",
                   "Assign each GRF a distinct index.", ini.name)
    ordered = sorted(set(indexes))
    if ordered[-1] - ordered[0] + 1 != len(ordered):
        report.add("GRF_INDEX_GAP", "info", "client",
                   "Numbered GRF load-order entries have gaps.",
                   "Review whether the load order is intentional.", ini.name)


def itemdb_partial_import(server: Path | None, client: Path | None,
                          report: Report) -> None:
    """Spot a pattern from rAthena #10098, not a runtime price prediction.

    This narrow static detector processes only obvious '- Id:' YAML records.
    It does not attempt general YAML parsing or infer which server revisions
    are affected. Reports neither item names nor contents.
    """
    assert server is not None
    root = server
    file = root / "db/import/item_db.yml"
    try:
        if not file.resolve().is_relative_to(root.resolve()):
            return
        if not file.is_file():
            return
        size = file.stat().st_size
    except OSError:
        return
    if size > IMPORT_SCAN_LIMIT:
        report.add("ITEMDB_IMPORT_TOO_LARGE", "info", "server",
                   "ItemDB import exceeds the bounded static-inspection limit.",
                   "Review partial overrides with the server ItemDB loader.",
                   "db/import/item_db.yml")
        return
    content = _safe_read(root, file)
    # _safe_read is restricted to 256 KiB; larger imports are explicitly unknown.
    if content is None:
        report.add("ITEMDB_IMPORT_NOT_INSPECTED", "info", "server",
                   "ItemDB import was not inspected by the bounded text reader.",
                   "Check this file manually if it contains partial overrides.",
                   "db/import/item_db.yml")
        return
    found: list[str] = []
    in_body = False
    current: str | None = None
    fields: set[str] = set()

    def finish() -> None:
        if current is not None and "Name" in fields and not (
            {"Buy", "Sell"} & fields
        ):
            found.append(current)

    for line in content.splitlines():
        if re.match(r"^Body:\s*(?:#.*)?$", line):
            in_body = True
            continue
        if not in_body or not line.strip() or line.lstrip().startswith("#"):
            continue
        match = ITEM_ID_RE.match(line)
        if match:
            finish()
            current = match.group("id")
            fields = set()
            continue
        if current is not None:
            field = ITEM_FIELD_RE.match(line)
            if field:
                fields.add(field.group("key"))
    finish()
    if found:
        report.add("ITEMDB_PARTIAL_OVERRIDE_REVIEW", "warning", "server",
                   f"Found {len(found)} name-only ItemDB import entry/entries without Buy/Sell.",
                   "Review derived price behavior when upgrading rAthena; see upstream issue #10098.",
                   "db/import/item_db.yml")


def mapcache_sparse(server: Path | None, client: Path | None,
                    report: Report) -> None:
    assert server is not None
    root = server
    for rel in ("db/map_cache.dat", "db/re/map_cache.dat",
                "db/pre-re/map_cache.dat", "db/import/map_cache.dat"):
        file = root / rel
        try:
            if not file.resolve().is_relative_to(root.resolve()) or not file.is_file():
                continue
            info = file.stat()
        except OSError:
            continue
        # On Windows the sparse attribute is exposed by os.stat_result.
        is_sparse = bool(getattr(info, "st_file_attributes", 0) &
                         getattr(stat, "FILE_ATTRIBUTE_SPARSE_FILE", 0x200))
        # Linux also reports allocated blocks separately.
        blocks = getattr(info, "st_blocks", None)
        if blocks is not None and info.st_size >= 256 * 1024 * 1024:
            is_sparse |= blocks * 512 < info.st_size // 4
        if is_sparse:
            report.add("MAPCACHE_SPARSE_FILE", "warning", "server",
                       "A mapcache file has sparse allocation; that alone does not prove corruption.",
                       "Verify map count and cache consistency before replacing it; see rAthena #10099.",
                       rel)


def exe_fingerprint(server: Path | None, client: Path | None,
                    report: Report) -> None:
    """Explicit opt-in fingerprinting to build a verified external version catalog.

    Hashes binary bytes in bounded chunks; never executes, decrypts or patches.
    PE linker timestamps are not Ragexe version dates.
    """
    assert client is not None
    root = client
    max_bytes = 200 * 1024 * 1024
    try:
        candidates = sorted((
            p for p in root.iterdir()
            if p.is_file() and p.suffix.casefold() == ".exe" and
            ("ragexe" in p.name.casefold() or "ragnarok" in p.name.casefold())
        ), key=lambda p: p.name.casefold())
    except OSError:
        return
    for exe in candidates:
        try:
            if not exe.resolve().is_relative_to(root.resolve()):
                continue
            length = exe.stat().st_size
            if length > max_bytes:
                report.add("CLIENT_EXE_TOO_LARGE_TO_HASH", "info", "client",
                           "Executable exceeds the 200 MiB fingerprinting limit.",
                           "Review this file manually before fingerprinting.", exe.name)
                continue
            sha = hashlib.sha256()
            with exe.open("rb") as stream:
                first = stream.read(64)
                sha.update(first)
                remaining = length - len(first)
                while remaining > 0:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise OSError("binary changed while hashing")
                    sha.update(chunk)
                    remaining -= len(chunk)
                # Decode PE header only as additional non-authoritative metadata.
                pe = ""
                if len(first) >= 64 and first[:2] == b"MZ":
                    offset = struct.unpack_from("<I", first, 0x3c)[0]
                    if 0 <= offset <= max(0, length - 12):
                        stream.seek(offset)
                        header = stream.read(12)
                        if len(header) == 12 and header[:4] == b"PE\x00\x00":
                            machine, _, timestamp = struct.unpack_from("<HHI", header, 4)
                            pe = f"; PE machine=0x{machine:04x}; linker timestamp={timestamp}"
            report.add("CLIENT_EXE_SHA256", "info", "client",
                       f"SHA-256 {sha.hexdigest()} ({length} bytes){pe}.",
                       "Use this content fingerprint for independent version evidence; "
                       "do not interpret PE timestamp as a Ragexe release date.",
                       exe.name)
        except OSError:
            report.add("CLIENT_EXE_FINGERPRINT_FAILED", "warning", "client",
                       "Unable to finish reading a candidate executable.",
                       "Check file permissions and ensure it is not changing.", exe.name)


def _dated_filenames(client: Path) -> set[str]:
    try:
        names = [p.name for p in client.iterdir()
                 if p.is_file() and p.suffix.casefold() == ".exe"
                 and ("ragexe" in p.name.casefold() or "ragnarok" in p.name.casefold())]
    except OSError:
        return set()
    result = set()
    for name in names:
        for match in DATE_RE.finditer(name):
            try:
                date(*map(int, match.groups()))
            except ValueError:
                continue
            result.add("".join(match.groups()))
    return result


def protocol_evidence(server: Path | None, client: Path | None,
                      report: Report) -> None:
    assert server is not None and client is not None
    declared: set[str] = set()
    for relative in ("src/custom/defines_pre.hpp", "src/config/packets.hpp",
                     "src/common/packets.hpp", "src/map/packets.hpp"):
        content = _safe_read(server, server / relative)
        if content:
            clean = re.sub(r"/\*.*?\*/|//[^\n]*", "", content, flags=re.S)
            declared.update(PACKETVER_RE.findall(clean))
    dates = _dated_filenames(client)
    if dates:
        report.add("CLIENT_DATE_FILENAME_EVIDENCE", "info", "compatibility",
                   "Found client date hint(s) in executable filename(s): "
                   + ", ".join(sorted(dates)) + ".",
                   "Filename hints are untrusted; confirm executable revision independently.")
    if dates and declared and not (dates & declared):
        report.add("PROTOCOL_DATE_HINT_DIFFERENCE", "info", "compatibility",
                   "PACKETVER source declarations and client filename date hints differ.",
                   "Do not assume mismatch: confirm build flags and a permitted handshake test.")
    report.add("PROTOCOL_NOT_VERIFIED", "info", "compatibility",
               "Static inspection cannot establish Ragexe-to-server protocol compatibility.",
               "Run a separate isolated client/server handshake test before claiming support.")
