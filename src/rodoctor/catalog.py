"""Local, explicitly supplied compatibility evidence. No URL fetching.

An exact SHA-256 pair is only a match to a claimed test record. The report
never certifies protocol compatibility without independently running a test.
"""
from datetime import date
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from .model import Report

SHA_RE = re.compile(r"^[0-9a-fA-F]{64}$")
MAX_CATALOG_BYTES = 512 * 1024
MAX_RECORDS = 2048
MAX_EXE_BYTES = 200 * 1024 * 1024
METHOD_RE = re.compile(r"^[A-Za-z0-9 _./-]{3,80}$")
SAFE_EXE = re.compile(r"^[^/\\:\x00-\x1f]{1,180}\.exe$", re.I)
STATUSES = {"pass", "fail", "unverified"}


class CatalogError(ValueError):
    """Non-sensitive, stable validation reason for a local catalog."""


def _validate_sha(value: object) -> str:
    if not isinstance(value, str) or not SHA_RE.fullmatch(value):
        raise CatalogError("invalid SHA-256 value")
    return value.lower()


def _load_records(path: Path) -> list[dict]:
    try:
        if not path.is_file() or path.stat().st_size > MAX_CATALOG_BYTES:
            raise CatalogError("catalog missing or exceeds 512 KiB")
        raw = path.read_bytes()
        if len(raw) > MAX_CATALOG_BYTES:
            raise CatalogError("catalog exceeds 512 KiB")
        obj = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise CatalogError("catalog cannot be read as JSON") from None
    if not isinstance(obj, dict) or set(obj) != {"schema_version", "records"}:
        raise CatalogError("catalog top-level schema mismatch")
    if obj["schema_version"] != "1":
        raise CatalogError("unsupported catalog schema")
    records = obj["records"]
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise CatalogError("invalid catalog record array")
    result = []
    for entry in records:
        if not isinstance(entry, dict) or set(entry) != {
            "client_sha256", "server_build_sha256", "status", "evidence"
        }:
            raise CatalogError("invalid record fields")
        client_hash = _validate_sha(entry["client_sha256"])
        server_hash = _validate_sha(entry["server_build_sha256"])
        status = entry["status"]
        if not isinstance(status, str) or status not in STATUSES:
            raise CatalogError("invalid test status")
        evidence = entry["evidence"]
        if not isinstance(evidence, dict) or set(evidence) != {
            "observed_at", "method", "source_url"
        }:
            raise CatalogError("invalid evidence fields")
        observed, method, source = (evidence["observed_at"],
                                    evidence["method"], evidence["source_url"])
        if not isinstance(observed, str) or len(observed) != 10:
            raise CatalogError("invalid evidence date")
        try:
            date.fromisoformat(observed)
        except ValueError:
            raise CatalogError("invalid evidence date") from None
        if not isinstance(method, str) or not METHOD_RE.fullmatch(method):
            raise CatalogError("invalid evidence method")
        if not isinstance(source, str) or len(source) > 300:
            raise CatalogError("invalid source URL")
        try:
            uri = urlsplit(source)
            if (uri.scheme != "https" or not uri.hostname or
                    uri.username or uri.password or uri.query or uri.fragment or
                    any(c.isspace() for c in source) or uri.port not in (None, 443)):
                raise CatalogError("source URL must be a public-style HTTPS link")
        except CatalogError:
            raise
        except ValueError:
            raise CatalogError("invalid source URL") from None
        result.append({"client": client_hash, "server": server_hash,
                       "status": status, "date": observed, "method": method})
    return result


def _select_exe(root: Path, basename: str | None) -> Path | None:
    try:
        options = sorted((
            p for p in root.iterdir()
            if p.is_file() and p.suffix.casefold() == ".exe"
            and ("ragexe" in p.name.casefold() or "ragnarok" in p.name.casefold())
            and p.resolve().is_relative_to(root.resolve())
        ), key=lambda p: p.name.casefold())
    except OSError:
        return None
    if basename is not None:
        if not SAFE_EXE.fullmatch(basename):
            raise CatalogError("client executable must be a basename ending in .exe")
        exact = [p for p in options if p.name.casefold() == basename.casefold()]
        return exact[0] if len(exact) == 1 else None
    if len(options) != 1:
        return None
    return options[0]


def _fingerprint(exe: Path) -> str:
    try:
        size = exe.stat().st_size
        if size > MAX_EXE_BYTES:
            raise CatalogError("client executable exceeds 200 MiB fingerprint limit")
        digest = hashlib.sha256()
        with exe.open("rb") as handle:
            remaining = size
            while remaining:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise CatalogError("client executable changed during hashing")
                digest.update(chunk)
                remaining -= len(chunk)
        return digest.hexdigest()
    except OSError:
        raise CatalogError("client executable cannot be read") from None


def verify(root: Path, catalog_path: Path | None, server_sha: str | None,
           exe_name: str | None, report: Report) -> None:
    if catalog_path is None or server_sha is None:
        report.add("CATALOG_NOT_CONFIGURED", "info", "compatibility",
                   "Provide a local catalog and a separately calculated server build SHA-256.",
                   "Use --catalog with --server-build-sha256 and a client directory.")
        return
    try:
        server_hash = _validate_sha(server_sha)
        records = _load_records(catalog_path)
        exe = _select_exe(root, exe_name)
        if exe is None:
            report.add("CATALOG_CLIENT_AMBIGUOUS", "info", "compatibility",
                       "No uniquely selected Ragexe/Ragnarok-named client EXE was found.",
                       "Use --client-exe with a single matching client executable basename.")
            return
        client_hash = _fingerprint(exe)
    except CatalogError as error:
        # Catalog errors contain fixed, non-sensitive messages.
        report.add("CATALOG_VALIDATION_FAILED", "warning", "compatibility",
                   str(error), "Review the catalog schema and explicit inputs.")
        return
    relevant = [record for record in records
                if record["client"] == client_hash and record["server"] == server_hash]
    if not relevant:
        report.add("CATALOG_EXACT_PAIR_UNKNOWN", "info", "compatibility",
                   "No catalog record matches both explicit SHA-256 fingerprints.",
                   "Collect an isolated, authorized client/server test with provenance.")
        return
    if len({rec["status"] for rec in relevant}) > 1:
        report.add("CATALOG_CONFLICT", "warning", "compatibility",
                   "Conflicting statuses exist for the same exact client/server hash pair.",
                   "Review underlying test evidence; do not conclude compatibility.")
        return
    status = relevant[0]["status"]
    dates = sorted(rec["date"] for rec in relevant)
    if status == "pass":
        code, severity, message = ("CATALOG_REPORTED_PASS", "info",
                                   "Catalog reports pass for this exact hash pair")
    elif status == "fail":
        code, severity, message = ("CATALOG_REPORTED_FAIL", "warning",
                                   "Catalog reports fail for this exact hash pair")
    else:
        code, severity, message = ("CATALOG_UNVERIFIED", "info",
                                   "Catalog has no verified test outcome for this exact hash pair")
    report.add(code, severity, "compatibility",
               f"{message} ({len(relevant)} record(s), last observation {dates[-1]}). "
               "This is externally reported evidence, not an independent runtime test.",
               "Inspect the catalog source_url and method; re-test in your own isolated environment.")


def detector(catalog_path: Path | None, server_sha: str | None,
             client_exe: str | None):
    def run(server: Path | None, client: Path | None, report: Report) -> None:
        assert client is not None
        verify(client, catalog_path, server_sha, client_exe, report)
    return run
