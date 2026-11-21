"""Portable, strictly bounded test-run case artifacts from external QA tools.

Test cases are *claims* linked to exact binary hashes and a log digest.
RO Doctor neither executes a test nor reads/fetches the referenced log.
"""
from datetime import date
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from . import catalog
from .model import Report

MAX_CASE_BYTES = 64 * 1024
CASE_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{2,63}$")
SCENARIO_RE = re.compile(r"^[a-z][a-z0-9._-]{2,63}$")
RUNNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _./-]{2,79}$")
KEYS = {"schema_version", "case_id", "scenario", "client_sha256",
        "server_build_sha256", "status", "observed_at", "runner",
        "log_sha256", "source_url"}


class CaseError(ValueError):
    pass


def _source_valid(source: object) -> bool:
    if not isinstance(source, str) or len(source) > 300:
        return False
    if any(ch.isspace() or ord(ch) < 32 for ch in source):
        return False
    try:
        parsed = urlsplit(source)
        return (parsed.scheme == "https" and bool(parsed.hostname)
                and parsed.username is None and parsed.password is None
                and parsed.query == "" and parsed.fragment == ""
                and parsed.port in (None, 443))
    except ValueError:
        return False


def read_case(path: Path) -> dict:
    try:
        if not path.is_file() or path.stat().st_size > MAX_CASE_BYTES:
            raise CaseError("test-case artifact missing or exceeds 64 KiB")
        raw = path.read_bytes()
        if len(raw) > MAX_CASE_BYTES:
            raise CaseError("test-case artifact exceeds 64 KiB")
        doc = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise CaseError("test-case artifact is not readable JSON") from None
    if not isinstance(doc, dict) or set(doc) != KEYS or doc["schema_version"] != "1":
        raise CaseError("test-case artifact schema mismatch")
    for key, pattern in (("case_id", CASE_ID_RE), ("scenario", SCENARIO_RE),
                         ("runner", RUNNER_RE)):
        if not isinstance(doc[key], str) or not pattern.fullmatch(doc[key]):
            raise CaseError(f"invalid {key}")
    for key in ("client_sha256", "server_build_sha256"):
        if not isinstance(doc[key], str) or not catalog.SHA_RE.fullmatch(doc[key]):
            raise CaseError("invalid test-case SHA-256")
    if not isinstance(doc["status"], str) or doc["status"] not in catalog.STATUSES:
        raise CaseError("invalid test-case status")
    observed = doc["observed_at"]
    if not isinstance(observed, str) or len(observed) != 10:
        raise CaseError("invalid test-case date")
    try:
        date.fromisoformat(observed)
    except ValueError:
        raise CaseError("invalid test-case date") from None
    if not _source_valid(doc["source_url"]):
        raise CaseError("test-case source must be public-style HTTPS URL")
    log = doc["log_sha256"]
    if log is not None and (not isinstance(log, str)
                            or not catalog.SHA_RE.fullmatch(log)):
        raise CaseError("invalid log SHA-256")
    if doc["status"] != "unverified" and log is None:
        raise CaseError("claimed pass/fail requires log SHA-256 evidence")
    return doc


def inspect(client: Path, path: Path | None, server_sha: str | None,
            client_exe: str | None, catalog_path: Path | None,
            report: Report) -> None:
    if path is None or server_sha is None:
        report.add("CASE_NOT_CONFIGURED", "info", "compatibility",
                   "No case artifact and server build hash supplied.",
                   "Provide both --case-file and --server-build-sha256.")
        return
    try:
        case = read_case(path)
        supplied_server_hash = catalog._validate_sha(server_sha)
        exe = catalog._select_exe(client, client_exe)
        if exe is None:
            report.add("CASE_CLIENT_AMBIGUOUS", "info", "compatibility",
                       "No uniquely selected client EXE was found.",
                       "Use --client-exe with a Ragexe/Ragnarok-named basename.")
            return
        actual_hash = catalog._fingerprint(exe)
    except (CaseError, catalog.CatalogError) as error:
        report.add("CASE_VALIDATION_FAILED", "warning", "compatibility",
                   str(error), "Review test-case schema and explicit local inputs.")
        return
    if (case["client_sha256"].lower() != actual_hash or
            case["server_build_sha256"].lower() != supplied_server_hash):
        report.add("CASE_HASH_PAIR_MISMATCH", "warning", "compatibility",
                   "Test-case binary hash pair differs from selected client and supplied server hash.",
                   "Do not reuse results for different executable builds.")
        return
    if date.fromisoformat(case["observed_at"]) > date.today():
        report.add("CASE_FUTURE_DATED", "warning", "compatibility",
                   "Reported test date is in the future.",
                   "Verify test artifact provenance and clock settings.")
        return
    if case["status"] == "pass":
        code, level = "CASE_REPORTED_PASS", "info"
    elif case["status"] == "fail":
        code, level = "CASE_REPORTED_FAIL", "warning"
    else:
        code, level = "CASE_UNVERIFIED", "info"
    report.add(code, level, "compatibility",
               f"Test case '{case['case_id']}' reports {case['status']} "
               f"for '{case['scenario']}' via {case['runner']}; "
               "the log checksum and source were not independently verified.",
               "Reproduce the claimed result in an authorized isolated client/server test.")
    if catalog_path is None:
        return
    try:
        records = catalog._load_records(catalog_path)
    except catalog.CatalogError:
        return  # Catalog detector will report the malformed input.
    same = [entry for entry in records
            if entry["client"] == actual_hash
            and entry["server"] == supplied_server_hash]
    if same and any(entry["status"] != case["status"] for entry in same):
        report.add("CASE_CATALOG_DISAGREEMENT", "warning", "compatibility",
                   "Test-case outcome disagrees with at least one catalog record for this hash pair.",
                   "Inspect dates, methods, and source evidence before making compatibility claims.")


def detector(path: Path | None, server_sha: str | None,
             client_exe: str | None, catalog_path: Path | None):
    def run(server: Path | None, client: Path | None, report: Report) -> None:
        assert client is not None
        inspect(client, path, server_sha, client_exe, catalog_path, report)
    return run
