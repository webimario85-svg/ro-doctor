"""Offline provenance audit for user-supplied compatibility claims.

File hashes identify the evidence document, not the credibility of its
author, source URL or real-world test outcome.
"""
from collections import defaultdict
from datetime import date
import hashlib
from pathlib import Path

from . import catalog
from .model import Report


def audit(server: Path | None, client: Path | None,
          report: Report, path: Path | None) -> None:
    if path is None:
        return
    try:
        records = catalog._load_records(path)
        # The validation function already bounds size at 512 KiB.
        blob = path.read_bytes()
        if len(blob) > catalog.MAX_CATALOG_BYTES:
            raise catalog.CatalogError("catalog exceeds 512 KiB")
    except (catalog.CatalogError, OSError):
        report.add("CATALOG_AUDIT_UNAVAILABLE", "info", "compatibility",
                   "The locally supplied catalog could not be audited.",
                   "Inspect schema errors from catalog-evidence and review the local file.")
        return
    digest = hashlib.sha256(blob).hexdigest()
    pass_count = sum(entry["status"] == "pass" for entry in records)
    fail_count = sum(entry["status"] == "fail" for entry in records)
    pairs: dict[tuple[str, str], set[str]] = defaultdict(set)
    duplicates: set[tuple] = set()
    seen: set[tuple] = set()
    future = 0
    for entry in records:
        pair = (entry["client"], entry["server"])
        pairs[pair].add(entry["status"])
        key = (pair, entry["status"], entry["date"], entry["method"])
        if key in seen:
            duplicates.add(key)
        seen.add(key)
        if date.fromisoformat(entry["date"]) > date.today():
            future += 1
    report.add("CATALOG_PROVENANCE_SUMMARY", "info", "compatibility",
               f"Local catalog SHA-256 {digest}; {len(records)} reported record(s) "
               f"({pass_count} pass, {fail_count} fail, "
               f"{len(records)-pass_count-fail_count} unverified).",
               "The file hash tracks a particular catalog revision, not whether claims are true.")
    conflicts = sum(len(statuses) > 1 for statuses in pairs.values())
    if conflicts:
        report.add("CATALOG_PROVENANCE_CONFLICT", "warning", "compatibility",
                   f"{conflicts} exact binary pair(s) have conflicting reported statuses.",
                   "Review each pair's test logs and independent sources.")
    if duplicates:
        report.add("CATALOG_PROVENANCE_REPEATED", "info", "compatibility",
                   f"{len(duplicates)} repeated date/method/status/pair combinations.",
                   "Determine whether these are independent observations or duplicate reports.")
    if future:
        report.add("CATALOG_PROVENANCE_FUTURE", "warning", "compatibility",
                   f"{future} catalog record(s) have future observation dates.",
                   "Verify local clock, source dates and test provenance.")


def detector(path: Path | None):
    def run(server: Path | None, client: Path | None, report: Report) -> None:
        audit(server, client, report, path)
    return run
