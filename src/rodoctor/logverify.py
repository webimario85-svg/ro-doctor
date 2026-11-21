"""Verify a deliberately supplied QA log's bytes, never its claimed outcome.

The caller supplies both the test-case JSON and an explicit local file.
Matching SHA-256 proves only that the log bytes match a stated digest.
Nothing is executed, inspected as instructions, or uploaded.
"""
from pathlib import Path
import hashlib

from .model import Report

MAX_LOG_BYTES = 128 * 1024 * 1024
CHUNK = 1024 * 1024


def verify(case: dict, path: Path, report: Report) -> bool:
    """Add bounded evidence findings. False blocks claimed PASS/FAIL output."""
    expected = case["log_sha256"]
    if expected is None:
        report.add("CASE_LOG_HASH_UNDECLARED", "warning", "compatibility",
                   "The case contains no log digest for the supplied log file.",
                   "Include log_sha256 in the case or omit --case-log.")
        return False
    try:
        if not path.is_file():
            raise OSError("log is not a file")
        size = path.stat().st_size
        if size > MAX_LOG_BYTES:
            report.add("CASE_LOG_TOO_LARGE", "warning", "compatibility",
                       "The supplied log exceeds the 128 MiB verification limit.",
                       "Produce a bounded, sanitized test log with an exact SHA-256 digest.")
            return False
        digest = hashlib.sha256()
        actual = 0
        with path.open("rb") as handle:
            while True:
                block = handle.read(CHUNK)
                if not block:
                    break
                actual += len(block)
                if actual > MAX_LOG_BYTES:
                    report.add("CASE_LOG_TOO_LARGE", "warning", "compatibility",
                               "The log grew past the bounded read limit.",
                               "Retry with a stable, bounded log artifact.")
                    return False
                digest.update(block)
        if actual != size:
            report.add("CASE_LOG_CHANGED", "warning", "compatibility",
                       "The log size changed during inspection.",
                       "Retry against a stable, completed log artifact.")
            return False
    except OSError:
        report.add("CASE_LOG_UNREADABLE", "warning", "compatibility",
                   "The explicitly supplied local log cannot be read.",
                   "Confirm the file exists and is readable; no path contents were disclosed.")
        return False
    if digest.hexdigest() != expected.lower():
        report.add("CASE_LOG_SHA256_MISMATCH", "warning", "compatibility",
                   "Supplied local log bytes differ from the case's SHA-256 digest.",
                   "Treat this case as untrusted until its log and manifest agree.")
        return False
    report.add("CASE_LOG_SHA256_MATCH", "info", "compatibility",
               f"Verified SHA-256 of {actual} explicitly supplied local log byte(s).",
               "A matching log digest proves file identity only, not test execution or outcome.")
    return True
