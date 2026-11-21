"""M3: rAthena map_index semantics and portable test-run provenance.

All fixtures synthetic. No game/client binaries, network access or live servers.
"""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

from rodoctor.cases import read_case, CaseError
from rodoctor.cli import main
from rodoctor.scan import build_registry, scan
from rodoctor.render import render_json


def synthetic_cache(names, *, layout=8):
    parts = []
    for name in names:
        payload = zlib.compress(bytes(4))
        parts.append(struct.pack("<12shhi",
                                 name.encode("ascii").ljust(12, b"\0")[:12],
                                 2, 2, len(payload)) + payload)
    body = b"".join(parts)
    total = layout + len(body)
    return struct.pack("<IH", total, len(names)) + (
        b"\0\0" if layout == 8 else b"") + body


class M3Tests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.server = self.root / "server"
        self.client = self.root / "client"
        self.server.mkdir()
        self.client.mkdir()
        self.sha_server = "b" * 64
        self.exe = self.client / "2026-02-19_Ragexe.exe"
        self.exe.write_bytes(b"MZsynthetic")
        self.sha_client = hashlib.sha256(self.exe.read_bytes()).hexdigest()

    def write(self, parent, rel, data):
        path = parent / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        return path

    def codes(self, result):
        return [item.code for item in result.findings]

    def cache(self, *names):
        return self.write(self.server, "db/re/map_cache.dat", synthetic_cache(names))

    def index(self, text, rel="db/map_index.txt"):
        return self.write(self.server, rel, text)

    def catalog(self, entries):
        path = self.root / "catalog.json"
        path.write_text(json.dumps({"schema_version": "1", "records": entries}),
                        encoding="utf-8")
        return path

    def record(self, status="unverified", source=None):
        return {
            "client_sha256": self.sha_client,
            "server_build_sha256": self.sha_server,
            "status": status,
            "evidence": {
                "observed_at": "2026-11-21",
                "method": "isolated-login-test",
                "source_url": source or "https://github.com/example/qa/1"
            }
        }

    def case(self, **changes):
        data = {
            "schema_version": "1",
            "case_id": "test-login-001",
            "scenario": "login-handshake",
            "client_sha256": self.sha_client,
            "server_build_sha256": self.sha_server,
            "status": "pass",
            "observed_at": "2026-11-21",
            "runner": "athena-testlab/0.1",
            "log_sha256": "a"*64,
            "source_url": "https://github.com/example/qa/1"
        }
        data.update(changes)
        path = self.root / "case.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_m3_detector_registry(self):
        checks = {check.id: check for check in build_registry().available()}
        self.assertEqual(len(checks), 14)
        self.assertTrue(checks["server-map-index"].default)
        self.assertFalse(checks["case-evidence"].default)
        self.assertFalse(checks["catalog-provenance"].default)

    def test_map_index_exact_names(self):
        self.index("// map name ID\nalb_ship 1\nalberta\nprontera\n")
        self.cache("alberta", "prontera")
        result = scan(server=self.server, only=["server-map-index"])
        self.assertEqual(self.codes(result), ["MAP_INDEX_COMPARE_COMPLETE"])

    def test_missing_index_is_not_error(self):
        self.cache("custom01")
        result = scan(server=self.server, only=["server-map-index"])
        self.assertEqual(self.codes(result), [])

    def test_missing_cache_is_not_error(self):
        self.index("alberta\n")
        result = scan(server=self.server, only=["server-map-index"])
        self.assertEqual(self.codes(result), [])

    def test_extra_index_maps_not_reported(self):
        self.index("alberta\nprontera\nunloaded_map\n")
        self.cache("alberta")
        result = scan(server=self.server, only=["server-map-index"])
        self.assertNotIn("MAP_INDEX_CACHE_ONLY_NAMES", self.codes(result))

    def test_custom_import_index_accepted(self):
        self.index("alberta\n")
        self.index("custom01 1005\n", rel="db/import/map_index.txt")
        self.cache("custom01")
        result = scan(server=self.server, only=["server-map-index"])
        self.assertNotIn("MAP_INDEX_CACHE_ONLY_NAMES", self.codes(result))

    def test_missing_map_index_only_info(self):
        self.index("alberta\n")
        self.cache("custom01")
        result = scan(server=self.server, only=["server-map-index"])
        self.assertIn("MAP_INDEX_CACHE_ONLY_NAMES", self.codes(result))
        self.assertEqual(result.summary()["error"], 0)
        self.assertEqual(result.summary()["warning"], 0)
        self.assertNotIn("custom01", render_json(result))

    def test_full_length_truncated_prefix_advisory(self):
        self.index("abcdefghijklMN\n")
        self.cache("abcdefghijkl")
        result = scan(server=self.server, only=["server-map-index"])
        self.assertIn("MAP_INDEX_TRUNCATED_PREFIX", self.codes(result))
        self.assertNotIn("MAP_INDEX_CACHE_ONLY_NAMES", self.codes(result))

    def test_exact_12_char_name_is_still_match(self):
        self.index("abcdefghijkl\n")
        self.cache("abcdefghijkl")
        result = scan(server=self.server, only=["server-map-index"])
        self.assertNotIn("MAP_INDEX_TRUNCATED_PREFIX", self.codes(result))

    def test_map_index_bad_lines_handled_without_crash(self):
        self.index("// header\nalberta\ninvalid ignored words\nprontera 17\n")
        self.cache("prontera")
        result = scan(server=self.server, only=["server-map-index"])
        self.assertIn("MAP_INDEX_PARTIAL", self.codes(result))
        self.assertIn("MAP_INDEX_COMPARE_COMPLETE", self.codes(result))

    def test_map_index_duplicate_name_info(self):
        self.index("alberta\n")
        self.index("alberta\n", rel="db/import/map_index.txt")
        self.cache("alberta")
        result = scan(server=self.server, only=["server-map-index"])
        self.assertIn("MAP_INDEX_DUPLICATE_NAME", self.codes(result))

    def test_oversized_map_index_bounded(self):
        self.index("a" * (2*1024*1024+1))
        self.cache("alberta")
        result = scan(server=self.server, only=["server-map-index"])
        self.assertIn("MAP_INDEX_UNREADABLE", self.codes(result))

    def test_corrupt_cache_is_not_compared(self):
        self.index("alberta\n")
        self.write(self.server, "db/re/map_cache.dat", b"corrupt")
        result = scan(server=self.server, only=["server-map-index"])
        self.assertIn("MAP_INDEX_CACHE_SKIPPED", self.codes(result))
        self.assertNotIn("MAP_INDEX_CACHE_ONLY_NAMES", self.codes(result))

    def test_case_exact_hash_pair_reports_not_certifies(self):
        path = self.case()
        result = scan(client=self.client, case_file=path,
                      server_build_sha256=self.sha_server, only=["case-evidence"])
        self.assertEqual(self.codes(result), ["CASE_REPORTED_PASS"])
        self.assertIn("not independently verified", render_json(result))

    def test_case_hash_pair_mismatch(self):
        path = self.case(server_build_sha256="f"*64)
        result = scan(client=self.client, case_file=path,
                      server_build_sha256=self.sha_server, only=["case-evidence"])
        self.assertEqual(self.codes(result), ["CASE_HASH_PAIR_MISMATCH"])

    def test_case_pass_without_log_rejected(self):
        path = self.case(log_sha256=None)
        with self.assertRaisesRegex(CaseError, "requires log"):
            read_case(path)

    def test_case_unverified_without_log_allowed(self):
        path = self.case(status="unverified", log_sha256=None)
        result = scan(client=self.client, case_file=path,
                      server_build_sha256=self.sha_server, only=["case-evidence"])
        self.assertEqual(self.codes(result), ["CASE_UNVERIFIED"])

    def test_case_future_dated(self):
        path = self.case(observed_at="2099-01-01")
        result = scan(client=self.client, case_file=path,
                      server_build_sha256=self.sha_server, only=["case-evidence"])
        self.assertEqual(self.codes(result), ["CASE_FUTURE_DATED"])

    def test_case_source_http_disallowed(self):
        path = self.case(source_url="http://localhost/")
        with self.assertRaises(CaseError):
            read_case(path)

    def test_case_unknown_keys_rejected(self):
        path = self.case(unexpected="secret")
        with self.assertRaisesRegex(CaseError, "schema"):
            read_case(path)

    def test_case_nonstring_status_safe_failure(self):
        path = self.case(status=["pass"])
        result = scan(client=self.client, case_file=path,
                      server_build_sha256=self.sha_server, only=["case-evidence"])
        self.assertEqual(self.codes(result), ["CASE_VALIDATION_FAILED"])

    def test_case_oversize_rejected(self):
        path = self.case()
        path.write_bytes(b"x" * (65 * 1024))
        with self.assertRaises(CaseError):
            read_case(path)

    def test_case_vs_catalog_disagreement(self):
        case = self.case(status="fail")
        catalog = self.catalog([self.record(status="pass")])
        result = scan(client=self.client, case_file=case, catalog_path=catalog,
                      server_build_sha256=self.sha_server,
                      only=["case-evidence"])
        self.assertEqual(self.codes(result),
                         ["CASE_REPORTED_FAIL", "CASE_CATALOG_DISAGREEMENT"])

    def test_case_vs_catalog_agree(self):
        case = self.case()
        catalog = self.catalog([self.record(status="pass")])
        result = scan(client=self.client, case_file=case, catalog_path=catalog,
                      server_build_sha256=self.sha_server,
                      only=["case-evidence"])
        self.assertEqual(self.codes(result), ["CASE_REPORTED_PASS"])

    def test_case_logs_are_not_read_or_executed(self):
        path = self.case()
        with patch("subprocess.run", side_effect=AssertionError("execute")), \
             patch("socket.socket", side_effect=AssertionError("network")):
            result = scan(client=self.client, case_file=path,
                          server_build_sha256=self.sha_server,
                          only=["case-evidence"])
        self.assertIn("CASE_REPORTED_PASS", self.codes(result))

    def test_catalog_sha_provenance_summary(self):
        path = self.catalog([self.record()])
        result = scan(client=self.client, catalog_path=path,
                      server_build_sha256=self.sha_server,
                      only=["catalog-provenance"])
        self.assertEqual(self.codes(result), ["CATALOG_PROVENANCE_SUMMARY"])
        self.assertIn(hashlib.sha256(path.read_bytes()).hexdigest(),
                      result.findings[0].message)

    def test_catalog_global_conflict_audit(self):
        path = self.catalog([self.record("pass"), self.record("fail")])
        result = scan(client=self.client, catalog_path=path,
                      server_build_sha256=self.sha_server,
                      only=["catalog-provenance"])
        self.assertIn("CATALOG_PROVENANCE_CONFLICT", self.codes(result))

    def test_catalog_global_future_date(self):
        one = self.record("pass")
        one["evidence"]["observed_at"] = "2099-01-01"
        path = self.catalog([one])
        result = scan(client=self.client, catalog_path=path,
                      server_build_sha256=self.sha_server,
                      only=["catalog-provenance"])
        self.assertIn("CATALOG_PROVENANCE_FUTURE", self.codes(result))

    def test_catalog_repeated_claims_notice(self):
        path = self.catalog([self.record(), self.record()])
        result = scan(client=self.client, catalog_path=path,
                      server_build_sha256=self.sha_server,
                      only=["catalog-provenance"])
        self.assertIn("CATALOG_PROVENANCE_REPEATED", self.codes(result))

    def test_catalog_audit_invalid_has_no_path_leaks(self):
        path = self.root / "catalog-secret.json"
        path.write_bytes(b"{not-json")
        result = scan(client=self.client, catalog_path=path,
                      server_build_sha256=self.sha_server,
                      only=["catalog-provenance"])
        self.assertIn("CATALOG_AUDIT_UNAVAILABLE", self.codes(result))
        self.assertNotIn(str(self.root), render_json(result))

    def test_cli_case_e2e(self):
        path = self.case()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--client", str(self.client), "--case-file", str(path),
                         "--server-build-sha256", self.sha_server,
                         "--only-check", "case-evidence", "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["findings"][0]["code"],
                         "CASE_REPORTED_PASS")

    def test_cli_case_requires_server_hash(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as err:
                main(["--client", str(self.client), "--case-file", str(self.case())])
        self.assertEqual(err.exception.code, 2)

    def test_cli_case_inside_root_forbidden(self):
        path = self.client / "case.json"
        path.write_text(self.case().read_text(encoding="utf8"), encoding="utf8")
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as err:
                main(["--client", str(self.client), "--case-file", str(path),
                      "--server-build-sha256", self.sha_server])
        self.assertEqual(err.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
