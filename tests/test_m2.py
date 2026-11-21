"""M2 mapcache and catalog regressions with synthetic assets only."""
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

from rodoctor.catalog import _load_records
from rodoctor.cli import main
from rodoctor.mapcache import inspect_cache
from rodoctor.model import Report
from rodoctor.render import render_json
from rodoctor.scan import build_registry, scan


def cache_payload(records, *, layout=8, header_count=None, header_size=None):
    """Generate minimal valid mapcache bytes, no copyrighted assets."""
    body = bytearray()
    for name, width, height, raw in records:
        compressed = zlib.compress(raw)
        body += struct.pack("<12shhi", name.encode("ascii")[:12].ljust(12, b"\0"),
                            width, height, len(compressed)) + compressed
    total = layout + len(body)
    header = struct.pack("<IH", header_size if header_size is not None else total,
                         header_count if header_count is not None else len(records))
    return header + (b"\0\0" if layout == 8 else b"") + bytes(body)


GOOD = [("alberta", 2, 2, b"\0\1\2\3"), ("prontera", 3, 2, b"\1" * 6)]


class M2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.server = self.base / "server"
        self.client = self.base / "client"
        self.server.mkdir()
        self.client.mkdir()

    def cache(self, data):
        target = self.server / "db" / "re" / "map_cache.dat"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target

    def exe(self, name="2026-02-19_Ragexe.exe", data=b"MZexample"):
        path = self.client / name
        path.write_bytes(data)
        return path

    def make_catalog(self, records):
        path = self.base / "evidence.json"
        path.write_text(json.dumps({"schema_version": "1", "records": records}),
                        encoding="utf-8")
        return path

    def record(self, client_hash, server_hash, status="pass",
               source_url="https://github.com/example/evidence/issues/1"):
        return {
            "client_sha256": client_hash,
            "server_build_sha256": server_hash,
            "status": status,
            "evidence": {
                "observed_at": "2026-11-21",
                "method": "isolated-login-test",
                "source_url": source_url,
            },
        }

    def codes(self, result):
        return [x.code for x in result.findings]

    def test_registry_adds_three_m2_detectors(self):
        all_checks = {c.id: c for c in build_registry().available()}
        self.assertEqual(len(all_checks), 11)
        self.assertFalse(all_checks["server-mapcache-deep"].default)
        self.assertFalse(all_checks["catalog-evidence"].default)
        self.assertTrue(all_checks["server-mapcache-structure"].default)

    def test_binary_aligned_header_real_world_layout(self):
        result = inspect_cache(self.cache(cache_payload(GOOD, layout=8)))
        self.assertTrue(result.ok)
        self.assertEqual(result.layout, 8)
        self.assertEqual(result.parsed_maps, 2)
        self.assertEqual(result.total_offset, result.actual_size)

    def test_documented_six_byte_layout(self):
        result = inspect_cache(self.cache(cache_payload(GOOD, layout=6)))
        self.assertTrue(result.ok)
        self.assertEqual(result.layout, 6)
        self.assertIn("MAPCACHE_LEGACY_HEADER",
                      self.codes(scan(server=self.server,
                                      only=["server-mapcache-structure"])))

    def test_structure_detector(self):
        self.cache(cache_payload(GOOD))
        result = scan(server=self.server, only=["server-mapcache-structure"])
        self.assertEqual(self.codes(result), ["MAPCACHE_STRUCTURE_VALID"])

    def test_deep_zlib_success(self):
        result = inspect_cache(self.cache(cache_payload(GOOD)), deep=True)
        self.assertTrue(result.ok)
        self.assertEqual(result.validated_payloads, 2)
        self.assertIn("MAPCACHE_ZLIB_VALIDATED",
                      self.codes(scan(server=self.server,
                                      only=["server-mapcache-deep"])))

    def test_mismatch_declared_size(self):
        data = cache_payload(GOOD, header_size=42)
        result = inspect_cache(self.cache(data))
        self.assertIn("advertised-size-mismatch", result.errors)
        self.assertIn("MAPCACHE_STRUCTURE_INVALID",
                      self.codes(scan(server=self.server,
                                      only=["server-mapcache-structure"])))

    def test_mismatch_declared_count(self):
        result = inspect_cache(self.cache(cache_payload(GOOD, header_count=1)))
        self.assertIn("unaccounted-trailing-data", result.errors)

    def test_corrupted_huge_count_safety_limit(self):
        result = inspect_cache(self.cache(cache_payload(GOOD, header_count=65000)))
        self.assertIn("map-count-limit", result.errors)

    def test_truncated_entry_header(self):
        data = cache_payload(GOOD)
        result = inspect_cache(self.cache(data[:8+15]))
        self.assertFalse(result.ok)

    def test_truncated_payload(self):
        data = cache_payload(GOOD)
        result = inspect_cache(self.cache(data[:-3]))
        self.assertFalse(result.ok)
        self.assertIn("MAPCACHE_STRUCTURE_INVALID",
                      self.codes(scan(server=self.server,
                                      only=["server-mapcache-structure"])))

    def test_bad_dimensions(self):
        result = inspect_cache(self.cache(cache_payload([("badmap", 0, 2, b"")])) )
        self.assertIn("invalid-map-dimensions", result.errors)

    def test_duplicate_map_names_advisory(self):
        data = cache_payload([GOOD[0], ("ALBERTA", 2, 2, b"\0\1\2\3")])
        self.cache(data)
        result = scan(server=self.server, only=["server-mapcache-structure"])
        self.assertIn("MAPCACHE_DUPLICATE_MAP_NAMES", self.codes(result))

    def test_zlib_corruption_detected_only_deep(self):
        data = bytearray(cache_payload(GOOD))
        payload_start = 8 + 20
        data[payload_start+3] ^= 0xFF
        path = self.cache(bytes(data))
        self.assertTrue(inspect_cache(path).ok)
        result = inspect_cache(path, deep=True)
        self.assertIn("entry-zlib-invalid", result.errors)

    def test_deep_output_bomb_is_bounded_by_dimensions(self):
        data = bytearray(cache_payload(GOOD))
        # zlib expands beyond declared 2x2 cells
        payload = zlib.compress(b"x" * 50000)
        data = struct.pack("<IH", 8+20+len(payload), 1) + b"\0\0"
        data += struct.pack("<12shhi", b"tiny\0\0\0\0\0\0\0\0", 2, 2, len(payload))
        data += payload
        result = inspect_cache(self.cache(data), deep=True)
        self.assertIn("entry-zlib-invalid", result.errors)

    def test_empty_file_reports_error_no_exception(self):
        result = scan(server=self.server, only=["server-mapcache-structure"])
        self.assertEqual(self.codes(result), [])
        self.cache(b"")
        result = scan(server=self.server, only=["server-mapcache-structure"])
        self.assertIn("MAPCACHE_STRUCTURE_INVALID", self.codes(result))

    def test_no_network_or_mutation_on_binary_check(self):
        original = cache_payload(GOOD)
        path = self.cache(original)
        with patch("socket.socket", side_effect=AssertionError("network")):
            result = scan(server=self.server, only=["server-mapcache-deep"])
        self.assertIn("MAPCACHE_ZLIB_VALIDATED", self.codes(result))
        self.assertEqual(path.read_bytes(), original)

    def test_catalog_match_pass_is_not_runtime_certification(self):
        exe = self.exe()
        client_hash = hashlib.sha256(exe.read_bytes()).hexdigest()
        server_hash = "a" * 64
        path = self.make_catalog([self.record(client_hash, server_hash)])
        result = scan(client=self.client, catalog_path=path,
                      server_build_sha256=server_hash)
        self.assertIn("CATALOG_REPORTED_PASS", self.codes(result))
        self.assertIn("not an independent runtime test", render_json(result))

    def test_catalog_match_fail_warns(self):
        exe = self.exe()
        catalog = self.make_catalog([self.record(
            hashlib.sha256(exe.read_bytes()).hexdigest(), "b"*64, "fail")])
        result = scan(client=self.client, catalog_path=catalog,
                      server_build_sha256="b"*64, only=["catalog-evidence"])
        self.assertEqual(self.codes(result), ["CATALOG_REPORTED_FAIL"])
        self.assertEqual(result.summary()["warning"], 1)

    def test_catalog_unverified_does_not_claim_pass(self):
        exe = self.exe()
        path = self.make_catalog([self.record(
            hashlib.sha256(exe.read_bytes()).hexdigest(), "f"*64, "unverified")])
        result = scan(client=self.client, catalog_path=path,
                      server_build_sha256="f"*64, only=["catalog-evidence"])
        self.assertEqual(self.codes(result), ["CATALOG_UNVERIFIED"])

    def test_catalog_pair_missing(self):
        self.exe()
        path = self.make_catalog([])
        result = scan(client=self.client, catalog_path=path,
                      server_build_sha256="0"*64, only=["catalog-evidence"])
        self.assertEqual(self.codes(result), ["CATALOG_EXACT_PAIR_UNKNOWN"])

    def test_catalog_conflicting_evidence(self):
        exe = self.exe()
        hash_value = hashlib.sha256(exe.read_bytes()).hexdigest()
        path = self.make_catalog([self.record(hash_value, "1"*64, "pass"),
                                  self.record(hash_value, "1"*64, "fail")])
        result = scan(client=self.client, catalog_path=path,
                      server_build_sha256="1"*64, only=["catalog-evidence"])
        self.assertEqual(self.codes(result), ["CATALOG_CONFLICT"])

    def test_catalog_invalid_sha_safe_diagnostic(self):
        self.exe()
        path = self.make_catalog([self.record("bad", "1"*64)])
        result = scan(client=self.client, catalog_path=path,
                      server_build_sha256="1"*64, only=["catalog-evidence"])
        self.assertEqual(self.codes(result), ["CATALOG_VALIDATION_FAILED"])

    def test_catalog_refuses_non_https(self):
        path = self.make_catalog([self.record(
            "a"*64, "b"*64, source_url="http://localhost/internal")])
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            _load_records(path)

    def test_catalog_missing_evidence_rejected(self):
        path = self.make_catalog([{"client_sha256": "a"*64,
                                   "server_build_sha256": "b"*64,
                                   "status": "pass"}])
        with self.assertRaises(ValueError):
            _load_records(path)

    def test_catalog_large_rejected(self):
        path = self.base / "big.json"
        path.write_bytes(b"a" * (513*1024))
        with self.assertRaisesRegex(ValueError, "512 KiB"):
            _load_records(path)

    def test_catalog_explicit_exe_selection(self):
        a = self.exe("Ragexe.exe", b"MZa")
        self.exe("Ragnarok.exe", b"MZb")
        path = self.make_catalog([self.record(
            hashlib.sha256(a.read_bytes()).hexdigest(), "e"*64)])
        ambiguous = scan(client=self.client, catalog_path=path,
                         server_build_sha256="e"*64, only=["catalog-evidence"])
        self.assertEqual(self.codes(ambiguous), ["CATALOG_CLIENT_AMBIGUOUS"])
        selected = scan(client=self.client, catalog_path=path,
                        server_build_sha256="e"*64, client_exe="Ragexe.exe",
                        only=["catalog-evidence"])
        self.assertEqual(self.codes(selected), ["CATALOG_REPORTED_PASS"])

    def test_catalog_client_exe_traversal_rejected(self):
        self.exe()
        path = self.make_catalog([])
        result = scan(client=self.client, catalog_path=path,
                      server_build_sha256="a"*64, client_exe="../secret.exe",
                      only=["catalog-evidence"])
        self.assertEqual(self.codes(result), ["CATALOG_VALIDATION_FAILED"])
        self.assertNotIn("secret.exe", render_json(result))

    def test_catalog_does_not_read_url_or_run_executable(self):
        self.exe()
        path = self.make_catalog([])
        with patch("socket.socket", side_effect=AssertionError("network")), \
             patch("subprocess.run", side_effect=AssertionError("execute")):
            result = scan(client=self.client, catalog_path=path,
                          server_build_sha256="a"*64,
                          only=["catalog-evidence"])
        self.assertIn("CATALOG_EXACT_PAIR_UNKNOWN", self.codes(result))

    def test_cli_rejects_missing_catalog_companion_args(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                main(["--client", str(self.client), "--catalog", str(self.base/"x")])
        self.assertEqual(error.exception.code, 2)

    def test_cli_rejects_catalog_inside_scanned_folder(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                main(["--client", str(self.client), "--catalog", str(self.client/"test.json"),
                      "--server-build-sha256", "a"*64])
        self.assertEqual(error.exception.code, 2)

    def test_cli_catalog_end_to_end_json(self):
        exe = self.exe()
        path = self.make_catalog([self.record(
            hashlib.sha256(exe.read_bytes()).hexdigest(), "c"*64)])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main(["--client", str(self.client), "--catalog", str(path),
                              "--server-build-sha256", "c"*64,
                              "--only-check", "catalog-evidence", "--format", "json"])
        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output.getvalue())["findings"][0]["code"],
                         "CATALOG_REPORTED_PASS")

    def test_report_does_not_leak_catalog_path(self):
        self.exe()
        catalog = self.make_catalog([])
        result = scan(client=self.client, catalog_path=catalog,
                      server_build_sha256="c"*64, only=["catalog-evidence"])
        self.assertNotIn(str(self.base), render_json(result))


if __name__ == "__main__":
    unittest.main()
