"""M1 regression checks: synthetic fixtures only, no game files required."""
import contextlib
import hashlib
import io
import json
import struct
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

from rodoctor.checks import Check, Registry
from rodoctor.cli import main
from rodoctor.model import Report
from rodoctor.render import render_json
from rodoctor.scan import build_registry, scan


class M1Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.server = self.base / "rathena"
        self.client = self.base / "client"
        self.server.mkdir()
        self.client.mkdir()

    def put(self, root, rel, data: str | bytes = ""):
        p = root / rel
        p.parent.mkdir(exist_ok=True, parents=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        return p

    def codes(self, report):
        return [f.code for f in report.findings]

    def test_registry_has_eight_builtins_and_unique_ids(self):
        checks = build_registry().available()
        self.assertEqual(len(checks), 8)
        self.assertEqual(len({c.id for c in checks}), 8)

    def test_invalid_detector_identifier_rejected(self):
        with self.assertRaises(ValueError):
            Check("../../etc", "client", "bad", lambda s, c, r: None)
        with self.assertRaises(ValueError):
            Check("valid", "garbage", "bad", lambda s, c, r: None)

    def test_duplicate_registration_rejected(self):
        registry = Registry()
        check = Check("sample", "client", "test", lambda s, c, r: None)
        registry.register(check)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            registry.register(check)

    def test_only_and_skip_select_correct_checks(self):
        report = scan(server=self.server, client=self.client,
                      only=["protocol-evidence"])
        self.assertEqual(self.codes(report), ["PROTOCOL_NOT_VERIFIED"])
        report = scan(server=self.server, client=self.client,
                      skip=["protocol-evidence"])
        self.assertNotIn("PROTOCOL_NOT_VERIFIED", self.codes(report))

    def test_unknown_check_returns_nonzero_usage_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as err:
                main(["--client", str(self.client), "--only-check", "unknown"])
        self.assertEqual(err.exception.code, 2)

    def test_list_checks_needs_no_paths(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--list-checks"])
        self.assertEqual(code, 0)
        self.assertIn("client-grf-header", output.getvalue())
        self.assertIn("protocol-evidence", output.getvalue())

    def test_external_detector_explicit_registration(self):
        registry = Registry()
        registry.register(Check("my-check", "client", "embedded",
                                lambda s, c, r: r.add(
                                    "MY_CHECK", "info", "client", "safe", "none")))
        self.assertEqual(self.codes(scan(client=self.client, registry=registry)),
                         ["MY_CHECK"])

    def test_failure_does_not_leak_exception_content(self):
        registry = Registry()
        def bad(s, c, report):
            raise RuntimeError("PRIVATE_PASSWORD_1234")
        registry.register(Check("bad-check", "client", "bad", bad))
        result = scan(client=self.client, registry=registry)
        self.assertIn("CHECK_EXECUTION_FAILED", self.codes(result))
        self.assertNotIn("PRIVATE_PASSWORD_1234", render_json(result))

    def test_grf_valid_signature(self):
        self.put(self.client, "data.grf", b"Master of Magic" + bytes(31))
        result = scan(client=self.client, only=["client-grf-header"])
        self.assertEqual(result.summary()["warning"], 0)

    def test_grf_truncated(self):
        self.put(self.client, "data.grf", b"Master of Magic")
        result = scan(client=self.client, only=["client-grf-header"])
        self.assertIn("GRF_HEADER_TRUNCATED", self.codes(result))

    def test_grf_invalid_signature(self):
        self.put(self.client, "data.grf", b"Incorrect header" + bytes(60))
        result = scan(client=self.client, only=["client-grf-header"])
        self.assertIn("GRF_HEADER_INVALID", self.codes(result))

    def test_nested_grf_reference_header(self):
        self.put(self.client, "custom/patch.grf", b"not a grf" + bytes(60))
        self.put(self.client, "data.ini", "[Data]\n0=custom\\patch.grf\n")
        result = scan(client=self.client, only=["client-grf-header"])
        self.assertIn("GRF_HEADER_INVALID", self.codes(result))

    def test_load_order_duplicate_and_gap(self):
        self.put(self.client, "data.ini",
                 "[Data]\n0=data.grf\n0=patch.grf\n2=third.grf\n")
        result = scan(client=self.client, only=["client-load-order"])
        self.assertIn("GRF_INDEX_DUPLICATE", self.codes(result))
        self.assertIn("GRF_INDEX_GAP", self.codes(result))

    def test_load_order_contiguous_is_clean(self):
        self.put(self.client, "data.ini", "[Data]\n0=a.grf\n1=b.grf\n")
        result = scan(client=self.client, only=["client-load-order"])
        self.assertEqual(result.summary()["warning"], 0)

    def test_rathena_10098_name_only_import_advisory(self):
        self.put(self.server, "db/import/item_db.yml",
                 "Header:\n  Type: ITEM_DB\n  Version: 3\nBody:\n"
                 "  - Id: 705\n    Name: Test_Clover_Name\n")
        result = scan(server=self.server, only=["server-itemdb"])
        self.assertIn("ITEMDB_PARTIAL_OVERRIDE_REVIEW", self.codes(result))
        self.assertNotIn("Test_Clover_Name", render_json(result))
        self.assertIn("#10098", result.findings[0].recommendation)

    def test_rathena_10098_explicit_sell_zero_preserved(self):
        self.put(self.server, "db/import/item_db.yml",
                 "Body:\n  - Id: 705\n    Name: Clover\n    Sell: 0\n")
        result = scan(server=self.server, only=["server-itemdb"])
        self.assertNotIn("ITEMDB_PARTIAL_OVERRIDE_REVIEW", self.codes(result))

    def test_itemdb_bounded_reader_is_explicitly_unknown(self):
        self.put(self.server, "db/import/item_db.yml",
                 " " * (260 * 1024))
        result = scan(server=self.server, only=["server-itemdb"])
        self.assertIn("ITEMDB_IMPORT_NOT_INSPECTED", self.codes(result))

    def test_sparse_mapcache_metadata_upstream_10099(self):
        file = self.put(self.server, "db/map_cache.dat", "test")
        original = Path.stat
        def fake_stat(path, *args, **kwargs):
            value = original(path, *args, **kwargs)
            if Path(path) == file:
                return types.SimpleNamespace(
                    st_mode=stat.S_IFREG, st_size=2_600_000_000,
                    st_file_attributes=0x200, st_blocks=0)
            return value
        with patch("pathlib.Path.stat", autospec=True, side_effect=fake_stat):
            result = scan(server=self.server, only=["server-sparse-cache"])
        self.assertIn("MAPCACHE_SPARSE_FILE", self.codes(result))
        self.assertIn("#10099", result.findings[0].recommendation)

    def test_date_hints_are_not_handshake_proof(self):
        self.put(self.server, "src/custom/defines_pre.hpp",
                 "#define PACKETVER 20230101\n")
        self.put(self.client, "2026-02-19_Ragexe.exe", "")
        result = scan(server=self.server, client=self.client,
                      only=["protocol-evidence"])
        self.assertIn("CLIENT_DATE_FILENAME_EVIDENCE", self.codes(result))
        self.assertIn("PROTOCOL_DATE_HINT_DIFFERENCE", self.codes(result))
        self.assertIn("PROTOCOL_NOT_VERIFIED", self.codes(result))
        self.assertEqual(result.summary()["warning"], 0)

    def test_invalid_executable_date_ignored(self):
        self.put(self.client, "2026-99-99_Ragexe.exe", "")
        result = scan(server=self.server, client=self.client,
                      only=["protocol-evidence"])
        self.assertNotIn("CLIENT_DATE_FILENAME_EVIDENCE", self.codes(result))

    def test_deterministic_report(self):
        self.put(self.client, "data.ini", "[Data]\n0=not_here.grf\n")
        a = render_json(scan(client=self.client))
        b = render_json(scan(client=self.client))
        self.assertEqual(a, b)
        self.assertNotIn(self.tmp.name, a)

    def test_executable_hash_opt_in_and_pe_metadata(self):
        pe = bytearray(128)
        pe[:2] = b"MZ"
        struct.pack_into("<I", pe, 0x3C, 80)
        pe[80:84] = b"PE\x00\x00"
        struct.pack_into("<HHI", pe, 84, 0x14C, 3, 1_500_000_000)
        payload = bytes(pe)
        self.put(self.client, "Ragexe.exe", payload)
        default_result = scan(client=self.client)
        self.assertNotIn("CLIENT_EXE_SHA256", self.codes(default_result))
        selected = scan(client=self.client, only=["client-exe-fingerprint"])
        self.assertEqual(self.codes(selected), ["CLIENT_EXE_SHA256"])
        self.assertIn(hashlib.sha256(payload).hexdigest(), selected.findings[0].message)
        self.assertIn("machine=0x014c", selected.findings[0].message)

    def test_executable_hash_never_runs_binary(self):
        self.put(self.client, "Ragnarok.exe", b"safe")
        with patch("subprocess.run", side_effect=AssertionError("execution")):
            report = scan(client=self.client, only=["client-exe-fingerprint"])
        self.assertIn("CLIENT_EXE_SHA256", self.codes(report))

    def test_no_network_activity_during_checks(self):
        self.put(self.client, "data.ini", "[Data]\n0=missing.grf\n")
        with patch("socket.socket", side_effect=AssertionError("network")):
            report = scan(client=self.client)
        self.assertIn("GRF_REFERENCE_MISSING", self.codes(report))


if __name__ == "__main__":
    unittest.main()
