"""M4: bound, adversarial tests for opt-in logs and map-index providers.

All test inputs are synthetic. No rAthena/Gravity file or executable is bundled.
"""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import random
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

from rodoctor.cli import main
from rodoctor.mapcache import inspect_cache
from rodoctor.mapindex import normalize_extra_index
from rodoctor.scan import scan
from rodoctor.render import render_json


def tiny_cache(names):
    body = b""
    for name in names:
        zipdata = zlib.compress(b"\x00\x00\x00\x00")
        body += struct.pack("<12shhi", name.encode("ascii").ljust(12, b"\0"),
                            2, 2, len(zipdata)) + zipdata
    return struct.pack("<IH", 8 + len(body), len(names)) + b"\0\0" + body


class M4Tests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.client = self.base / "client"
        self.server = self.base / "server"
        self.client.mkdir()
        self.server.mkdir()
        self.exe = self.client / "Ragexe.exe"
        self.exe.write_bytes(b"MZsynthetic-client")
        self.server_sha = "c" * 64
        self.log = self.base / "session.log"
        self.log.write_bytes(b"synthetic login session\nresult=pass\n")
        self.case = self.base / "testcase.json"
        self.make_case()

    def file(self, root, name, contents):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents if isinstance(contents, bytes) else contents.encode())
        return path

    def make_case(self, **updates):
        data = {
            "schema_version": "1",
            "case_id": "synthetic-login-01",
            "scenario": "login-handshake",
            "client_sha256": hashlib.sha256(self.exe.read_bytes()).hexdigest(),
            "server_build_sha256": self.server_sha,
            "status": "pass",
            "observed_at": "2026-11-21",
            "runner": "athena-testlab/0.1",
            "log_sha256": hashlib.sha256(self.log.read_bytes()).hexdigest(),
            "source_url": "https://github.com/example/qa/1",
        }
        data.update(updates)
        self.case.write_text(json.dumps(data), encoding="utf-8")
        return self.case

    def check(self, **overrides):
        inputs = dict(client=self.client, case_file=self.case,
                      case_log=self.log, server_build_sha256=self.server_sha,
                      only=["case-evidence"])
        inputs.update(overrides)
        return scan(**inputs)

    @staticmethod
    def codes(report):
        return [f.code for f in report.findings]

    def test_valid_log_checksum_and_claim_are_separate(self):
        result = self.check()
        self.assertEqual(self.codes(result),
                         ["CASE_LOG_SHA256_MATCH", "CASE_REPORTED_PASS"])
        self.assertIn("not verified", render_json(result))
        self.assertEqual(result.summary()["error"], 0)

    def test_log_mismatch_prevents_pass_claim(self):
        self.log.write_bytes(b"tampered")
        result = self.check()
        self.assertEqual(self.codes(result), ["CASE_LOG_SHA256_MISMATCH"])
        self.assertNotIn("CASE_REPORTED_PASS", render_json(result))

    def test_log_missing_prevents_pass_claim(self):
        self.log.unlink()
        result = self.check()
        self.assertEqual(self.codes(result), ["CASE_LOG_UNREADABLE"])

    def test_log_with_no_declared_hash_rejected(self):
        self.make_case(status="unverified", log_sha256=None)
        result = self.check()
        self.assertEqual(self.codes(result), ["CASE_LOG_HASH_UNDECLARED"])

    def test_log_exceeds_limit_without_reading(self):
        from rodoctor import logverify
        with patch.object(logverify, "MAX_LOG_BYTES", 4):
            result = self.check()
        self.assertEqual(self.codes(result), ["CASE_LOG_TOO_LARGE"])

    def test_log_equality_never_proves_runtime_pass(self):
        before = self.log.read_bytes()
        with patch("subprocess.run", side_effect=AssertionError("run")), \
             patch("socket.socket", side_effect=AssertionError("network")):
            result = self.check()
        self.assertIn("CASE_LOG_SHA256_MATCH", self.codes(result))
        self.assertEqual(self.log.read_bytes(), before)

    def test_case_hash_mismatch_prevents_log_verification(self):
        self.make_case(client_sha256="f" * 64)
        result = self.check()
        self.assertEqual(self.codes(result), ["CASE_HASH_PAIR_MISMATCH"])

    def test_case_future_date_prevents_log_verification(self):
        self.make_case(observed_at="2099-01-01")
        result = self.check()
        self.assertEqual(self.codes(result), ["CASE_FUTURE_DATED"])

    def test_legacy_case_without_log_preserves_previous_behavior(self):
        result = self.check(case_log=None)
        self.assertEqual(self.codes(result), ["CASE_REPORTED_PASS"])
        self.assertIn("not independently verified", render_json(result))

    def test_cli_argv_provides_log_verification(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["--client", str(self.client), "--case-file", str(self.case),
                         "--case-log", str(self.log), "--server-build-sha256",
                         self.server_sha, "--only-check", "case-evidence",
                         "--format", "json"])
        self.assertEqual(code, 0)
        codes = [f["code"] for f in json.loads(out.getvalue())["findings"]]
        self.assertEqual(codes, ["CASE_LOG_SHA256_MATCH", "CASE_REPORTED_PASS"])

    def test_cli_rejects_log_without_case_file(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as err:
                main(["--client", str(self.client), "--case-log", str(self.log)])
        self.assertEqual(err.exception.code, 2)

    def test_cli_rejects_log_inside_scanned_client_root(self):
        inside = self.file(self.client, "case.log", b"secret")
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as err:
                main(["--client", str(self.client), "--case-file", str(self.case),
                      "--case-log", str(inside),
                      "--server-build-sha256", self.server_sha])
        self.assertEqual(err.exception.code, 2)

    def test_cli_mismatch_returns_warning_failure_when_configured(self):
        self.log.write_bytes(b"changed")
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["--client", str(self.client), "--case-file", str(self.case),
                         "--case-log", str(self.log), "--server-build-sha256",
                         self.server_sha, "--only-check", "case-evidence",
                         "--fail-on", "warning"])
        self.assertEqual(code, 1)

    def test_map_index_provider_explicit_relative_file(self):
        self.file(self.server, "db/re/map_cache.dat", tiny_cache(["custom1"]))
        self.file(self.server, "conf/maps/my-index.txt", "custom1 10001\n")
        result = scan(server=self.server, only=["server-map-index"],
                      map_indices=("conf/maps/my-index.txt",))
        self.assertEqual(self.codes(result), ["MAP_INDEX_COMPARE_COMPLETE"])

    def test_map_index_provider_works_with_backslashes(self):
        self.file(self.server, "db/re/map_cache.dat", tiny_cache(["custom1"]))
        self.file(self.server, "conf/maps/my-index.txt", "custom1\n")
        result = scan(server=self.server, only=["server-map-index"],
                      map_indices=(r"conf\maps\my-index.txt",))
        self.assertNotIn("MAP_INDEX_CACHE_ONLY_NAMES", self.codes(result))

    def test_map_index_provider_adds_to_default_not_replaces(self):
        self.file(self.server, "db/re/map_cache.dat", tiny_cache(["alberta", "custom1"]))
        self.file(self.server, "db/map_index.txt", "alberta\n")
        self.file(self.server, "conf/custom-index.txt", "custom1\n")
        result = scan(server=self.server, only=["server-map-index"],
                      map_indices=("conf/custom-index.txt",))
        self.assertNotIn("MAP_INDEX_CACHE_ONLY_NAMES", self.codes(result))

    def test_map_index_provider_rejects_traversal(self):
        self.file(self.server, "db/re/map_cache.dat", tiny_cache(["alberta"]))
        result = scan(server=self.server, only=["server-map-index"],
                      map_indices=("../secrets.txt",))
        self.assertEqual(self.codes(result), ["MAP_INDEX_PROVIDER_REJECTED"])

    def test_map_index_provider_rejects_missing_explicit(self):
        self.file(self.server, "db/re/map_cache.dat", tiny_cache(["alberta"]))
        result = scan(server=self.server, only=["server-map-index"],
                      map_indices=("conf/missing.txt",))
        self.assertEqual(self.codes(result), ["MAP_INDEX_PROVIDER_REJECTED"])

    def test_map_index_provider_rejects_17_entries(self):
        result = scan(server=self.server, only=["server-map-index"],
                      map_indices=tuple(f"conf/{i}.txt" for i in range(17)))
        self.assertEqual(self.codes(result), ["MAP_INDEX_PROVIDER_REJECTED"])

    def test_normalizer_adversarial_path_corpus(self):
        bad = ("../secret.txt", r"..\secret.txt", "/abs/index.txt",
               r"C:\abs\map_index.txt", "conf//index.txt", "conf/./index.txt",
               "conf/../index.txt", "", "file.json", "name\x00.txt",
               "a" * 260 + ".txt")
        for value in bad:
            with self.subTest(value=value):
                self.assertIsNone(normalize_extra_index(value))

    def test_cli_provider_requires_server(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as err:
                main(["--client", str(self.client), "--map-index", "other.txt"])
        self.assertEqual(err.exception.code, 2)

    def test_cli_provider_rejects_traversal(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as err:
                main(["--server", str(self.server), "--map-index", "../outside.txt"])
        self.assertEqual(err.exception.code, 2)

    def test_cli_provider_end_to_end(self):
        self.file(self.server, "db/re/map_cache.dat", tiny_cache(["custom1"]))
        self.file(self.server, "conf/custom.txt", "custom1\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["--server", str(self.server), "--map-index",
                         "conf/custom.txt", "--only-check",
                         "server-map-index", "--format", "json"])
        self.assertEqual(code, 0)
        codes = [f["code"] for f in json.loads(out.getvalue())["findings"]]
        self.assertEqual(codes, ["MAP_INDEX_COMPARE_COMPLETE"])

    def test_fuzz_bounded_mapcache_never_mutates_or_crashes(self):
        rng = random.Random(0xD0C70A)
        for i in range(250):
            amount = rng.randrange(0, 256)
            data = rng.randbytes(amount)
            path = self.file(self.server, "db/map_cache.dat", data)
            before = hashlib.sha256(data).hexdigest()
            inspected = inspect_cache(path, deep=(i % 7 == 0))
            self.assertIn(inspected.layout, (6, 8))
            self.assertEqual(inspected.actual_size, amount)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)

    def test_fuzz_nonstring_catalog_and_case_not_leaked(self):
        for status in ([], {}, None, 1, True, ["pass"], {"pass": 1}):
            self.make_case(status=status)
            result = self.check(case_log=None)
            self.assertEqual(self.codes(result), ["CASE_VALIDATION_FAILED"])
            self.assertNotIn(str(self.base), render_json(result))


if __name__ == "__main__":
    unittest.main()
