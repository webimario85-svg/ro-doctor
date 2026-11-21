import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from rodoctor.cli import main
from rodoctor.model import Report
from rodoctor.render import render_html, render_json
from rodoctor.scan import scan


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.server = self.root / "server"
        self.client = self.root / "client"
        self.server.mkdir()
        self.client.mkdir()

    def _write(self, base: Path, path: str, content: str = "") -> Path:
        file = base / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content, encoding="utf-8")
        return file

    def _codes(self, result) -> set[str]:
        return {f.code for f in result.findings}

    def test_invalid_path_does_not_crash(self):
        result = scan(server=self.root / "absent")
        self.assertIn("TARGET_NOT_DIRECTORY", self._codes(result))
        self.assertEqual(result.summary()["error"], 1)

    def test_unrecognized_server_is_warning_not_proof(self):
        result = scan(server=self.server)
        self.assertIn("SERVER_LAYOUT_UNRECOGNIZED", self._codes(result))

    def test_packetver_declaration_is_not_handshake(self):
        self._write(self.server, "src/map/map.cpp", "/* marker */")
        self._write(self.server, "src/custom/defines_pre.hpp",
                    "#define PACKETVER 20220101\n")
        result = scan(server=self.server, client=self.client)
        self.assertIn("PACKETVER_DECLARATION", self._codes(result))
        self.assertIn("PROTOCOL_NOT_VERIFIED", self._codes(result))
        self.assertNotIn("PACKETVER_MISMATCH", self._codes(result))

    def test_multiple_packetvers_are_warning(self):
        self._write(self.server, "src/custom/defines_pre.hpp",
                    "#define PACKETVER 20220101\n")
        self._write(self.server, "src/common/packets.hpp",
                    "#define PACKETVER 20230822\n")
        self.assertIn("PACKETVER_MULTIPLE", self._codes(scan(server=self.server)))

    def test_zero_byte_mapcache(self):
        self._write(self.server, "db/map_cache.dat")
        result = scan(server=self.server)
        self.assertIn("MAPCACHE_EMPTY", self._codes(result))

    def test_data_ini_grf_happy_path_case_insensitive(self):
        self._write(self.client, "Ragexe.exe", "")
        self._write(self.client, "DATA.GRF", "")
        self._write(self.client, "data.ini", "[Data]\n0=data.grf\n")
        result = scan(client=self.client)
        self.assertEqual(result.summary()["error"], 0)
        self.assertNotIn("GRF_REFERENCE_MISSING", self._codes(result))

    def test_missing_grf_in_load_order(self):
        self._write(self.client, "Ragexe.exe")
        self._write(self.client, "data.ini", "[Data]\n0=missing.grf\n")
        result = scan(client=self.client)
        self.assertIn("GRF_REFERENCE_MISSING", self._codes(result))

    def test_duplicate_grf_reference(self):
        self._write(self.client, "Ragexe.exe")
        self._write(self.client, "data.grf")
        self._write(self.client, "data.ini",
                    "[Data]\n0=data.grf\n1=DATA.GRF\n")
        self.assertIn("GRF_DUPLICATE_REFERENCE",
                      self._codes(scan(client=self.client)))

    def test_comments_and_non_data_section_ignored(self):
        self._write(self.client, "data.grf")
        self._write(self.client, "data.ini",
                    "[Other]\n0=notexist.grf\n[Data]\n; comment\n0=data.grf\n")
        self.assertNotIn("GRF_REFERENCE_MISSING",
                         self._codes(scan(client=self.client)))

    def test_utf16_data_ini(self):
        self._write(self.client, "data.grf")
        (self.client / "data.ini").write_text("[Data]\n0=data.grf\n",
                                               encoding="utf-16")
        self.assertNotIn("DATA_INI_NO_ENTRIES",
                         self._codes(scan(client=self.client)))

    def test_report_never_emits_root_absolute_path(self):
        self._write(self.client, "data.ini", "[Data]\n0=missing.grf\n")
        result = scan(client=self.client)
        self.assertNotIn(str(self.root), render_json(result))
        self.assertNotIn(str(self.root), render_html(result))

    def test_html_escapes_untrusted_values(self):
        report = Report()
        report.add("TEST", "error", "client", "<script>alert(1)</script>",
                   "Don't run this")
        html = render_html(report)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>", html)

    def test_cli_json_exit_code(self):
        self._write(self.client, "data.ini", "[Data]\n0=absent.grf\n")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--client", str(self.client), "--format", "json"])
        self.assertEqual(code, 1)
        data = json.loads(output.getvalue())
        self.assertEqual(data["schema_version"], "1")
        self.assertTrue(any(f["code"] == "GRF_REFERENCE_MISSING"
                            for f in data["findings"]))

    def test_cli_fail_on_never(self):
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["--server", str(self.server), "--fail-on", "never"])
        self.assertEqual(code, 0)

    def test_cli_reject_output_inside_target(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                main(["--server", str(self.server), "--output",
                      str(self.server / "report.html")])
        self.assertEqual(caught.exception.code, 2)

    def test_scanning_does_not_mutate_input(self):
        ini = self._write(self.client, "data.ini", "[Data]\n0=missing.grf\n")
        before = ini.read_bytes()
        scan(client=self.client)
        self.assertEqual(ini.read_bytes(), before)

    def test_oversized_mapcache_uses_warning_not_corruption_verdict(self):
        from unittest.mock import patch
        self._write(self.server, "db/map_cache.dat", "x" * 20)
        with patch("rodoctor.scan.SUSPICIOUS_MAPCACHE_BYTES", 10):
            result = scan(server=self.server)
        self.assertIn("MAPCACHE_UNUSUALLY_LARGE", self._codes(result))
        self.assertNotIn("MAPCACHE_EMPTY", self._codes(result))

    def test_invalid_relative_reference_never_leaks_source_path(self):
        self._write(self.client, "data.ini",
                    "[Data]\n0=../../secret-token.grf\n1=../../secret-token.grf\n")
        result = scan(client=self.client)
        rendered = render_json(result)
        self.assertIn("GRF_REFERENCE_INVALID", self._codes(result))
        self.assertNotIn("secret-token", rendered)

    def test_commented_packetver_does_not_count(self):
        self._write(self.server, "src/custom/defines_pre.hpp",
                    "/*\n#define PACKETVER 20200101\n*/\n"
                    "// #define PACKETVER 20210101\n")
        self.assertNotIn("PACKETVER_DECLARATION",
                         self._codes(scan(server=self.server)))

    def test_cli_report_written_outside_target(self):
        self._write(self.client, "data.ini", "[Data]\n0=missing.grf\n")
        report_file = self.root / "result.json"
        with contextlib.redirect_stdout(io.StringIO()):
            status = main(["--client", str(self.client), "--format", "json",
                           "--output", str(report_file)])
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(report_file.read_text(encoding="utf-8"))
                         ["summary"]["error"], 1)


if __name__ == "__main__":
    unittest.main()
