"""RO Doctor command-line entry point."""
import argparse
from pathlib import Path
import sys

from . import __version__
from .render import render_html, render_json, render_text
from .scan import build_registry, scan
from .mapindex import MAX_EXTRA_PATHS, normalize_extra_index

FORMATS = {"text": render_text, "json": render_json, "html": render_html}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rodoctor",
        description="Offline, read-only rAthena/Ragexe diagnostics. No network or game execution.",
    )
    parser.add_argument("--server", type=Path, help="Path to a rAthena checkout")
    parser.add_argument("--client", type=Path, help="Path to a Ragnarok client root")
    parser.add_argument("--format", choices=tuple(FORMATS), default="text")
    parser.add_argument("--output", type=Path,
                        help="Write report outside scanned directories (default: stdout)")
    parser.add_argument("--fail-on", choices=("error", "warning", "never"),
                        default="error",
                        help="Exit status 1 at or above this severity (default: error)")
    parser.add_argument("--only-check", action="append", metavar="ID",
                        help="Run only selected detector ID(s); repeat to select multiple")
    parser.add_argument("--skip-check", action="append", metavar="ID",
                        help="Exclude detector ID(s); repeat to exclude multiple")
    parser.add_argument("--list-checks", action="store_true",
                        help="Print available check IDs and exit (no scan required)")
    parser.add_argument("--catalog", type=Path,
                        help="Local evidence catalog JSON (only with --client and server hash)")
    parser.add_argument("--server-build-sha256", metavar="SHA256",
                        help="Exact SHA-256 of deployed map-server binary; user-supplied")
    parser.add_argument("--client-exe", metavar="BASENAME",
                        help="Exact Ragexe/Ragnarok executable basename when ambiguous")
    parser.add_argument("--case-file", type=Path,
                        help="Local external QA test-case JSON with exact hashes and log digest")
    parser.add_argument("--case-log", type=Path,
                        help="Opt-in local QA log to verify against --case-file log_sha256")
    parser.add_argument("--map-index", action="append", metavar="RELATIVE_TXT",
                        help="Add a custom relative map index .txt file inside --server")
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    registry = build_registry(catalog_path=args.catalog,
                              server_build_sha256=args.server_build_sha256,
                              client_exe=args.client_exe, case_file=args.case_file,
                              case_log=args.case_log,
                              map_indices=tuple(args.map_index or ()))
    if args.list_checks:
        for check in registry.available():
            mode = "default" if check.default else "on-demand"
            print(f"{check.id}\t{check.target}\t{mode}\t{check.description}")
        return 0
    if args.server is None and args.client is None:
        parser.error("provide --server, --client, or both")
    if args.case_log is not None and args.case_file is None:
        parser.error("--case-log requires --case-file")
    if args.map_index and args.server is None:
        parser.error("--map-index requires --server")
    if len(args.map_index or ()) > MAX_EXTRA_PATHS:
        parser.error(f"--map-index accepts at most {MAX_EXTRA_PATHS} entries")
    for raw in args.map_index or ():
        normalized = normalize_extra_index(raw)
        if normalized is None or not (args.server / normalized).resolve().is_relative_to(args.server.resolve()) or not (args.server / normalized).is_file():
            parser.error("--map-index must be an existing relative .txt file within --server")
    evidence_files = (("--catalog", args.catalog), ("--case-file", args.case_file),
                      ("--case-log", args.case_log))
    if any(path is not None for _, path in evidence_files):
        if args.client is None or args.server_build_sha256 is None:
            parser.error("--catalog/--case-file requires --client and --server-build-sha256")
    elif args.server_build_sha256 is not None or args.client_exe is not None:
        parser.error("--server-build-sha256 and --client-exe require --catalog or --case-file")
    for label, path in evidence_files:
        if path is None:
            continue
        source = path.resolve()
        for root in (args.server, args.client):
            if root is not None and source.is_relative_to(root.resolve()):
                parser.error(f"{label} must be outside scanned directories")
    try:
        registry.select(args.only_check, args.skip_check)
    except ValueError as exc:
        parser.error(str(exc))
    if args.output is not None:
        output = args.output.resolve()
        for root in (args.server, args.client):
            if root is not None and output.is_relative_to(root.resolve()):
                parser.error("--output must be outside scanned directories")
        if output.exists() and output.is_dir():
            parser.error("--output must be a file, not a directory")

    report = scan(args.server, args.client, only=args.only_check,
                  skip=args.skip_check, registry=registry, case_file=args.case_file,
                  case_log=args.case_log, map_indices=tuple(args.map_index or ()))
    rendered = FORMATS[args.format](report)
    if args.output is None:
        sys.stdout.write(rendered)
    else:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            print(f"Unable to write report: {exc.strerror or type(exc).__name__}",
                  file=sys.stderr)
            return 2
        print(f"Report written: {args.output.name}")
    counts = report.summary()
    if args.fail_on == "error" and counts["error"]:
        return 1
    if args.fail_on == "warning" and (counts["error"] or counts["warning"]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
