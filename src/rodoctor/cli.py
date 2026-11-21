"""RO Doctor command-line entry point."""
import argparse
from pathlib import Path
import sys

from . import __version__
from .render import render_html, render_json, render_text
from .scan import build_registry, scan

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
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    registry = build_registry()
    if args.list_checks:
        for check in registry.available():
            mode = "default" if check.default else "on-demand"
            print(f"{check.id}\t{check.target}\t{mode}\t{check.description}")
        return 0
    if args.server is None and args.client is None:
        parser.error("provide --server, --client, or both")
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
                  skip=args.skip_check, registry=registry)
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
