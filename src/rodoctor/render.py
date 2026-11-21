"""Deterministic local reports; no external assets or JavaScript."""
from html import escape
import json

from .model import Report


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"


def render_text(report: Report) -> str:
    data = report.to_dict()
    lines = [
        f"RO Doctor {data['version']}  |  schema {data['schema_version']}",
        "Targets: " + (", ".join(f"{k}={v}" for k, v in
                              sorted(report.targets.items())) or "(none)"),
        "Summary: " + ", ".join(f"{k}={v}" for k, v in report.summary().items()),
        "",
    ]
    for finding in report.findings:
        location = f" [{finding.path}]" if finding.path else ""
        lines.append(f"[{finding.severity.upper()}] {finding.code} / "
                     f"{finding.subject}{location}")
        lines.append(f"  {finding.message}")
        lines.append(f"  Next: {finding.recommendation}")
    return "\n".join(lines) + "\n"


def render_html(report: Report) -> str:
    data = report.to_dict()
    summary = report.summary()
    tiles = "".join(
        f"<span class='tile {escape(k)}'>{escape(k)}: {v}</span>"
        for k, v in summary.items()
    )
    findings = "".join(
        "<article><div class='heading'><span class='severity "
        + escape(f.severity) + "'>" + escape(f.severity.upper())
        + "</span> <strong>" + escape(f.code)
        + "</strong> <small>" + escape(f.subject)
        + (": " + escape(f.path) if f.path else "")
        + "</small></div><p>" + escape(f.message)
        + "</p><p class='next'>Next: " + escape(f.recommendation)
        + "</p></article>" for f in report.findings
    )
    targets = ", ".join(f"{escape(k)} = {escape(v)}"
                        for k, v in sorted(report.targets.items()))
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>RO Doctor report</title><style>"
        "body{max-width:860px;margin:40px auto;padding:0 18px;font:16px/1.6 "
        "system-ui,sans-serif;background:#111827;color:#f3f4f6}"
        "article{border:1px solid #374151;border-radius:12px;padding:12px 18px;"
        "margin:12px 0;background:#1f2937}.heading{display:flex;gap:12px;"
        "align-items:center;flex-wrap:wrap}.tile,.severity{border-radius:6px;"
        "padding:2px 9px;background:#374151;display:inline-block;margin-right:8px}"
        ".error{background:#8b2626}.warning{background:#795308}.info{background:#1e527b}"
        ".next,small{color:#d1d5db}h1{margin-bottom:4px}</style></head><body>"
        "<h1>RO Doctor</h1><p>Offline diagnostic report · version "
        + escape(data["version"]) + "</p><p>Targets: " + (targets or "none")
        + "</p><section>" + tiles + "</section><main>" + findings
        + "</main><footer><small>Static checks only. No protocol handshake or "
        "client execution was performed.</small></footer></body></html>\n"
    )
