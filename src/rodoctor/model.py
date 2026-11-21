"""Stable, serializable diagnostic results (schema v1)."""
from dataclasses import asdict, dataclass, field

from . import __version__


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    subject: str
    message: str
    recommendation: str
    path: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Report:
    targets: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def add(self, code: str, severity: str, subject: str, message: str,
            recommendation: str, path: str | None = None) -> None:
        if severity not in {"error", "warning", "info"}:
            raise ValueError("invalid severity")
        self.findings.append(Finding(code, severity, subject, message,
                                     recommendation, path))

    def summary(self) -> dict[str, int]:
        return {level: sum(f.severity == level for f in self.findings)
                for level in ("error", "warning", "info")}

    def to_dict(self) -> dict:
        return {
            "schema_version": "1",
            "tool": "ro-doctor",
            "version": __version__,
            "targets": self.targets,
            "summary": self.summary(),
            "findings": [finding.to_dict() for finding in self.findings],
        }
