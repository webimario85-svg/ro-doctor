"""Explicit, embeddable detector registry.

Detectors are registered by application code, never discovered from arbitrary
files or automatically imported from third-party packages.
"""
from dataclasses import dataclass
import re
from pathlib import Path
from typing import Callable

from .model import Report

Runner = Callable[[Path | None, Path | None, Report], None]
IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
TARGETS = {"server", "client", "combined"}


@dataclass(frozen=True)
class Check:
    id: str
    target: str
    description: str
    run: Runner
    default: bool = True

    def __post_init__(self) -> None:
        if not IDENTIFIER.fullmatch(self.id):
            raise ValueError("check ID must use lowercase letters, digits and hyphens")
        if self.target not in TARGETS:
            raise ValueError("check target must be server, client, or combined")
        if not callable(self.run):
            raise TypeError("check runner must be callable")


class Registry:
    def __init__(self) -> None:
        self._checks: dict[str, Check] = {}

    def register(self, check: Check) -> None:
        if check.id in self._checks:
            raise ValueError(f"duplicate check ID: {check.id}")
        self._checks[check.id] = check

    def available(self) -> tuple[Check, ...]:
        return tuple(self._checks.values())

    def select(self, only: list[str] | None = None,
               skip: list[str] | None = None) -> tuple[Check, ...]:
        only_set = set(only) if only is not None else None
        skip_set = set(skip or ())
        unknown = ((only_set or set()) | skip_set) - self._checks.keys()
        if unknown:
            raise ValueError("unknown check ID(s): " + ", ".join(sorted(unknown)))
        return tuple(check for key, check in self._checks.items()
                     if ((check.default if only_set is None else key in only_set)
                         and key not in skip_set))
