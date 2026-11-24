"""Parser plugin registry.

Every parser implements::

    detect(path: Path) -> bool
    parse(path: Path, ctx: ScanContext) -> PartialGraph

Parsers run in ``priority`` order (lower first). A parser may *claim* companion
files (e.g. the npm manifest parser claims ``package-lock.json`` next to it), in
which case the claimed file is recorded as consumed instead of parsed again.
"""
from __future__ import annotations

from pathlib import Path

from .model import PartialGraph


class Parser:
    name = "base"
    ecosystem = "unknown"
    priority = 50

    def detect(self, path: Path) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def parse(self, path: Path, ctx) -> PartialGraph:  # pragma: no cover - interface
        raise NotImplementedError


REGISTRY: list[Parser] = []


def register(cls):
    REGISTRY.append(cls())
    REGISTRY.sort(key=lambda p: (p.priority, p.name))
    return cls


def parser_for(path: Path) -> Parser | None:
    _load_plugins()
    for p in REGISTRY:
        if p.detect(path):
            return p
    return None


_loaded = False


def _load_plugins() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    from .parsers import (  # noqa: F401  (import registers the parsers)
        containers, github_actions, lockfiles, npm, python, unsupported,
    )
