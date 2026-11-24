"""Manifest discovery: walk a folder and match every file against the parser registry."""
from __future__ import annotations

import os
from pathlib import Path

from .registry import parser_for

SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", ".venv", "venv", "vendor"}


def iter_files(project_dir: Path):
    """Yield every file under project_dir (sorted, skip-dirs pruned)."""
    for dirpath, dirnames, filenames in os.walk(project_dir):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for f in sorted(filenames):
            yield Path(dirpath) / f


def discover(project_dir: Path) -> list[tuple[Path, object]]:
    """Return [(path, parser)] for every recognised manifest, sorted by path."""
    found = []
    for path in iter_files(project_dir):
        p = parser_for(path)
        if p is not None:
            found.append((path, p))
    return sorted(found, key=lambda t: t[0].as_posix())
