"""Catch-all: manifests we recognise but deliberately do not parse. Never skipped silently."""
from __future__ import annotations

from pathlib import Path

from ..model import Unsupported
from ..registry import Parser, register

REASONS = {
    "bower.json": "Bower (legacy frontend) not supported: no lockfile, transitive graph unknowable offline",
    "Pipfile": "Pipfile without Pipfile.lock: versions unresolved",
    "composer.json": "composer.json without composer.lock: versions unresolved",
    "Gemfile": "Gemfile without Gemfile.lock: versions unresolved",
    "Cargo.toml": "Cargo.toml without Cargo.lock: versions unresolved",
    "setup.py": "setup.py is executable code; not evaluated (untrusted)",
    "packages.config": "legacy NuGet packages.config not supported",
    "environment.yml": "conda environment files not supported",
    "go.work": "go.work workspace files not supported (each go.mod is parsed)",
    "Podfile.lock": "CocoaPods not supported",
    "pubspec.lock": "Dart/Flutter not supported",
    "mix.lock": "Elixir not supported",
    "Package.resolved": "SwiftPM not supported",
    "deno.lock": "Deno not supported",
    "bun.lockb": "Bun binary lockfile not supported",
}


@register
class KnownUnsupportedParser(Parser):
    name = "known-unsupported"
    ecosystem = "various"
    priority = 90

    def detect(self, path: Path) -> bool:
        return path.name in REASONS

    def parse(self, path: Path, ctx):
        raise Unsupported(REASONS[path.name])
