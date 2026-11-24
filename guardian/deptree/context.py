"""Per-scan context shared by all parsers."""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Options:
    generate_lockfiles: bool = True     # npm --package-lock-only fallback (needs network)
    refresh_lockfiles: bool = False     # ignore cached generated lockfiles
    allow_build_tools: bool = False     # mvn/gradle execute project build logic: opt-in only
    crosscheck: bool = True             # compare npm graphs with `npm ls`


@dataclass
class ScanContext:
    project_dir: Path
    repo_root: Path
    out_dir: Path | None = None
    options: Options = field(default_factory=Options)
    # rel path -> {"status": ..., "by": ..., "detail": ...}
    manifest_status: dict[str, dict] = field(default_factory=dict)

    def rel(self, path: Path) -> str:
        path = Path(path).resolve()
        try:
            return path.relative_to(self.repo_root.resolve()).as_posix()
        except ValueError:
            return path.as_posix()

    def claim(self, path: Path, by: Path, detail: str = "") -> None:
        r = self.rel(path)
        if r not in self.manifest_status:
            self.manifest_status[r] = {"status": "consumed", "by": self.rel(by), "detail": detail}

    def is_claimed(self, path: Path) -> bool:
        return self.rel(path) in self.manifest_status

    @staticmethod
    def which(tool: str) -> str | None:
        return shutil.which(tool)

    @staticmethod
    def run(cmd: list[str], cwd: Path, timeout: int = 600, env: dict | None = None):
        full_env = dict(os.environ)
        full_env.update(env or {})
        return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                              timeout=timeout, env=full_env)
