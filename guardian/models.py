from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class Component:
    key: str                 # lockfile path, e.g. "node_modules/a/node_modules/b"
    name: str
    version: str
    purl: str
    direct: bool = False
    dev: bool = False
    optional: bool = False
    resolved: str = ""
    integrity: str = ""
    has_install_script: bool = False
    declared_spec: str = ""  # spec from package.json if direct

    @property
    def scope(self) -> str:
        return "dev" if self.dev else "runtime"

    @property
    def label(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass
class Evidence:
    """A VERIFIED fact produced by a deterministic tool (scanner, parser, diff)."""
    source: str              # e.g. "OSV.dev", "Trivy", "lockfile-diff", "Dockerfile rule DF003"
    detail: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    id: str
    category: str            # vulnerability | malicious-package | suspicious-change | container | ci-cd | manifest-hygiene
    title: str
    severity: str            # CRITICAL/HIGH/MEDIUM/LOW/INFO (from evidence)
    component: str = ""      # name@version or file
    purl: str = ""
    scope: str = ""          # runtime | dev | build | ci
    location: str = ""       # file the finding was found in
    dependency_paths: list[list[str]] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    vuln_ids: list[str] = field(default_factory=list)
    cvss: float | None = None
    fixed_version: str = ""
    references: list[str] = field(default_factory=list)
    changed: bool = False    # introduced by the baseline -> modified diff
    # filled by the threat-intelligence agent (verified, from CISA KEV / FIRST EPSS)
    kev: bool = False
    epss: float | None = None
    epss_percentile: float | None = None
    # filled by risk.py
    risk_score: int = 0
    risk_level: str = ""
    confidence: str = ""
    risk_rationale: list[str] = field(default_factory=list)
    # filled by explain.py (AI INFERENCE - never treated as evidence)
    ai: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
