"""Second advisory source: the GitHub Advisory Database, through npm's bulk advisory API.

Used to corroborate OSV.dev and to catch advisories OSV did not return:
- an OSV finding whose GHSA alias is also listed here gets a second evidence entry (corroborated)
- an advisory listed here but not by OSV becomes its own finding (source: GitHub Advisory DB)
No API key is needed. Responses are cached on disk."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import requests

from .discover import Inventory
from .graph import DepGraph
from .models import Evidence, Finding
from .semver import satisfies

BULK = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"
SOURCE = "GitHub Advisory DB (npm audit API)"
SEV = {"critical": "CRITICAL", "high": "HIGH", "moderate": "MEDIUM", "low": "LOW", "info": "INFO"}


class AdvisoryClient:
    def __init__(self, cache_dir: Path, session: requests.Session | None = None):
        self.cache = cache_dir / "ghsa"
        self.cache.mkdir(parents=True, exist_ok=True)
        self.s = session or requests.Session()

    def bulk(self, pkgs: dict[str, list[str]]) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        names = sorted(pkgs)
        for i in range(0, len(names), 300):
            chunk = {n: sorted(pkgs[n]) for n in names[i:i + 300]}
            key = hashlib.sha256(json.dumps(chunk, sort_keys=True).encode()).hexdigest()
            p = self.cache / f"{key}.json"
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
            else:
                r = self.s.post(BULK, json=chunk, timeout=60)
                r.raise_for_status()
                data = r.json()
                p.write_text(json.dumps(data), encoding="utf-8")
            for n, advs in (data or {}).items():
                out.setdefault(n, []).extend(advs or [])
        return out


def fixed_from_range(rng: str) -> str:
    """'<4.17.21' or '>=1.0.0 <1.2.6 || <0.2.4' -> '4.17.21, 1.2.6, 0.2.4' (upper bounds are the fixes)."""
    import re
    return ", ".join(dict.fromkeys(re.findall(r"(?<![<>=])<\s*v?([0-9][0-9A-Za-z.+-]*)", rng or "")))


def ghsa_id(adv: dict) -> str:
    url = adv.get("url") or ""
    return url.rstrip("/").rsplit("/", 1)[-1] if "/advisories/" in url else f"NPM-{adv.get('id')}"


def cross_check(osv_findings: list[Finding], inv: Inventory, graph: DepGraph, client: AdvisoryClient) -> tuple[list[Finding], dict]:
    """Mutates OSV findings (adds corroborating evidence) and returns (new findings, stats)."""
    versions: dict[str, set[str]] = {}
    for c in inv.components.values():
        if c.version and not c.version.startswith(("http", "git")):
            versions.setdefault(c.name, set()).add(c.version)
    data = client.bulk({n: sorted(v) for n, v in versions.items()})

    # (name, version) -> {GHSA id: advisory}
    hits: dict[tuple[str, str], dict[str, dict]] = {}
    for name, advs in data.items():
        for adv in advs:
            for v in versions.get(name, ()):
                if satisfies(v, adv.get("vulnerable_versions", "")):
                    hits.setdefault((name, v), {})[ghsa_id(adv)] = adv

    corroborated = 0
    seen: set[tuple[str, str]] = set()
    for f in osv_findings:
        name, _, version = f.component.rpartition("@")
        for gid in f.vuln_ids:
            adv = hits.get((name, version), {}).get(gid)
            if adv:
                f.evidence.append(Evidence(source=SOURCE, detail=f"{gid} also lists {f.component} as affected "
                                           f"(vulnerable versions {adv.get('vulnerable_versions')})",
                                           data={"ghsa": gid, "severity": adv.get("severity"), "cwe": adv.get("cwe")}))
                corroborated += 1
                seen.add((f.component, gid))
                break

    locations: dict[tuple[str, str], list[str]] = {}
    for k, c in inv.components.items():
        locations.setdefault((c.name, c.version), []).append(k)
    new: list[Finding] = []
    for (name, version), advs in sorted(hits.items()):
        label = f"{name}@{version}"
        for gid, adv in sorted(advs.items()):
            if (label, gid) in seen or any(f.component == label and gid in f.vuln_ids for f in osv_findings):
                continue
            keys = locations.get((name, version), [])
            comps = [inv.components[k] for k in keys]
            paths: list[list[str]] = []
            for k in keys[:3]:
                for p in graph.paths(k, limit=2):
                    if p not in paths:
                        paths.append(p)
            cvss = (adv.get("cvss") or {}).get("score") or None
            sev = SEV.get(str(adv.get("severity", "")).lower(), "MEDIUM")
            new.append(Finding(
                id=f"VULN-{label}-{gid}", category="vulnerability", title=adv.get("title") or gid, severity=sev,
                component=label, purl=comps[0].purl if comps else "",
                scope="runtime" if any(not c.dev for c in comps) else "dev", location="package-lock.json",
                dependency_paths=paths[:4], vuln_ids=[gid], cvss=float(cvss) if cvss else None,
                fixed_version=fixed_from_range(adv.get("vulnerable_versions", "")),
                references=[adv["url"]] if adv.get("url") else [],
                evidence=[Evidence(source=SOURCE, detail=f"{label} matches {gid} (vulnerable versions "
                                   f"{adv.get('vulnerable_versions')}); severity {sev}; not returned by OSV.dev",
                                   data={"ghsa": gid, "installed_at": keys, "direct": any(c.direct for c in comps),
                                         "cwe": adv.get("cwe")})]))
    stats = {"source": SOURCE, "packages_with_advisories": len(hits),
             "advisories": len({g for a in hits.values() for g in a}), "corroborated_osv_findings": corroborated,
             "only_in_github_db": len(new)}
    return new, stats
