"""Google Open Source Insights (deps.dev): third advisory source + package health. Free, no key.

- version batch: advisory keys (GHSA), licenses, deprecation for every name@version
- advisories:    title / CVSS / aliases for advisory IDs that neither OSV nor GitHub DB returned
- projects:      OpenSSF Scorecard of a package's source repository (used for direct dependencies)
All responses are cached on disk."""
from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

import requests

from .discover import Inventory
from .graph import DepGraph
from .models import Evidence, Finding

API = "https://api.deps.dev"
SOURCE = "deps.dev (Open Source Insights)"


class DepsDevClient:
    def __init__(self, cache_dir: Path, session: requests.Session | None = None):
        self.cache = cache_dir / "depsdev"
        self.cache.mkdir(parents=True, exist_ok=True)
        self.s = session or requests.Session()

    def _cached(self, key: str, fetch):
        p = self.cache / (hashlib.sha256(key.encode()).hexdigest() + ".json")
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
        data = fetch()
        p.write_text(json.dumps(data), encoding="utf-8")
        return data

    def versions(self, pkgs: list[tuple[str, str]]) -> dict[tuple[str, str], dict]:
        out: dict[tuple[str, str], dict] = {}
        for i in range(0, len(pkgs), 1000):
            chunk = pkgs[i:i + 1000]

            def fetch(chunk=chunk):
                body = {"requests": [{"versionKey": {"system": "NPM", "name": n, "version": v}} for n, v in chunk]}
                rows, token = [], None
                while True:
                    r = self.s.post(f"{API}/v3alpha/versionbatch", json={**body, **({"pageToken": token} if token else {})},
                                    timeout=60)
                    r.raise_for_status()
                    d = r.json()
                    rows += d.get("responses", [])
                    token = d.get("nextPageToken")
                    if not token:
                        return rows
            for row in self._cached("vb:" + json.dumps(chunk), fetch):
                k = row.get("request", {}).get("versionKey", {})
                if row.get("version"):
                    out[(k.get("name"), k.get("version"))] = row["version"]
        return out

    def advisory(self, aid: str) -> dict:
        def fetch():
            r = self.s.get(f"{API}/v3/advisories/{quote(aid, safe='')}", timeout=30)
            if r.status_code == 404:  # withdrawn / unknown advisory
                return {}
            r.raise_for_status()
            return r.json()
        return self._cached("adv:" + aid, fetch)

    def scorecard(self, project: str) -> dict | None:
        def fetch():
            r = self.s.get(f"{API}/v3/projects/{quote(project, safe='')}", timeout=30)
            if r.status_code == 404:
                return {}
            r.raise_for_status()
            return r.json()
        return (self._cached("proj:" + project, fetch) or {}).get("scorecard")


def source_project(version: dict) -> str | None:
    for rp in version.get("relatedProjects") or []:
        if rp.get("relationType") == "SOURCE_REPO":
            return (rp.get("projectKey") or {}).get("id")
    return None


def advisory_check(findings: list[Finding], inv: Inventory, graph: DepGraph, client: DepsDevClient,
                   versions: dict[tuple[str, str], dict]) -> tuple[list[Finding], dict]:
    """Corroborate existing findings with deps.dev advisory keys; add advisories nobody else returned."""
    known: dict[str, set[str]] = {}
    for f in findings:
        known.setdefault(f.component, set()).update(f.vuln_ids)
    corroborated, new = 0, []
    for f in findings:
        name, _, ver = f.component.rpartition("@")
        keys = {a.get("id") for a in (versions.get((name, ver)) or {}).get("advisoryKeys") or []}
        hit = next((i for i in f.vuln_ids if i in keys), None)
        if hit:
            f.evidence.append(Evidence(source=SOURCE, detail=f"deps.dev also lists {hit} for {f.component}",
                                       data={"advisory": hit}))
            corroborated += 1
    locations: dict[tuple[str, str], list[str]] = {}
    for k, c in inv.components.items():
        locations.setdefault((c.name, c.version), []).append(k)
    missing = sorted({(n, v, a.get("id")) for (n, v), ver in versions.items() for a in ver.get("advisoryKeys") or []
                      if a.get("id") and a["id"] not in known.get(f"{n}@{v}", set())})
    details = {}
    if missing:
        with ThreadPoolExecutor(max_workers=8) as ex:
            ids = sorted({m[2] for m in missing})
            details = dict(zip(ids, ex.map(client.advisory, ids)))
    unresolved = 0
    for name, ver, aid in missing:
        d = details.get(aid) or {}
        if not d:  # deps.dev has no detail (withdrawn advisory): cannot be verified, skip
            unresolved += 1
            continue
        aliases = [a for a in d.get("aliases") or [] if a.startswith(("CVE-", "GHSA-"))]
        if any(a in known.get(f"{name}@{ver}", set()) for a in aliases):
            continue
        keys = locations.get((name, ver), [])
        comps = [inv.components[k] for k in keys]
        score = d.get("cvss3Score") or None
        sev = ("CRITICAL" if score and score >= 9 else "HIGH" if score and score >= 7 else
               "MEDIUM" if score and score >= 4 else "LOW" if score else "MEDIUM")
        paths: list[list[str]] = []
        for k in keys[:3]:
            for p in graph.paths(k, limit=2):
                if p not in paths:
                    paths.append(p)
        new.append(Finding(id=f"VULN-{name}@{ver}-{aid}", category="vulnerability", title=d.get("title") or aid,
                           severity=sev, component=f"{name}@{ver}", purl=comps[0].purl if comps else "",
                           scope="runtime" if any(not c.dev for c in comps) else "dev", location="package-lock.json",
                           dependency_paths=paths[:4], vuln_ids=[aid] + [a for a in aliases if a != aid],
                           cvss=float(score) if score else None, references=[d["url"]] if d.get("url") else [],
                           evidence=[Evidence(source=SOURCE, detail=f"{name}@{ver} is affected by {aid} according to deps.dev; "
                                              "not returned by OSV.dev or the GitHub Advisory DB",
                                              data={"advisory": aid, "installed_at": keys,
                                                    "direct": any(c.direct for c in comps)})]))
        known.setdefault(f"{name}@{ver}", set()).update([aid] + aliases)  # aliases too: no duplicate CVEs
    return new, {"source": SOURCE, "versions_found": len(versions), "corroborated_findings": corroborated,
                 "only_in_deps_dev": len(new), "withdrawn_or_unknown": unresolved}


def health_check(inv: Inventory, graph: DepGraph, client: DepsDevClient, versions: dict[tuple[str, str], dict],
                 min_scorecard: float = 3.0) -> tuple[list[Finding], dict]:
    """Deprecated versions, licenses, and OpenSSF Scorecard of direct runtime dependencies."""
    findings: list[Finding] = []
    licenses: dict[str, int] = {}
    by_label = {}
    for k, c in inv.components.items():
        by_label.setdefault(c.label, []).append(c)
    transitive_deprecated: list[tuple[str, str, str]] = []
    for (name, ver), v in sorted(versions.items()):
        for lic in v.get("licenses") or ["unknown"]:
            licenses[lic] = licenses.get(lic, 0) + 1
        if v.get("isDeprecated"):
            comps = by_label.get(f"{name}@{ver}", [])
            if not any(c.direct for c in comps):  # transitive: summarised below, one finding in total
                transitive_deprecated.append((name, ver, "runtime" if any(not c.dev for c in comps) else "dev"))
                continue
            findings.append(Finding(
                id=f"HEALTH-deprecated-{name}@{ver}", category="manifest-hygiene", title=f"Deprecated package version {name}@{ver}",
                severity="LOW", component=f"{name}@{ver}", purl=comps[0].purl if comps else "",
                scope="runtime" if any(not c.dev for c in comps) else "dev", location="package-lock.json",
                evidence=[Evidence(source=SOURCE, detail=f"The npm registry marks {name}@{ver} as deprecated"
                                   + (f": {v.get('deprecatedReason')}" if v.get("deprecatedReason") else ""),
                                   data={"direct": any(c.direct for c in comps)})]))
    if transitive_deprecated:
        rt = [t for t in transitive_deprecated if t[2] == "runtime"]
        sample = ", ".join(f"{n}@{v}" for n, v, _ in (rt or transitive_deprecated)[:12])
        findings.append(Finding(
            id="HEALTH-deprecated-transitive", category="manifest-hygiene",
            title=f"{len(transitive_deprecated)} transitive dependencies are deprecated",
            severity="INFO", component=f"{len(transitive_deprecated)} packages", scope="runtime" if rt else "dev",
            location="package-lock.json",
            evidence=[Evidence(source=SOURCE, detail=f"{len(transitive_deprecated)} indirect packages ({len(rt)} shipped to "
                               f"production) are marked deprecated on npm, e.g. {sample}",
                               data={"packages": [f"{n}@{v}" for n, v, _ in transitive_deprecated]})]))
    direct = sorted({(c.name, c.version) for c in inv.components.values() if c.direct and not c.dev})
    projects = {(n, ver): source_project(versions.get((n, ver)) or {}) for n, ver in direct}
    projects = {k: p for k, p in projects.items() if p}
    cards = {}
    if projects:
        with ThreadPoolExecutor(max_workers=8) as ex:
            cards = dict(zip(projects, ex.map(client.scorecard, projects.values())))
    scored = 0
    for (n, ver), card in cards.items():
        if not card or card.get("overallScore") is None:
            continue
        scored += 1
        s = float(card["overallScore"])
        if s < min_scorecard:
            weak = sorted((c for c in card.get("checks") or [] if c.get("score", 10) is not None and 0 <= c.get("score", 10) <= 2),
                          key=lambda c: c.get("score", 0))[:4]
            comps = by_label.get(f"{n}@{ver}", [])
            findings.append(Finding(
                id=f"HEALTH-scorecard-{n}", category="manifest-hygiene", title=f"Low OpenSSF Scorecard for direct dependency {n} ({s:.1f}/10)",
                severity="LOW", component=f"{n}@{ver}", purl=comps[0].purl if comps else "", scope="runtime",
                location="package.json",
                evidence=[Evidence(source=SOURCE, detail=f"OpenSSF Scorecard {s:.1f}/10 for {projects[(n, ver)]}"
                                   + (f"; weakest checks: {', '.join(c['name'] for c in weak)}" if weak else ""),
                                   data={"direct": True, "scorecard": s, "project": projects[(n, ver)]})]))
    return findings, {"deprecated": sum(1 for f in findings if "deprecated-" in f.id and "transitive" not in f.id)
                      + len(transitive_deprecated), "deprecated_direct": sum(1 for f in findings if "deprecated-" in f.id
                                                                             and "transitive" not in f.id),
                      "low_scorecard": sum(1 for f in findings if "scorecard" in f.id),
                      "scorecards_checked": scored, "licenses": dict(sorted(licenses.items(), key=lambda x: -x[1])[:10])}
