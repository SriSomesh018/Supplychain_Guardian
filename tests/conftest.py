"""Shared fixtures. Every test runs OFFLINE: real HTTP is blocked and each external service
(OSV.dev, GitHub Advisory DB, CISA KEV, FIRST EPSS, Gemini) is replaced by a fake."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

PKG = {"name": "demo-app", "version": "1.0.0",
       "dependencies": {"lodash": "^4.17.20", "mkdirp": "0.5.1"},
       "devDependencies": {"left-pad": "1.3.0"}}
LOCK = {"name": "demo-app", "version": "1.0.0", "lockfileVersion": 3, "requires": True, "packages": {
    "": {"name": "demo-app", "version": "1.0.0", "dependencies": PKG["dependencies"], "devDependencies": PKG["devDependencies"]},
    "node_modules/lodash": {"version": "4.17.20", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                            "integrity": "sha512-AAAA"},
    "node_modules/mkdirp": {"version": "0.5.1", "resolved": "https://registry.npmjs.org/mkdirp/-/mkdirp-0.5.1.tgz",
                            "integrity": "sha512-BBBB", "dependencies": {"minimist": "0.0.8"}},
    "node_modules/minimist": {"version": "1.2.0", "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.0.tgz",
                              "integrity": "sha512-CCCC"},
    "node_modules/left-pad": {"version": "1.3.0", "dev": True, "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                              "integrity": "sha512-DDDD"}}}
DOCKERFILE = "FROM node:18-alpine\nWORKDIR /app\nCOPY . .\nRUN npm ci --omit=dev\nCMD [\"node\", \"server.js\"]\n"
WORKFLOW = "name: ci\non: [push]\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"

OSV_HITS = {("lodash", "4.17.20"): ["GHSA-35jh-r3h4-6jhm"], ("minimist", "1.2.0"): ["GHSA-xvch-5gv4-984h"]}
OSV_VULNS = {
    "GHSA-35jh-r3h4-6jhm": {"id": "GHSA-35jh-r3h4-6jhm", "summary": "Command Injection in lodash",
                            "aliases": ["CVE-2021-23337"], "database_specific": {"severity": "HIGH"},
                            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
                            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
                            "references": [{"url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"}]},
    "GHSA-xvch-5gv4-984h": {"id": "GHSA-xvch-5gv4-984h", "summary": "Prototype Pollution in minimist",
                            "aliases": ["CVE-2021-44906"], "database_specific": {"severity": "CRITICAL"},
                            "affected": [{"package": {"ecosystem": "npm", "name": "minimist"},
                                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.6"}]}]}]},
}
GH_BULK = {"lodash": [
    {"id": 1, "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm", "title": "Command Injection in lodash",
     "severity": "high", "vulnerable_versions": "<4.17.21", "cwe": ["CWE-77"], "cvss": {"score": 7.2}},
    {"id": 2, "url": "https://github.com/advisories/GHSA-29mw-wpgm-hmr9", "title": "ReDoS in lodash",
     "severity": "moderate", "vulnerable_versions": ">=4.0.0 <4.17.21", "cwe": ["CWE-1333"], "cvss": {"score": 5.3}},
    {"id": 3, "url": "https://github.com/advisories/GHSA-old0-0000-0000", "title": "Old issue",
     "severity": "low", "vulnerable_versions": "<4.0.0", "cwe": [], "cvss": {"score": 0}}]}
DEPSDEV = {
    ("lodash", "4.17.20"): {"licenses": ["MIT"], "isDeprecated": False,
                            "advisoryKeys": [{"id": "GHSA-35jh-r3h4-6jhm"}, {"id": "GHSA-29mw-wpgm-hmr9"}, {"id": "GHSA-r5fr-rjxr-66jc"}],
                            "relatedProjects": [{"projectKey": {"id": "github.com/lodash/lodash"}, "relationType": "SOURCE_REPO"}]},
    ("mkdirp", "0.5.1"): {"licenses": ["MIT"], "isDeprecated": False, "advisoryKeys": [],
                          "relatedProjects": [{"projectKey": {"id": "github.com/substack/node-mkdirp"}, "relationType": "SOURCE_REPO"}]},
    ("minimist", "1.2.0"): {"licenses": ["MIT"], "isDeprecated": True, "advisoryKeys": [{"id": "GHSA-xvch-5gv4-984h"}]},
    ("left-pad", "1.3.0"): {"licenses": ["WTFPL"], "isDeprecated": True, "deprecatedReason": "use String.prototype.padStart()",
                            "advisoryKeys": []},
}
DEPSDEV_ADV = {"GHSA-r5fr-rjxr-66jc": {"title": "ReDoS in lodash trimEnd", "cvss3Score": 5.3, "aliases": ["CVE-2020-28500"],
                                       "url": "https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc"},
               "GHSA-29mw-wpgm-hmr9": {"title": "ReDoS in lodash", "cvss3Score": 5.3, "aliases": ["CVE-2020-28500"]}}
SCORECARDS = {"github.com/lodash/lodash": {"overallScore": 2.4, "checks": [{"name": "Maintained", "score": 0}]},
              "github.com/substack/node-mkdirp": {"overallScore": 6.1, "checks": []}}
KEV = {"CVE-2021-23337": {"cveID": "CVE-2021-23337", "dateAdded": "2026-01-15", "knownRansomwareCampaignUse": "Unknown"}}
EPSS = {"CVE-2021-23337": {"epss": 0.2, "percentile": 0.97, "date": "2026-11-22"},
        "CVE-2021-44906": {"epss": 0.004, "percentile": 0.6, "date": "2026-11-22"}}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(self, method, url, *a, **k):
        raise requests.ConnectionError(f"network disabled in tests: {method} {url}")
    monkeypatch.setattr(requests.Session, "request", blocked)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)


def write_app(root: Path, lock: dict | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps(PKG, indent=2))
    (root / "package-lock.json").write_text(json.dumps(lock or LOCK, indent=2))
    (root / "Dockerfile").write_text(DOCKERFILE)
    (root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (root / ".github" / "workflows" / "ci.yml").write_text(WORKFLOW)
    return root


@pytest.fixture
def app_dir(tmp_path):
    return write_app(tmp_path / "demo-app")


@pytest.fixture
def fake_services(monkeypatch):
    """Healthy fakes for every external service."""
    from guardian import advisories, depsdev, threat_intel, vulns
    calls = {"osv": 0, "gh": 0, "kev": 0, "epss": 0, "depsdev": 0}

    def query_batch(self, pkgs):
        calls["osv"] += 1
        return {k: v for k, v in OSV_HITS.items() if k in set(pkgs)}

    def bulk(self, pkgs):
        calls["gh"] += 1
        return {n: GH_BULK[n] for n in pkgs if n in GH_BULK}

    def kev(self):
        calls["kev"] += 1
        return KEV

    def epss(self, cves):
        calls["epss"] += 1
        return {c: EPSS.get(c, {}) for c in cves}

    monkeypatch.setattr(vulns.OSVClient, "query_batch", query_batch)
    monkeypatch.setattr(vulns.OSVClient, "get", lambda self, vid: OSV_VULNS[vid])
    monkeypatch.setattr(advisories.AdvisoryClient, "bulk", bulk)
    monkeypatch.setattr(threat_intel.ThreatIntel, "kev", kev)
    monkeypatch.setattr(threat_intel.ThreatIntel, "epss", epss)

    def versions(self, pkgs):
        calls["depsdev"] += 1
        return {k: DEPSDEV[k] for k in pkgs if k in DEPSDEV}
    monkeypatch.setattr(depsdev.DepsDevClient, "versions", versions)
    monkeypatch.setattr(depsdev.DepsDevClient, "advisory", lambda self, aid: DEPSDEV_ADV.get(aid, {}))
    monkeypatch.setattr(depsdev.DepsDevClient, "scorecard", lambda self, p: SCORECARDS.get(p))
    return calls


@pytest.fixture
def ctx_factory(tmp_path):
    from guardian.agents.base import ScanContext

    def make(target: Path, baseline: Path | None = None, **kw):
        events: list[tuple] = []
        out = tmp_path / "out"
        out.mkdir(exist_ok=True)
        cache = tmp_path / "cache"
        cache.mkdir(exist_ok=True)
        ctx = ScanContext(target=target, out=out, baseline=baseline, cache=cache,
                          emit=lambda *a: events.append(a), meta={"slug": "demo"},
                          use_llm=False, use_trivy=False, use_syft=False, retry_interval=0.01, **kw)
        return ctx, events
    return make
