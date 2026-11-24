"""Second advisory source, semver matching, threat intelligence and the risk model."""
from __future__ import annotations

import pytest

from guardian.advisories import AdvisoryClient, cross_check, ghsa_id
from guardian.depsdev import DepsDevClient, advisory_check, health_check, source_project
from guardian.discover import discover
from guardian.graph import DepGraph
from guardian.models import Evidence, Finding
from guardian.risk import score_finding
from guardian.semver import satisfies
from guardian.threat_intel import ThreatIntel, enrich
from guardian.vulns import scan_vulnerabilities


@pytest.mark.parametrize("version,rng,expected", [
    ("4.17.20", "<4.17.21", True),
    ("4.17.21", "<4.17.21", False),
    ("1.2.0", ">=1.0.0 <1.2.6", True),
    ("1.2.6", ">=1.0.0 <1.2.6", False),
    ("0.0.8", "<0.2.1 || >=1.0.0 <1.2.3", True),
    ("1.2.3", "<0.2.1 || >=1.0.0 <1.2.3", False),
    ("2.0.0", "1.0.0 - 2.0.0", True),
    ("2.0.1", "1.0.0 - 2.0.0", False),
    ("1.0.0-beta.1", "<1.0.0", True),
    ("3.0.0", "*", True),
    ("not-a-version", "<1.0.0", False),
])
def test_semver(version, rng, expected):
    assert satisfies(version, rng) is expected


def test_ghsa_id():
    assert ghsa_id({"url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"}) == "GHSA-35jh-r3h4-6jhm"
    assert ghsa_id({"id": 7}) == "NPM-7"


def test_github_db_corroborates_and_adds(app_dir, fake_services, tmp_path):
    inv = discover(app_dir)
    graph = DepGraph(inv)
    osv, _ = scan_vulnerabilities(inv, graph, tmp_path)
    new, stats = cross_check(osv, inv, graph, AdvisoryClient(tmp_path))
    lodash = next(f for f in osv if f.component == "lodash@4.17.20")
    assert [e.source for e in lodash.evidence] == ["OSV.dev", "GitHub Advisory DB (npm audit API)"]
    assert [f.vuln_ids for f in new] == [["GHSA-29mw-wpgm-hmr9"]]          # only in GitHub DB
    assert new[0].severity == "MEDIUM" and new[0].scope == "runtime"
    assert stats["corroborated_osv_findings"] == 1 and stats["only_in_github_db"] == 1
    assert not any("GHSA-old0" in i for f in new for i in f.vuln_ids)       # range does not match


def _vuln(ids, **kw):
    return Finding(id="V", category="vulnerability", title="t", severity="HIGH", component="x@1",
                   scope="runtime", vuln_ids=ids, cvss=7.0, fixed_version="2", evidence=[Evidence("OSV.dev", "d")], **kw)


def test_enrich_adds_kev_and_epss(fake_services, tmp_path):
    a, b = _vuln(["GHSA-a", "CVE-2021-23337"]), _vuln(["GHSA-b", "CVE-2021-44906"])
    st = enrich([a, b], ThreatIntel(tmp_path))
    assert a.kev and a.epss == 0.2 and not b.kev and b.epss == 0.004
    assert {e.source for e in a.evidence} >= {"CISA KEV", "FIRST EPSS"}
    assert st == {"cves": 2, "kev_matches": 1, "epss_scored": 2, "epss_high": 1, "errors": []}


def test_enrich_survives_one_feed_down(fake_services, monkeypatch, tmp_path):
    def down(self):
        raise ConnectionError("down")
    monkeypatch.setattr(ThreatIntel, "kev", down)
    a = _vuln(["CVE-2021-23337"])
    st = enrich([a], ThreatIntel(tmp_path))
    assert not a.kev and a.epss == 0.2 and st["errors"] == ["CISA KEV unavailable: ConnectionError"]


def test_enrich_raises_when_all_feeds_down(monkeypatch, tmp_path):
    def down(*a, **k):
        raise ConnectionError("down")
    monkeypatch.setattr(ThreatIntel, "kev", down)
    monkeypatch.setattr(ThreatIntel, "epss", down)
    with pytest.raises(RuntimeError):
        enrich([_vuln(["CVE-1"])], ThreatIntel(tmp_path))


def test_risk_uses_exploit_intel_and_corroboration():
    base = _vuln(["CVE-1"])
    score_finding(base)
    kev = _vuln(["CVE-1"], kev=True)
    score_finding(kev)
    assert kev.risk_score == min(100, base.risk_score + 15)
    assert any("CISA" in r for r in kev.risk_rationale)
    low = _vuln(["CVE-1"], epss=0.001)
    score_finding(low)
    assert low.risk_score == base.risk_score - 5
    two = _vuln(["CVE-1"])
    two.evidence.append(Evidence("GitHub Advisory DB (npm audit API)", "d"))
    score_finding(two)
    assert two.confidence == "High (2 sources)" and base.confidence == "High"


def test_depsdev_corroborates_fills_gaps_and_checks_health(app_dir, fake_services, tmp_path):
    inv = discover(app_dir)
    graph = DepGraph(inv)
    osv, _ = scan_vulnerabilities(inv, graph, tmp_path)
    client = DepsDevClient(tmp_path)
    versions = client.versions(sorted({(c.name, c.version) for c in inv.components.values()}))
    new, st = advisory_check(osv, inv, graph, client, versions)
    assert st["corroborated_findings"] == 2                      # lodash + minimist OSV findings
    # r5fr and 29mw share alias CVE-2020-28500: the second one is not duplicated
    assert [f.vuln_ids[0] for f in new] == ["GHSA-29mw-wpgm-hmr9"]
    health, hst = health_check(inv, graph, client, versions)
    assert {f.id for f in health} == {"HEALTH-deprecated-left-pad@1.3.0", "HEALTH-deprecated-transitive", "HEALTH-scorecard-lodash"}
    assert hst["scorecards_checked"] == 2 and hst["licenses"]["MIT"] == 3
    assert source_project(versions[("lodash", "4.17.20")]) == "github.com/lodash/lodash"
