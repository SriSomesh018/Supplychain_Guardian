"""LangGraph orchestration: order, parallelism, conditional routing, retries and degradation."""
from __future__ import annotations

import json
import shutil

import pytest
import requests

from guardian.agents.base import AgentFailed, friendly_error, is_network_error
from guardian.agents.orchestrator import run_agents

ORDER = ["discovery", "vulnerability", "intel", "integrity", "change", "risk"]


def steps(events, status=None):
    return [e[0] for e in events if status is None or e[1] == status]


def test_full_run_without_baseline(app_dir, fake_services, ctx_factory):
    ctx, events = ctx_factory(app_dir)
    state, rep = run_agents(ctx)
    assert [a["id"] for a in rep["agents"]] == ORDER
    st = {a["id"]: a["status"] for a in rep["agents"]}
    assert st == {"discovery": "done", "vulnerability": "done", "intel": "done", "integrity": "done",
                  "change": "skipped", "risk": "done"}
    assert rep["framework"].startswith("LangGraph") and rep["degraded"] == []
    # every UI step was reported done, change was skipped as "first scan"
    assert set(steps(events, "done")) >= {"discover", "sbom", "vulns", "intel", "tamper", "compare", "ai"}
    lodash = [f for f in state["ranked"] if f.component == "lodash@4.17.20" and f.category == "vulnerability"]
    assert {f.vuln_ids[0] for f in lodash} == {"GHSA-35jh-r3h4-6jhm", "GHSA-29mw-wpgm-hmr9", "GHSA-r5fr-rjxr-66jc"}
    kev = next(f for f in lodash if f.vuln_ids[0] == "GHSA-35jh-r3h4-6jhm")
    assert kev.kev and kev.confidence == "High (2 sources)"
    assert [e.source.split(" ")[0] for e in kev.evidence][:3] == ["OSV.dev", "GitHub", "deps.dev"]
    assert state["vstats"]["source"] == "OSV.dev + GitHub Advisory DB + deps.dev"
    health = {f.id for f in state["ranked"] if f.id.startswith("HEALTH-")}
    assert health == {"HEALTH-deprecated-left-pad@1.3.0", "HEALTH-deprecated-transitive", "HEALTH-scorecard-lodash"}
    assert (ctx.out / "deptree_graph.json").exists()


def test_branches_run_in_parallel(app_dir, fake_services, ctx_factory, monkeypatch):
    import time
    from guardian.agents import integrity, vulnerability
    for mod, cls in ((vulnerability, vulnerability.VulnerabilityAgent), (integrity, integrity.IntegrityAgent)):
        orig = cls.run
        def slow(self, state, _orig=orig):
            time.sleep(0.4)
            return _orig(self, state)
        monkeypatch.setattr(cls, "run", slow)
    ctx, _ = ctx_factory(app_dir)
    _, rep = run_agents(ctx)
    a = {r["id"]: r for r in rep["agents"]}
    # integrity starts before the vulnerability agent finishes
    assert a["integrity"]["started_s"] < a["vulnerability"]["started_s"] + a["vulnerability"]["duration_s"]


def test_change_agent_runs_with_baseline(app_dir, fake_services, ctx_factory, tmp_path):
    base = tmp_path / "baseline"
    shutil.copytree(app_dir, base)
    lock = json.loads((base / "package-lock.json").read_text())
    del lock["packages"]["node_modules/minimist"]
    lock["packages"]["node_modules/mkdirp"].pop("dependencies")
    (base / "package-lock.json").write_text(json.dumps(lock))
    ctx, _ = ctx_factory(app_dir, baseline=base)
    state, rep = run_agents(ctx)
    assert next(a for a in rep["agents"] if a["id"] == "change")["status"] == "done"
    assert "minimist@1.2.0" in state["changes"]["added"]
    assert any(f.changed for f in state["ranked"])


def test_network_agent_retries_then_degrades(app_dir, fake_services, ctx_factory, monkeypatch):
    from guardian import advisories, depsdev, vulns
    calls = {"n": 0}
    def down(self, *a, **k):
        calls["n"] += 1
        raise requests.ConnectionError("offline")
    monkeypatch.setattr(vulns.OSVClient, "query_batch", down)
    monkeypatch.setattr(advisories.AdvisoryClient, "bulk", down)
    monkeypatch.setattr(depsdev.DepsDevClient, "versions", down)
    ctx, events = ctx_factory(app_dir)
    state, rep = run_agents(ctx)
    v = next(a for a in rep["agents"] if a["id"] == "vulnerability")
    assert v["status"] == "error" and v["attempts"] == 3 and v["degraded"]
    assert "network" in v["error"]
    assert calls["n"] == 9                                       # 3 sources x 3 attempts
    assert ("vulns", "error") in [(e[0], e[1]) for e in events]
    assert rep["degraded"][0]["step"] == "vulns"
    # the scan still finished: integrity findings are ranked, risk agent ran
    assert next(a for a in rep["agents"] if a["id"] == "risk")["status"] == "done"
    assert state["vstats"]["advisories"] == 0


def test_one_advisory_source_down_is_a_warning(app_dir, fake_services, ctx_factory, monkeypatch):
    from guardian import advisories
    def down(self, *a, **k):
        raise requests.ConnectionError("offline")
    monkeypatch.setattr(advisories.AdvisoryClient, "bulk", down)
    ctx, _ = ctx_factory(app_dir)
    state, rep = run_agents(ctx)
    v = next(a for a in rep["agents"] if a["id"] == "vulnerability")
    assert v["status"] == "done" and v["warnings"]
    assert rep["warnings"][0]["agent"] == "Vulnerability agent"
    # OSV kept (2) + deps.dev filled the gap once (its two advisories share CVE-2020-28500: no duplicate)
    assert state["vstats"]["advisories"] == 3


def test_discovery_failure_stops_scan(tmp_path, fake_services, ctx_factory):
    empty = tmp_path / "empty"
    empty.mkdir()
    ctx, events = ctx_factory(empty)
    with pytest.raises(AgentFailed) as ei:
        run_agents(ctx)
    assert ei.value.step == "discover" and ("discover", "error") in [(e[0], e[1]) for e in events]


def test_non_network_bug_degrades_without_retry(app_dir, fake_services, ctx_factory, monkeypatch):
    from guardian.agents import intel
    def bug(self, state):
        raise KeyError("boom")
    monkeypatch.setattr(intel.ThreatIntelAgent, "run", bug)
    ctx, _ = ctx_factory(app_dir)
    _, rep = run_agents(ctx)
    i = next(a for a in rep["agents"] if a["id"] == "intel")
    assert i["status"] == "error" and i["attempts"] == 1


def test_friendly_errors():
    r = requests.Response()
    r.status_code = 429
    e = requests.HTTPError(response=r)
    assert is_network_error(e) and "rate-limiting" in friendly_error(e, "OSV.dev")
    assert "Could not reach OSV.dev" in friendly_error(requests.ConnectionError("x"), "OSV.dev")
    assert not is_network_error(ValueError("x"))


def test_one_source_http_error_keeps_other_sources(app_dir, fake_services, ctx_factory, monkeypatch):
    """Regression: a 404 from deps.dev once discarded the OSV results too."""
    from guardian import depsdev
    def http404(self, *a, **k):
        r = requests.Response(); r.status_code = 404
        raise requests.HTTPError("404 Not Found", response=r)
    monkeypatch.setattr(depsdev.DepsDevClient, "versions", http404)
    ctx, _ = ctx_factory(app_dir)
    state, rep = run_agents(ctx)
    v = next(a for a in rep["agents"] if a["id"] == "vulnerability")
    assert v["status"] == "done" and any("deps.dev" in w for w in v["warnings"])
    assert state["vstats"]["advisories"] == 3 and rep["degraded"] == []


def test_withdrawn_depsdev_advisory_is_skipped(app_dir, fake_services, ctx_factory, monkeypatch):
    from guardian import depsdev
    monkeypatch.setattr(depsdev.DepsDevClient, "advisory", lambda self, aid: {})   # 404 -> {}
    ctx, _ = ctx_factory(app_dir)
    state, rep = run_agents(ctx)
    assert state["vstats"]["deps_dev"]["withdrawn_or_unknown"] == 1
    assert not any(f.vuln_ids[:1] == ["GHSA-r5fr-rjxr-66jc"] for f in state["ranked"])


def test_baseline_marks_only_truly_new_packages(app_dir, fake_services, ctx_factory, tmp_path):
    """Regression: findings from extra sources must not all look 'new' against the baseline."""
    base = tmp_path / "same"
    shutil.copytree(app_dir, base)
    ctx, _ = ctx_factory(app_dir, baseline=base)
    state, _ = run_agents(ctx)
    assert state["changes"]["new_findings"] == 0
    assert not any(f.changed for f in state["ranked"])
