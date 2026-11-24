"""Gemini client (LangChain transport), the Flask API, and the end-to-end pipeline."""
from __future__ import annotations

import json

import pytest

from guardian import llm as llm_mod
from guardian.agents.base import AgentFailed


class FakeMsg:
    def __init__(self, text):
        self.text = text


def fake_chat(script):
    """script: model -> list of outcomes (str reply or Exception), consumed in order."""
    class Chat:
        def __init__(self, model, **kw):
            self.model = model
            assert kw["google_api_key"] == "test-key-123"

        def invoke(self, messages):
            out = script[self.model].pop(0)
            if isinstance(out, Exception):
                raise out
            return FakeMsg(out)
    return Chat


@pytest.fixture
def gemini(monkeypatch, tmp_path):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-123")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-old")
    monkeypatch.setenv("GEMINI_FALLBACK_MODELS", "gemini-new")
    monkeypatch.setattr(llm_mod.time, "sleep", lambda s: None)
    return lambda script: (monkeypatch.setattr(llm_mod, "ChatGoogleGenerativeAI", fake_chat(script)), llm_mod.LLM(tmp_path))[1]


def test_llm_falls_back_to_next_model_and_strips_fences(gemini):
    llm = gemini({"gemini-old": [Exception("404 NOT_FOUND models/gemini-old")],
                  "gemini-new": ['```json\n{"ok": true}\n```']})
    assert llm.backend.startswith("LangChain")
    assert llm.generate_json("hi") == {"ok": True}
    assert llm.model == "gemini-new" and llm.attempts == ["gemini-old: not available (404)", "gemini-new: ok"]
    # second identical prompt is served from the cache
    assert llm.generate_json("hi") == {"ok": True} and llm.calls["cache_hits"] == 1


def test_llm_bad_key_stops_and_never_leaks_key(gemini):
    llm = gemini({"gemini-old": [Exception("401 API key test-key-123 invalid")], "gemini-new": []})
    assert llm.generate_json("x") is None
    assert "test-key-123" not in llm.last_error and "***" in llm.last_error
    assert llm.attempts == ["gemini-old: HTTP 401"]


def test_llm_retries_invalid_json(gemini):
    llm = gemini({"gemini-old": ["not json", '{"a": 1}'], "gemini-new": []})
    assert llm.generate_json("y") == {"a": 1}


# ------------------------------------------------------------------ Flask API

@pytest.fixture
def client(monkeypatch, tmp_path):
    from guardian import server
    monkeypatch.setattr(server, "OUTPUT", tmp_path / "output")
    (tmp_path / "output").mkdir()
    server.app.config["TESTING"] = True
    return server.app.test_client()


def test_api_basics(client):
    assert client.get("/").status_code == 200
    steps = [s[0] for s in client.get("/api/presets").get_json()["steps"]]
    assert steps.index("vulns") < steps.index("intel") < steps.index("tamper")
    assert client.post("/api/scan", json={"url": "ftp://nope"}).status_code == 400
    assert client.post("/api/scan", json={"preset": "nope"}).status_code == 400
    assert client.get("/api/report/../etc").status_code in (400, 404)
    assert client.get("/api/report/missing").status_code == 404
    assert client.get("/api/jobs/unknown").status_code == 404


def test_job_error_reports_failed_step(monkeypatch):
    from guardian import server

    def boom(*a, **k):
        raise AgentFailed("Discovery agent", "discover", "Required file not found: package-lock.json.")
    monkeypatch.setattr(server, "clone", lambda url, emit: (server.TARGETS / "x", "abc"))
    monkeypatch.setattr(server, "ensure_lockfile", lambda t, e: "found")
    monkeypatch.setattr(server, "snapshot_dir", lambda slug: server.TARGETS / "no-such-snapshot")
    monkeypatch.setattr(server, "run_scan", boom)
    job = {"events": [], "started": 0}
    server._run_job(job, None, "https://github.com/o/r")
    assert job["status"] == "error" and job["failed_step"] == "discover"
    assert job["error"] == "Required file not found: package-lock.json."


# ------------------------------------------------------------------ end to end

def test_run_scan_end_to_end(app_dir, fake_services, tmp_path):
    from guardian.pipeline import run_scan
    out = tmp_path / "report"
    events = []
    r = run_scan(app_dir, out, None, emit=lambda *a: events.append(a), use_llm=False, use_trivy=False,
                 use_syft=False, meta={"slug": "demo"})
    assert r["agents"]["framework"].startswith("LangGraph") and len(r["agents"]["agents"]) == 6
    assert r["full_graph"]["nodes"] >= 4 and (out / "deptree_graph.json").exists()
    assert r["vulnerability_scan"]["source"] == "OSV.dev + GitHub Advisory DB + deps.dev"
    assert "deptree_graph.json" in {f["name"] for f in r["files"]["outputs"]}
    saved = json.loads((out / "guardian_report.json").read_text())
    top = next(f for f in saved["findings"] if f["id"].endswith("GHSA-35jh-r3h4-6jhm"))
    assert top["kev"] is True and top["epss"] == 0.2
    assert any("CISA" in x for x in top["risk_rationale"])
    assert events[-1][:2] == ("report", "done")
    fixes = {f["package"]: f for f in r["remediation"]["fixes"]}
    assert fixes["lodash"]["kind"] == "direct" and fixes["lodash"]["to_version"] == "4.17.21"
    assert fixes["minimist"]["kind"] == "override" and fixes["minimist"]["to_version"] == "1.2.6"
