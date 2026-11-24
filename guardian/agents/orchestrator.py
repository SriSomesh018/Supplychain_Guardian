"""LangGraph orchestrator for the six Guardian agents.

    START -> discovery -+-> vulnerability -> threat intel -+-> merge --(baseline?)--> change -> risk -> END
                        +-> integrity ---------------------+         \\------(no)--------------^

- discovery fans out to two branches that run in parallel: advisories (+ exploit intelligence)
  and supply-chain integrity
- network agents get a LangGraph RetryPolicy (backoff + jitter); after the last attempt they
  degrade instead of failing the scan
- merge waits for both branches, combines their findings, and routes conditionally
- change runs only when a baseline exists; otherwise the orchestrator records it as skipped
- every node appends a trace record (reducer: list concatenation), exported in the report
"""
from __future__ import annotations

import operator
import time
from importlib import metadata
from typing import Annotated, Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import RetryPolicy

from .base import RetryableAgentError, ScanContext
from .change import ChangeAgent
from .discovery import DiscoveryAgent
from .integrity import IntegrityAgent
from .intel import ThreatIntelAgent
from .risk import RiskExplainAgent
from .vulnerability import VulnerabilityAgent

AGENTS = [DiscoveryAgent, VulnerabilityAgent, ThreatIntelAgent, IntegrityAgent, ChangeAgent, RiskExplainAgent]


class ScanState(TypedDict, total=False):
    # discovery
    inv: Any
    graph: Any
    stats: dict
    sbom_path: Any
    syft: dict
    full_graph: dict
    # vulnerability
    vulns: list
    vstats: dict
    depsdev: dict
    # threat intelligence
    intel: dict
    health_findings: list
    # integrity
    other: list
    images: list
    workflows: list
    image_findings: list
    # merge / change
    findings: list
    changes: dict
    # risk
    ranked: list
    ai_status: dict
    # orchestration trace (parallel-safe: lists are concatenated)
    trace: Annotated[list, operator.add]


def build(ctx: ScanContext):
    g = StateGraph(ScanState)

    def node(name: str, agent):
        retry = RetryPolicy(max_attempts=agent.max_attempts, initial_interval=ctx.retry_interval, backoff_factor=2.0,
                            retry_on=RetryableAgentError) if agent.max_attempts > 1 else None
        g.add_node(name, agent, retry_policy=retry)

    node("discovery", DiscoveryAgent(ctx))
    node("vulnerability", VulnerabilityAgent(ctx))
    node("intel", ThreatIntelAgent(ctx))
    node("integrity", IntegrityAgent(ctx))

    def merge(state: ScanState) -> dict:
        findings = (list(state.get("vulns") or []) + list(state.get("other") or []) + list(state.get("image_findings") or [])
                    + list(state.get("health_findings") or []))
        update: dict = {"findings": findings, "changes": {}}
        has_baseline = bool(ctx.baseline and (ctx.baseline / "package-lock.json").exists())
        if not has_baseline:
            ctx.emit("compare", "done", "First scan of this repository: it becomes the baseline for the next scan", {"new": 0})
            update["trace"] = [{"id": ChangeAgent.id, "name": ChangeAgent.name, "role": ChangeAgent.role,
                                "tools": ChangeAgent.tools, "uses_llm": False, "status": "skipped",
                                "started_s": round(time.time() - ctx.t0, 2), "duration_s": 0,
                                "summary": "No baseline yet: this scan becomes the baseline for the next one.",
                                "outputs": {}}]
        return update

    g.add_node("merge", merge)
    node("change", ChangeAgent(ctx))
    node("risk", RiskExplainAgent(ctx))

    g.add_edge(START, "discovery")
    g.add_edge("discovery", "vulnerability")
    g.add_edge("discovery", "integrity")
    g.add_edge("vulnerability", "intel")
    g.add_edge(["intel", "integrity"], "merge")
    g.add_conditional_edges("merge",
                            lambda s: "change" if ctx.baseline and (ctx.baseline / "package-lock.json").exists() else "risk",
                            {"change": "change", "risk": "risk"})
    g.add_edge("change", "risk")
    g.add_edge("risk", END)
    return g.compile()


def _version(pkg: str) -> str:
    try:
        return metadata.version(pkg)
    except metadata.PackageNotFoundError:
        return "?"


def run_agents(ctx: ScanContext) -> tuple[dict, dict]:
    """Run the agent graph. Returns (final state, orchestration report)."""
    app = build(ctx)
    t0 = time.time()
    state = app.invoke({"trace": []})
    order = {a.id: i for i, a in enumerate(AGENTS)}
    trace = sorted(state.get("trace") or [], key=lambda r: order.get(r["id"], 99))
    ai = state.get("ai_status") or {}
    try:
        mermaid = app.get_graph().draw_mermaid()
    except Exception:
        mermaid = ""
    report = {
        "framework": f"LangGraph {_version('langgraph')}",
        "llm": {"provider": "Google Gemini", "client": ai.get("backend", ""), "model": ai.get("model") if ai.get("mode") == "llm" else None,
                "mode": ai.get("mode"), "attempts": ai.get("attempts", [])},
        "duration_s": round(time.time() - t0, 2),
        "flow": [["discovery"], ["vulnerability", "integrity"], ["intel"], ["change"], ["risk"]],
        "edges": [["discovery", "vulnerability", ""], ["discovery", "integrity", ""], ["vulnerability", "intel", ""],
                  ["intel", "change", "after both branches"], ["integrity", "change", "after both branches"],
                  ["change", "risk", "if baseline, else skipped"]],
        "degraded": [{"agent": r["name"], "step": next((a.step for a in AGENTS if a.id == r["id"]), ""),
                      "error": r.get("error", "")} for r in trace if r.get("status") == "error"],
        "warnings": [{"agent": r["name"], "warning": w} for r in trace for w in r.get("warnings", [])],
        "mermaid": mermaid,
        "agents": trace,
        "principles": ["Scores and facts come only from deterministic tools.",
                       "The LLM explains; it never scores, edits files or changes dependencies.",
                       "Only verified evidence for the top findings is sent to the LLM (no source code, no secrets).",
                       "Invented advisory IDs and unsupported evidence claims are removed automatically."],
    }
    return state, report
