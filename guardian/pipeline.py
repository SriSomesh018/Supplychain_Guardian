"""The Guardian pipeline as a reusable function.

run_scan(...) is used by both the CLI and the web app. It reports progress through
emit(step, status, message, metrics) so the UI can tell the story live."""
from __future__ import annotations

import json
import shutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import networkx as nx

from . import __version__
from .anomalies import diff_against_baseline, static_checks
from .container_ci import dockerfile_checks, trivy_image_scan, workflow_checks
from .discover import discover
from .explain import explain
from .graph import ROOT as GROOT, DepGraph
from .llm import LLM
from .models import Finding
from .risk import rank
from .sbom import syft_crosscheck, write_sbom
from .vulns import scan_vulnerabilities

ROOT = Path(__file__).resolve().parents[1]
Emit = Callable[..., None]
BUNDLED = "bundled (no URL)"  # shipped inside another package's tarball; not a download source

STEPS = [
    ("fetch", "Get the code"),
    ("discover", "Read the ingredient list"),
    ("sbom", "Build the family tree"),
    ("vulns", "Check against known-bad lists"),
    ("intel", "Check real-world exploitation"),
    ("tamper", "Look for tampering"),
    ("compare", "Compare with last known-good"),
    ("ai", "Ask AI to explain"),
    ("report", "Write the report"),
]


def _noop(*_a, **_k):
    pass


def _signature(f: Finding) -> tuple:
    return (f.category, f.title, f.component, f.location.split(":")[0])


def _non_vuln_checks(app: Path, inv, graph):
    df, images = dockerfile_checks(app)
    ci, workflows = workflow_checks(app)
    return static_checks(inv, graph) + df + ci, images, workflows


def _pick_image(images: list[str]) -> str | None:
    """Scan the image that actually ships (final stage); if it floats (:latest), the last pinned one."""
    pinned = [i for i in images if ":" in i.split("/")[-1] and not i.endswith(":latest")]
    if images and images[-1] in pinned:
        return images[-1]
    return pinned[-1] if pinned else None


def _discovery_story(inv, graph: DepGraph, lock_status: str) -> dict:
    g = graph.g
    direct = []
    for k, c in inv.components.items():
        if c.direct:
            direct.append({"name": c.name, "version": c.version, "spec": c.declared_spec, "scope": c.scope,
                           "brings": len(nx.descendants(g, k)), "key": k})
    direct.sort(key=lambda d: -d["brings"])
    depth = Counter(len(graph.shortest_path(k)) - 1 for k in inv.components)
    hosts = Counter((c.resolved.split("/")[2] if c.resolved.startswith("http")
                     else (c.resolved.split(":")[0] or BUNDLED)) for c in inv.components.values())
    # a worked example of Node's resolution: a nested, deep, runtime package
    example = None
    cands = sorted(((k, c) for k, c in inv.components.items() if not c.dev and k.count("node_modules/") >= 2),
                   key=lambda kc: -len(graph.shortest_path(kc[0])))
    if not cands:
        cands = sorted(inv.components.items(), key=lambda kc: -len(graph.shortest_path(kc[0])))
    if cands:
        k, c = cands[0]
        p = graph.shortest_path(k)
        example = {"name": c.name, "version": c.version, "lock_path": k,
                   "path": [graph.label(x) for x in p], "required_by": graph.label(p[-2]) if len(p) > 1 else ""}
    m = inv.manifest
    return {
        "lockfile": {"status": lock_status, "version": inv.lockfile_version, "entries": len(inv.components)},
        "manifest": {"dependencies": len(m.get("dependencies") or {}), "devDependencies": len(m.get("devDependencies") or {}),
                     "scripts": sorted((m.get("scripts") or {}).keys())},
        "direct": direct,
        "depth_histogram": [{"depth": d, "count": depth[d]} for d in sorted(depth) if d >= 0],
        "sources": [{"host": h, "count": n} for h, n in hosts.most_common()],
        "example": example,
    }


def _full_graph(target: Path, out: Path, slug: str) -> dict | None:
    """Full multi-ecosystem dependency graph (all manifests: npm, containers, CI, ...) for the Full Graph tab.

    Built by the vendored deptree engine. Optional: any failure leaves the Guardian scan untouched."""
    try:
        from .deptree.context import Options
        from .deptree.outputs import dumps
        from .deptree.scanner import scan as deptree_scan
        g = deptree_scan(target, out_dir=out / "deptree", options=Options(), repo_root=target.parent, project=slug)
        (out / "deptree_graph.json").write_text(dumps(g), encoding="utf-8")
        s = g["stats"]
        return {"file": "deptree_graph.json", "manifests": s["roots"], "nodes": s["nodes"], "edges": s["edges"],
                "max_depth": s["max_depth"], "ecosystems": sorted(s["by_ecosystem"]),
                "npm_ls_checks": [{"root": c["root"], "status": c["status"]} for c in g["checks"]]}
    except Exception as e:  # never break the main scan
        (out / "deptree_graph.json").unlink(missing_ok=True)
        return {"error": f"{type(e).__name__}: {str(e)[:200]}"}


def _remediation(target: Path, out: Path, ranked, inv) -> dict:
    """Fix proposals for human approval. Optional: a failure never breaks the scan.

    A new scan invalidates the previous sandbox result and patch; reviewer decisions are kept."""
    try:
        from .remediation import plan_fixes
        for stale in ("remediation_result.json", "remediation.patch"):
            (out / stale).unlink(missing_ok=True)
        if (out / "sandbox").exists():
            shutil.rmtree(out / "sandbox", ignore_errors=True)
        return plan_fixes(target, ranked, inv)
    except Exception as e:
        return {"fixes": [], "skipped": [], "error": f"{type(e).__name__}: {str(e)[:200]}"}


def _files(target: Path, out: Path, workflows: list[str]) -> dict:
    def info(p: Path, name: str, role: str):
        return {"name": name, "role": role, "size": p.stat().st_size} if p.exists() else None
    inputs = [info(target / "package.json", "package.json", "What the developers asked for (direct dependencies, scripts)"),
              info(target / "package-lock.json", "package-lock.json", "The exact resolved tree: every package, version, download URL and hash"),
              info(target / "Dockerfile", "Dockerfile", "How the container image is built (base image, commands, user)")]
    inputs += [info(target / w, w, "CI/CD pipeline: which third-party actions run, with which permissions") for w in workflows]
    outs = [("guardian_report.json", "Machine-readable Guardian report (findings, evidence, AI reasoning)"),
            ("sbom.cdx.json", "Software Bill of Materials, CycloneDX 1.5"),
            ("sbom.baseline.cdx.json", "SBOM of the baseline, for comparison"),
            ("sbom.syft.cdx.json", "Independent SBOM from Syft, used as a cross-check"),
            ("deptree_graph.json", "Full dependency graph of every manifest (npm, containers, CI), with depth and evidence")]
    outputs = [info(out / n, n, r) for n, r in outs]
    outputs += [info(p, p.name, "Raw Trivy container-image scan") for p in sorted(out.glob("trivy-image-*.json"))]
    return {"inputs": [x for x in inputs if x], "outputs": [x for x in outputs if x]}


def run_scan(target: Path, out: Path, baseline: Path | None = None, *, emit: Emit = _noop,
             top: int = 8, use_llm: bool = True, use_trivy: bool = True, use_syft: bool = True,
             meta: dict | None = None, lock_status: str = "found") -> dict:
    meta = meta or {}
    target, out, cache = target.resolve(), out.resolve(), ROOT / ".cache"
    out.mkdir(parents=True, exist_ok=True)
    cache.mkdir(exist_ok=True)

    # Five agents orchestrated by LangGraph: discovery -> (vulnerability || integrity) -> change? -> risk
    from .agents.base import ScanContext
    from .agents.orchestrator import run_agents
    ctx = ScanContext(target=target, out=out, baseline=baseline, cache=cache, emit=emit, meta=meta, top=top,
                      use_llm=use_llm, use_trivy=use_trivy, use_syft=use_syft, lock_status=lock_status)
    st, agents_report = run_agents(ctx)
    inv, graph, stats = st["inv"], st["graph"], st["stats"]
    sbom_path, syft, full_graph = st["sbom_path"], st["syft"], st.get("full_graph")
    vstats, images, workflows = st["vstats"], st["images"], st["workflows"]
    changes, ranked, ai_status = st.get("changes") or {}, st["ranked"], st["ai_status"]

    emit("report", "running", "Writing the report, SBOM and evidence files")
    levels = Counter(f.risk_level for f in ranked)
    label_to_keys: dict[str, list[str]] = {}
    for k, c in inv.components.items():
        label_to_keys.setdefault(c.label, []).append(k)
    flagged: dict[str, int] = {}
    for f in ranked:
        if f.component in label_to_keys and (f.risk_score >= 70 or f.changed) and len(flagged) < 45:
            k = label_to_keys[f.component][0]
            flagged[k] = max(flagged.get(k, 0), f.risk_score)
    g = graph.subgraph_for(set(flagged))
    for n in g["nodes"]:
        n["risk"] = flagged.get(n["id"], 0)
        n["depth"] = len(graph.shortest_path(n["id"])) - 1 if n["id"] != GROOT else 0
        if n["id"] == GROOT:
            continue
        c = inv.components[n["id"]]
        # evidence for "why is this direct / transitive?" (with the files it came from)
        n["lock_path"] = n["id"]
        n["declared_in"] = inv.declared_in.get(c.name, "") if c.direct else ""
        n["spec"] = c.declared_spec
        parents = [p for p in graph.g.predecessors(n["id"]) if p != GROOT]
        n["required_by_count"] = len(parents)
        n["required_by"] = [{"label": graph.label(p), "range": inv.ranges.get((p, n["id"]), "")}
                            for p in sorted(parents, key=lambda p: len(graph.shortest_path(p)))[:6]]

    report = {
        "schema": "supply-chain-guardian/report/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": {"name": "supply-chain-guardian", "version": __version__, "team": "Team 17"},
        "target": {"name": inv.app_name, "version": inv.app_version, "path": str(target),
                   "upstream": meta.get("url", ""), "commit": meta.get("commit", ""),
                   "preset": meta.get("preset"), "slug": meta.get("slug", target.name)},
        "baseline": str(baseline) if baseline and changes else None,
        "checkpoint": {
            "what_is_in_the_app": {**stats, "lockfile_version": inv.lockfile_version,
                                   "direct_dependencies": sorted(c.label for c in inv.components.values() if c.direct),
                                   "container_images": images, "ci_workflows": workflows},
            "what_changed": changes,
            "what_looks_risky": {
                "by_risk_level": {k: levels.get(k, 0) for k in ("Critical", "High", "Medium", "Low", "Info")},
                "by_category": dict(Counter(f.category for f in ranked)),
                "top": [f.id for f in ranked[:10]]},
        },
        "discovery": _discovery_story(inv, graph, lock_status),
        "sbom": {"file": sbom_path.name, "format": "CycloneDX 1.5 JSON",
                 "components": stats["total_components"], "syft_crosscheck": syft},
        "vulnerability_scan": {"source": "OSV.dev", **vstats},
        "full_graph": full_graph,
        "agents": agents_report,
        "remediation": _remediation(target, out, ranked, inv),
        "ai": ai_status,
        "evidence_policy": "`evidence` entries are verified tool output. `ai` entries are model "
                           "inference generated from that evidence only and are never used for scoring.",
        "findings": [f.to_dict() for f in ranked],
        "inventory": [
            {"name": c.name, "version": c.version, "label": c.label, "scope": c.scope, "direct": c.direct,
             "declared_in": inv.declared_in.get(c.name, "") if c.direct else "", "spec": c.declared_spec,
             "depth": len(graph.shortest_path(k)) - 1, "parents": graph.g.in_degree(k),
             "install_script": c.has_install_script,
             "source": c.resolved.split("/")[2] if c.resolved.startswith("http") else c.resolved[:40],
             "lock_path": k}
            for k, c in sorted(inv.components.items(), key=lambda kv: kv[1].label)],
        "graph": g,
    }
    (out / "guardian_report.json").write_text("{}", encoding="utf-8")  # placeholder so it is listed
    report["files"] = _files(target, out, workflows)
    rp = out / "guardian_report.json"
    rp.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    for f in report["files"]["outputs"]:
        if f["name"] == "guardian_report.json":
            f["size"] = rp.stat().st_size
    rp.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    emit("report", "done", f"{len(ranked)} findings ranked; report ready", {"findings": len(ranked)})
    return report


def copy_baseline(src: Path, dst: Path) -> Path:
    from .repo import rmtree
    rmtree(dst)
    shutil.copytree(src, dst)
    return dst
