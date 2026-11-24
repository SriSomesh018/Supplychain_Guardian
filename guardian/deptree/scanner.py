"""Scan orchestration and graph assembly (merge, depth, scopes, stats, deterministic order)."""
from __future__ import annotations

import os
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .context import Options, ScanContext
from .discovery import discover
from .model import (APPLICATION, CONTAINER_IMAGE, GITHUB_ACTION, PACKAGE, SCHEMA_VERSION,
                    PartialGraph, Unsupported)


def _git_commit(path: Path) -> str | None:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=path, capture_output=True,
                              text=True, check=True).stdout.strip() or None
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def _now() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    dt = datetime.fromtimestamp(int(epoch), timezone.utc) if epoch else datetime.now(timezone.utc)
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def scan(project_dir: Path, out_dir: Path | None = None, options: Options | None = None,
         repo_root: Path | None = None, project: str | None = None, source: dict | None = None,
         log=lambda msg: None) -> dict:
    project_dir = Path(project_dir).resolve()
    repo_root = Path(repo_root).resolve() if repo_root else project_dir.parent
    ctx = ScanContext(project_dir=project_dir, repo_root=repo_root, out_dir=out_dir,
                      options=options or Options())
    merged = PartialGraph()
    manifests = []
    found = discover(project_dir)
    log(f"discovered {len(found)} manifest(s)")
    for path, parser in sorted(found, key=lambda t: (t[1].priority, t[0].as_posix())):
        rel = ctx.rel(path)
        if ctx.is_claimed(path):
            st = ctx.manifest_status[rel]
            manifests.append({"file": rel, "ecosystem": parser.ecosystem, "parser": parser.name,
                              "status": st["status"], "consumed_by": st["by"], "detail": st["detail"]})
            continue
        ctx.manifest_status[rel] = {"status": "parsed", "by": rel, "detail": ""}
        log(f"parsing {rel} ({parser.name})")
        try:
            pg = parser.parse(path, ctx)
        except Unsupported as e:
            merged.unsupported.append({"file": rel, "reason": str(e)})
            manifests.append({"file": rel, "ecosystem": parser.ecosystem, "parser": parser.name,
                              "status": "unsupported"})
            continue
        except Exception as e:  # never silently skip
            merged.unsupported.append({"file": rel, "reason": f"parser error: {type(e).__name__}: {e}"})
            manifests.append({"file": rel, "ecosystem": parser.ecosystem, "parser": parser.name,
                              "status": "error"})
            continue
        merged.merge(pg)
        manifests.append({"file": rel, "ecosystem": parser.ecosystem, "parser": parser.name,
                          "status": "parsed", "roots": sorted(pg.roots)})
    return assemble(merged, manifests, project or project_dir.name,
                    _git_commit(project_dir), source)


def assemble(pg: PartialGraph, manifests: list, project: str, commit: str | None,
             source: dict | None = None) -> dict:
    roots = sorted(pg.roots)
    out_edges = defaultdict(list)
    for e in pg.edges.values():
        out_edges[e.source].append(e)

    # min depth: BFS from all roots
    depth = {r: 0 for r in roots}
    q = deque(roots)
    while q:
        n = q.popleft()
        for e in out_edges[n]:
            if e.target not in depth:
                depth[e.target] = depth[n] + 1
                q.append(e.target)

    # scopes: a node carries the scope of every root edge through which it is reachable
    scopes = defaultdict(set)
    for r in roots:
        by_scope = defaultdict(list)
        for e in out_edges[r]:
            by_scope[e.scope or "prod"].append(e.target)
        for s, starts in by_scope.items():
            seen = set(starts)
            q = deque(starts)
            while q:
                n = q.popleft()
                scopes[n].add(s)
                for e in out_edges[n]:
                    if e.target not in seen:
                        seen.add(e.target)
                        q.append(e.target)

    root_set = set(roots)
    direct = {e.target for e in pg.edges.values() if e.source in root_set}
    nodes = []
    for nid in sorted(pg.nodes):
        n = pg.nodes[nid]
        nodes.append({
            "id": n.id, "type": n.type, "ecosystem": n.ecosystem, "name": n.name,
            "version": n.version, "purl": n.purl,
            "direct": nid in direct, "min_depth": depth.get(nid),
            "scopes": sorted(scopes.get(nid, ())) if n.type != APPLICATION else [],
            "resolved": n.resolved, "integrity": n.integrity,
            "evidence": sorted(n.evidence, key=lambda ev: (ev["file"], ev["locator"])),
            "properties": n.properties,
        })
    edges = []
    for e in sorted(pg.edges.values(), key=lambda e: e.key()):
        d = {"from": e.source, "to": e.target, "relation": e.relation, "scope": e.scope,
             "declared_range": e.declared_range}
        if e.properties:
            d["properties"] = e.properties
        edges.append(d)

    def sort_dicts(items):
        import json
        uniq = {json.dumps(i, sort_keys=True): i for i in items}
        return [uniq[k] for k in sorted(uniq)]

    graph = {
        "schema_version": SCHEMA_VERSION,
        "project": project,
        "git_commit": commit,
        "source": source or {},
        "generated_at": _now(),
        "generator": {"name": "deptree", "version": __version__},
        "roots": roots,
        "nodes": nodes,
        "edges": edges,
        "manifests": sorted(manifests, key=lambda m: m["file"]),
        "unresolved": sort_dicts(pg.unresolved),
        "unsupported": sort_dicts(pg.unsupported),
        "checks": sort_dicts(pg.checks),
    }
    graph["stats"] = compute_stats(graph)
    return graph


def compute_stats(g: dict) -> dict:
    nodes = [n for n in g["nodes"] if n["type"] != APPLICATION]
    by_eco = defaultdict(lambda: {"nodes": 0, "edges": 0, "direct": 0, "transitive": 0})
    eco_of = {n["id"]: n["ecosystem"] for n in g["nodes"]}
    for n in nodes:
        s = by_eco[n["ecosystem"]]
        s["nodes"] += 1
        s["direct" if n["direct"] else "transitive"] += 1
    for e in g["edges"]:
        by_eco[eco_of.get(e["to"], "unknown")]["edges"] += 1
    versions = defaultdict(set)
    for n in nodes:
        if n["type"] == PACKAGE and n["version"]:
            versions[(n["ecosystem"], n["name"])].add(n["version"])
    dependents = defaultdict(set)
    for e in g["edges"]:
        dependents[e["to"]].add(e["from"])
    top = sorted(((len(v), k) for k, v in dependents.items() if eco_of.get(k) and k not in g["roots"]),
                 key=lambda t: (-t[0], t[1]))[:10]
    actions = [n for n in nodes if n["type"] == GITHUB_ACTION]
    depths = [n["min_depth"] for n in nodes if n["min_depth"] is not None]
    return {
        "roots": len(g["roots"]),
        "nodes": len(nodes),
        "edges": len(g["edges"]),
        "direct": sum(1 for n in nodes if n["direct"]),
        "transitive": sum(1 for n in nodes if not n["direct"]),
        "max_depth": max(depths) if depths else 0,
        "by_ecosystem": {k: by_eco[k] for k in sorted(by_eco)},
        "multiple_versions": [{"ecosystem": e, "name": n, "versions": sorted(v)}
                              for (e, n), v in sorted(versions.items()) if len(v) > 1],
        "top_dependents": [{"id": k, "dependents": c} for c, k in top],
        "container_images": sorted(n["id"] for n in nodes if n["type"] == CONTAINER_IMAGE),
        "github_actions": {
            "pinned": sum(1 for a in actions if a["properties"].get("pinned_to_sha")),
            "unpinned": sum(1 for a in actions if a["properties"].get("pinned_to_sha") is False),
            "local": sum(1 for a in actions if a["properties"].get("local")),
        },
        "unresolved_versions": sum(1 for n in nodes if n["properties"].get("version_unresolved")),
        "unsupported": len(g["unsupported"]),
    }
