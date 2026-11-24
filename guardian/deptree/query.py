"""Graph queries shared by the API and future CVE/defect agents."""
from __future__ import annotations

from collections import defaultdict, deque


def index(graph: dict):
    parents = defaultdict(list)
    children = defaultdict(list)
    for e in graph["edges"]:
        parents[e["to"]].append(e)
        children[e["from"]].append(e)
    return parents, children


def paths_to(graph: dict, node_id: str, limit: int = 50) -> list[list[str]]:
    """Up to `limit` acyclic paths root -> node_id, shortest first."""
    parents, _ = index(graph)
    roots = set(graph["roots"])
    out = []
    q = deque([[node_id]])
    while q and len(out) < limit:
        path = q.popleft()
        head = path[0]
        if head in roots:
            out.append(path)
            continue
        for e in sorted(parents.get(head, []), key=lambda e: e["from"]):
            if e["from"] not in path:
                q.append([e["from"]] + path)
        if len(q) > 200_000:
            break
    return out


def find(graph: dict, name: str | None = None, ecosystem: str | None = None,
         version: str | None = None, purl: str | None = None) -> list[dict]:
    res = []
    for n in graph["nodes"]:
        if purl and n.get("purl") != purl:
            continue
        if name and n["name"] != name:
            continue
        if ecosystem and n["ecosystem"] != ecosystem:
            continue
        if version and n.get("version") != version:
            continue
        res.append(n)
    return res
