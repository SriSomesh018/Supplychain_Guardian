"""Shared helpers for the smaller ecosystem parsers."""
from __future__ import annotations

from ..model import APPLICATION, PACKAGE, Edge, Node, PartialGraph


def make_root(pg: PartialGraph, ctx, path, ecosystem: str, resolution: str, name=None,
              version=None, **props) -> str:
    rel = ctx.rel(path)
    root_id = f"app:{rel}"
    p = {"manifest": rel, "resolution": resolution}
    p.update({k: v for k, v in props.items() if v is not None})
    pg.add_root(Node(id=root_id, type=APPLICATION, ecosystem=ecosystem, name=name or rel,
                     version=version, evidence=[{"file": rel, "locator": "$"}], properties=p))
    return root_id


def pkg(pg: PartialGraph, ecosystem: str, name: str, version, purl_str: str, file: str,
        locator: str, resolved=None, integrity=None, **props) -> Node:
    if version is None:
        props["version_unresolved"] = True
    return pg.add_node(Node(id=purl_str, type=PACKAGE, ecosystem=ecosystem, name=name,
                            version=version, purl=purl_str, resolved=resolved,
                            integrity=integrity, evidence=[{"file": file, "locator": locator}],
                            properties={k: v for k, v in props.items() if v is not None}))


def edge(pg, src, dst, scope="prod", declared_range=None, **props):
    pg.add_edge(Edge(src, dst, scope=scope, declared_range=declared_range,
                     properties={k: v for k, v in props.items() if v is not None}))


def transitive_unresolved(pg, root_id, reason):
    pg.unresolved.append({"root": root_id, "reason": f"transitive dependencies unresolved: {reason}"})
