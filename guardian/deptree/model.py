"""Core data model: nodes, edges, partial graphs and Package URL helpers."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import quote

SCHEMA_VERSION = "1.0"

# Relations. Additive: consumers must ignore relations they do not know.
DEPENDS_ON = "depends_on"
USES_BASE_IMAGE = "uses_base_image"
USES_IMAGE = "uses_image"  # docker-compose service image / CI job container
USES_ACTION = "uses_action"

APPLICATION = "application"
PACKAGE = "package"
CONTAINER_IMAGE = "container-image"
GITHUB_ACTION = "github-action"


def _enc(segment: str, safe: str = "") -> str:
    return quote(segment, safe=safe)


def purl(ptype: str, name: str, version: str | None = None, namespace: str | None = None,
         qualifiers: dict | None = None, subpath: str | None = None) -> str:
    """Build a Package URL (https://github.com/package-url/purl-spec)."""
    out = f"pkg:{ptype}/"
    if namespace:
        out += "/".join(_enc(p) for p in namespace.split("/")) + "/"
    out += _enc(name)
    if version:
        out += "@" + _enc(version, safe=":.-_~+!")
    if qualifiers:
        q = {k: v for k, v in qualifiers.items() if v}
        if q:
            out += "?" + "&".join(f"{k}={_enc(str(v), safe=':/.-_~')}" for k, v in sorted(q.items()))
    if subpath:
        out += "#" + "/".join(_enc(p) for p in subpath.strip("/").split("/"))
    return out


def npm_purl(name: str, version: str | None) -> str:
    if name.startswith("@") and "/" in name:
        ns, n = name.split("/", 1)
        return purl("npm", n, version, namespace=ns)
    return purl("npm", name, version)


def _merge_props(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        if k not in out:
            out[k] = v
        elif isinstance(out[k], list) and isinstance(v, list):
            merged = list(out[k])
            for item in v:
                if item not in merged:
                    merged.append(item)
            out[k] = sorted(merged, key=lambda x: json.dumps(x, sort_keys=True))
    return out


@dataclass
class Node:
    id: str
    type: str
    ecosystem: str
    name: str
    version: str | None = None
    purl: str | None = None
    resolved: str | None = None
    integrity: str | None = None
    evidence: list[dict] = field(default_factory=list)
    properties: dict = field(default_factory=dict)

    def merge(self, other: "Node") -> None:
        for ev in other.evidence:
            if ev not in self.evidence:
                self.evidence.append(ev)
        self.resolved = self.resolved or other.resolved
        self.integrity = self.integrity or other.integrity
        if self.version is None:
            self.version = other.version
        self.properties = _merge_props(self.properties, other.properties)


@dataclass
class Edge:
    source: str
    target: str
    relation: str = DEPENDS_ON
    scope: str | None = None
    declared_range: str | None = None
    properties: dict = field(default_factory=dict)

    def key(self) -> tuple:
        return (self.source, self.target, self.relation, self.scope or "",
                json.dumps(self.properties, sort_keys=True))


@dataclass
class PartialGraph:
    """What a single parser returns for a single manifest (one sub-root)."""
    roots: list[str] = field(default_factory=list)
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: dict[tuple, Edge] = field(default_factory=dict)
    unsupported: list[dict] = field(default_factory=list)
    unresolved: list[dict] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)

    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        existing.merge(node)
        return existing

    def add_root(self, node: Node) -> Node:
        n = self.add_node(node)
        if n.id not in self.roots:
            self.roots.append(n.id)
        return n

    def add_edge(self, edge: Edge) -> None:
        k = edge.key()
        if k not in self.edges:
            self.edges[k] = edge
        elif edge.declared_range and not self.edges[k].declared_range:
            self.edges[k].declared_range = edge.declared_range

    def merge(self, other: "PartialGraph") -> None:
        for r in other.roots:
            if r not in self.roots:
                self.roots.append(r)
        for n in other.nodes.values():
            self.add_node(n)
        for e in other.edges.values():
            self.add_edge(e)
        self.unsupported.extend(other.unsupported)
        self.unresolved.extend(other.unresolved)
        self.checks.extend(other.checks)


class Unsupported(Exception):
    """Raised by a parser when it recognises a file but cannot extract a graph from it."""
