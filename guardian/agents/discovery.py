"""Agent 1 - Discovery: what is in the application.

Reads package.json + package-lock.json, builds the dependency graph, writes the CycloneDX SBOM
(optionally cross-checked with Syft) and maps every other manifest (containers, CI, other
ecosystems) into the full graph."""
from __future__ import annotations

from ..discover import discover
from ..graph import DepGraph
from ..sbom import syft_crosscheck, write_sbom
from .base import Agent


class DiscoveryAgent(Agent):
    id = "discovery"
    name = "Discovery agent"
    role = "Inventory every component: direct and transitive dependencies, SBOM, full multi-manifest graph."
    step = "discover"
    tools = ["lockfile parser (Node resolution)", "networkx dependency graph", "CycloneDX SBOM writer",
             "Syft cross-check", "deptree full graph"]
    critical = True

    def run(self, state: dict) -> dict:
        from ..pipeline import _full_graph
        c = self.ctx
        self.emit("running", "Reading package.json and package-lock.json")
        inv = discover(c.target)
        graph = DepGraph(inv)
        stats = graph.stats()
        self.emit("done", f"{stats['direct']} packages chosen by the developers pulled in "
                          f"{stats['transitive']:,} more", {"direct": stats["direct"],
                          "transitive": stats["transitive"], "total": stats["total_components"]})

        self.emit("running", "Linking every package to the packages that need it", step="sbom")
        sbom_path = write_sbom(inv, c.out)
        syft = syft_crosscheck(c.target, c.out) if c.use_syft else {"available": False, "skipped": True}
        if syft.get("npm_components") is not None:
            syft["guardian_runtime_unique"] = stats["runtime_unique_name_versions"]
            syft["note"] = ("Syft catalogs production (non-dev) packages, de-duplicated by name@version; "
                            "compare with guardian_runtime_unique")
        self.emit("running", "Mapping every manifest in the repository (npm, containers, CI) into one full graph",
                  step="sbom")
        full_graph = _full_graph(c.target, c.out, c.meta.get("slug", c.target.name))
        self.emit("done", f"{stats['edges']:,} links, up to {stats['max_depth']} levels deep. SBOM written",
                  {"edges": stats["edges"], "depth": stats["max_depth"], "syft": syft.get("npm_components")},
                  step="sbom")

        self.summary = (f"{stats['total_components']:,} components ({stats['direct']} direct), "
                        f"{stats['edges']:,} edges, depth {stats['max_depth']}.")
        self.outputs = {"components": stats["total_components"], "direct": stats["direct"],
                        "edges": stats["edges"], "max_depth": stats["max_depth"],
                        "full_graph_manifests": (full_graph or {}).get("manifests"),
                        "full_graph_packages": (full_graph or {}).get("nodes"),
                        "syft_components": syft.get("npm_components")}
        return {"inv": inv, "graph": graph, "stats": stats, "sbom_path": sbom_path, "syft": syft,
                "full_graph": full_graph}
