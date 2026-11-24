"""Agent 4 - Change detection: what is new since the last known-good state.

Diffs packages, hashes, sources and scripts against the baseline and marks every finding that did
not exist before. The orchestrator only routes here when a baseline exists."""
from __future__ import annotations

from ..anomalies import diff_against_baseline
from ..discover import discover
from ..graph import DepGraph
from ..sbom import write_sbom
from ..vulns import scan_vulnerabilities
from .base import Agent


class ChangeAgent(Agent):
    id = "change"
    name = "Change detection agent"
    role = "Compare with the last known-good copy: new packages, silent hash or source changes, new scripts, images and workflows."
    step = "compare"
    tools = ["lockfile diff", "baseline re-scan (OSV + rules)", "finding signature matcher"]
    max_attempts = 2
    service = "OSV.dev (baseline re-scan)"

    def run(self, state: dict) -> dict:
        from ..pipeline import _non_vuln_checks, _signature
        c = self.ctx
        findings = list(state["findings"])
        self.emit("running", "Comparing every package, hash and script with the last known-good copy")
        b_inv = discover(c.baseline)
        b_graph = DepGraph(b_inv)
        diff_f, changes = diff_against_baseline(b_inv, state["inv"], state["graph"])
        b_vulns, _ = scan_vulnerabilities(b_inv, b_graph, c.cache)
        b_other, b_images, b_wfs = _non_vuln_checks(c.baseline, b_inv, b_graph)
        base_sigs = {_signature(x) for x in b_vulns + b_other}
        base_labels = {c.label for c in b_inv.components.values()}
        for f in findings:
            if f.id.startswith("IMAGE-"):
                continue
            if f.id == "HEALTH-deprecated-transitive":  # summary finding: new if any listed package is new
                pk = (f.evidence[0].data.get("packages") if f.evidence else None) or []
                f.changed = any(p not in base_labels for p in pk)
            elif f.category in ("vulnerability", "malicious-package") or f.id.startswith("HEALTH-"):
                # package-level facts: new only if this exact name@version was not in the baseline
                # (the baseline is re-scanned with fewer sources, so signatures alone would over-report)
                f.changed = f.component not in base_labels
            else:
                f.changed = _signature(f) not in base_sigs
        changes["new_images"] = sorted(set(state["images"]) - set(b_images))
        changes["new_workflows"] = sorted(set(state["workflows"]) - set(b_wfs))
        findings += diff_f
        changes["new_findings"] = sum(1 for f in findings if f.changed)
        changes["baseline_label"] = c.meta.get("baseline_label", "trusted baseline")
        write_sbom(b_inv, c.out, "sbom.baseline.cdx.json")
        self.emit("done", f"{changes['new_findings']} findings are new since the baseline", {"new": changes["new_findings"]})
        self.summary = (f"{changes['new_findings']} new findings; {len(changes.get('added') or [])} packages added, "
                        f"{len(changes.get('integrity_changed') or [])} silent content changes.")
        self.outputs = {"new_findings": changes["new_findings"], "added": len(changes.get("added") or []),
                        "integrity_changed": len(changes.get("integrity_changed") or []),
                        "source_changed": len(changes.get("source_changed") or []),
                        "scripts_changed": len(changes.get("scripts_changed") or []),
                        "new_images": changes["new_images"], "new_workflows": changes["new_workflows"]}
        return {"findings": findings, "changes": changes}

    def fallback(self, state: dict) -> dict:
        return {"findings": list(state["findings"]), "changes": {"error": "baseline comparison failed"}}
