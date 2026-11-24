"""Agent 3 - Supply-chain integrity: risks that are not CVEs.

Typosquats, install scripts, non-registry sources, integrity hashes, Dockerfile and GitHub
Actions rules, and a Trivy scan of the shipped base image. Runs in parallel with the
vulnerability agent."""
from __future__ import annotations

from .base import Agent


class IntegrityAgent(Agent):
    id = "integrity"
    name = "Supply-chain integrity agent"
    role = "Find tampering signals that no CVE list knows: typosquats, install scripts, odd sources, risky Dockerfile and CI steps."
    step = "tamper"
    tools = ["typosquat detector (edit distance + npm downloads)", "lifecycle-script inspector",
             "source / integrity checker", "Dockerfile rules", "GitHub Actions rules", "Trivy image scan"]
    max_attempts = 2
    service = "the npm downloads API"

    def run(self, state: dict) -> dict:
        from ..container_ci import trivy_image_scan
        from ..pipeline import _non_vuln_checks, _pick_image
        c = self.ctx
        self.emit("running", "Checking for look-alike names, install scripts, odd download sources, Dockerfile and CI risks")
        other, images, workflows = _non_vuln_checks(c.target, state["inv"], state["graph"])
        extra = []
        img = _pick_image(images) if c.use_trivy else None
        if img:
            self.emit("running", f"Scanning the container base image {img} with Trivy")
            f = trivy_image_scan(img, c.cache, c.out)
            if f:
                extra.append(f)
        self.emit("done", f"{len(other)} supply-chain warnings beyond known CVEs",
                  {"warnings": len(other), "images": len(set(images)), "workflows": len(workflows)})
        cats: dict[str, int] = {}
        for f in other:
            cats[f.category] = cats.get(f.category, 0) + 1
        self.summary = f"{len(other)} warnings across {len(set(images))} images and {len(workflows)} workflows."
        self.outputs = {"warnings": len(other), "by_category": cats, "images": sorted(set(images)),
                        "workflows": workflows, "trivy_image": img if extra else None}
        return {"other": other, "images": images, "workflows": workflows, "image_findings": extra}

    def fallback(self, state: dict) -> dict:
        return {"other": [], "images": [], "workflows": [], "image_findings": []}
