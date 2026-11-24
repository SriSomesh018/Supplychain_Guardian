"""GitHub Actions workflow parser: every `uses:` (steps and reusable workflows) plus job images."""
from __future__ import annotations

import re
from pathlib import Path

from ..model import (APPLICATION, GITHUB_ACTION, USES_ACTION, USES_IMAGE, Edge, Node,
                     PartialGraph, Unsupported, purl)
from ..registry import Parser, register
from .containers import image_node

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_USES_LINE = re.compile(r"""uses:\s*["']?([^\s"'#]+)["']?\s*(?:#\s*(.*))?$""")


def action_node(uses: str, ev: dict, comment: str | None) -> Node:
    if uses.startswith("./") or uses.startswith("../"):
        nid = f"local-action:{uses}"
        return Node(id=nid, type=GITHUB_ACTION, ecosystem="github-actions", name=uses,
                    evidence=[ev], properties={"local": True, "pinned_to_sha": None})
    ref = None
    target = uses
    if "@" in uses:
        target, ref = uses.rsplit("@", 1)
    parts = target.split("/")
    owner, repo, sub = parts[0], parts[1] if len(parts) > 1 else "", "/".join(parts[2:])
    p = purl("github", repo, ref, namespace=owner, subpath=sub or None)
    pinned = bool(ref and SHA_RE.match(ref))
    if pinned:
        ref_type = "sha"
    elif ref and re.match(r"^v?\d+(\.\d+)*$", ref):
        ref_type = "tag"
    else:
        ref_type = "branch-or-tag" if ref else "none"
    props = {"pinned_to_sha": pinned, "ref_type": ref_type, "repository": f"{owner}/{repo}"}
    if sub:
        props["path"] = sub
    if comment:
        props["version_comment"] = comment.strip()
    return Node(id=p, type=GITHUB_ACTION, ecosystem="github-actions", name=target, version=ref,
                purl=p, evidence=[ev], properties=props)


@register
class WorkflowParser(Parser):
    name = "github-workflow"
    ecosystem = "github-actions"
    priority = 30

    def detect(self, path: Path) -> bool:
        return path.suffix in (".yml", ".yaml") and path.parent.name == "workflows" \
            and path.parent.parent.name == ".github"

    def parse(self, path: Path, ctx) -> PartialGraph:
        import yaml
        rel = ctx.rel(path)
        text = path.read_text()
        data = yaml.safe_load(text)
        if not isinstance(data, dict) or not isinstance(data.get("jobs"), dict):
            raise Unsupported("no jobs: section")
        comments = {}
        for line in text.splitlines():
            m = _USES_LINE.search(line.strip())
            if m and m.group(2) and m.group(1) not in comments:
                comments[m.group(1)] = m.group(2)
        root_id = f"app:{rel}"
        pg = PartialGraph()
        pg.add_root(Node(id=root_id, type=APPLICATION, ecosystem="github-actions",
                         name=data.get("name") or rel, evidence=[{"file": rel, "locator": "$"}],
                         properties={"manifest": rel, "note": "analysed as data only"}))

        def add_uses(uses, locator, job):
            uses = str(uses).strip()
            ev = {"file": rel, "locator": locator}
            if uses.startswith("docker://"):
                n = pg.add_node(image_node(uses[len("docker://"):], ev))
                pg.add_edge(Edge(root_id, n.id, relation=USES_IMAGE, scope="ci",
                                 properties={"job": job}))
                return
            n = pg.add_node(action_node(uses, ev, comments.get(uses)))
            pg.add_edge(Edge(root_id, n.id, relation=USES_ACTION, scope="ci",
                             properties={"job": job}))

        for job_id, job in sorted(data["jobs"].items()):
            job = job or {}
            if job.get("uses"):
                add_uses(job["uses"], f"jobs.{job_id}.uses", job_id)
            for i, step in enumerate(job.get("steps") or []):
                if isinstance(step, dict) and step.get("uses"):
                    add_uses(step["uses"], f"jobs.{job_id}.steps[{i}].uses", job_id)
            cont = job.get("container")
            img = cont.get("image") if isinstance(cont, dict) else cont
            images = [(img, f"jobs.{job_id}.container")] if img else []
            for svc, spec in sorted((job.get("services") or {}).items()):
                simg = spec.get("image") if isinstance(spec, dict) else None
                if simg:
                    images.append((simg, f"jobs.{job_id}.services.{svc}.image"))
            for img, loc in images:
                if "${{" in str(img):
                    pg.unresolved.append({"root": root_id, "name": str(img),
                                          "reason": "image uses a workflow expression"})
                    continue
                n = pg.add_node(image_node(str(img), {"file": rel, "locator": loc}))
                pg.add_edge(Edge(root_id, n.id, relation=USES_IMAGE, scope="ci",
                                 properties={"job": job_id}))
        return pg
