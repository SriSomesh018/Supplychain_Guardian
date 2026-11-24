"""Dockerfile (every FROM incl. multi-stage, COPY --from=<image>) and docker-compose image: parsers."""
from __future__ import annotations

import re
from pathlib import Path

from ..model import (APPLICATION, CONTAINER_IMAGE, USES_BASE_IMAGE, USES_IMAGE, Edge, Node,
                     PartialGraph, Unsupported, purl)
from ..registry import Parser, register

_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?[-+]([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def substitute(value: str, env: dict) -> tuple[str, list[str]]:
    missing = []

    def rep(m):
        name = m.group(1) or m.group(3)
        default = m.group(2)
        if env.get(name) not in (None, ""):
            return env[name]
        if default is not None:
            return default
        missing.append(name)
        return m.group(0)

    return _VAR.sub(rep, value), missing


def parse_image_ref(ref: str) -> dict:
    """'gcr.io/distroless/node:18@sha256:..' -> registry/repository/tag/digest + purl."""
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = None
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
    parts = ref.split("/")
    registry = None
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry, parts = parts[0], parts[1:]
    if registry in (None, "docker.io", "index.docker.io", "registry-1.docker.io"):
        registry = "docker.io"
        if len(parts) == 1:
            parts = ["library"] + parts
    repository = "/".join(parts)
    if not tag and not digest:
        tag = "latest"
    display = repository[len("library/"):] if registry == "docker.io" and repository.startswith("library/") \
        else repository
    if registry != "docker.io":
        display = f"{registry}/{repository}"
    ns, _, name = repository.rpartition("/")
    qualifiers = {"repository_url": registry if registry != "docker.io" else None,
                  "tag": tag if digest else None}
    p = purl("docker", name, digest or tag, namespace=ns or None, qualifiers=qualifiers)
    return {"registry": registry, "repository": repository, "tag": tag, "digest": digest,
            "display": display, "purl": p, "pinned_by_digest": bool(digest)}


def image_node(ref: str, ev: dict, extra_props: dict | None = None) -> Node:
    info = parse_image_ref(ref)
    props = {k: info[k] for k in ("registry", "repository", "tag", "digest", "pinned_by_digest")}
    props.update(extra_props or {})
    return Node(id=info["purl"], type=CONTAINER_IMAGE, ecosystem="docker", name=info["display"],
                version=info["digest"] or info["tag"], purl=info["purl"], evidence=[ev],
                properties=props)


def _logical_lines(text: str):
    """Join backslash continuations; yield (first_line_no, line)."""
    buf, start = "", None
    for i, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not buf and (not stripped or stripped.startswith("#")):
            continue
        if buf and stripped.startswith("#"):
            continue
        if start is None:
            start = i
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        buf += stripped
        yield start, buf
        buf, start = "", None
    if buf:
        yield start, buf


def is_dockerfile(path: Path) -> bool:
    n = path.name
    return n.startswith("Dockerfile") or n.endswith((".Dockerfile", ".dockerfile"))


@register
class DockerfileParser(Parser):
    name = "dockerfile"
    ecosystem = "docker"
    priority = 30

    def detect(self, path: Path) -> bool:
        return is_dockerfile(path)

    def parse(self, path: Path, ctx) -> PartialGraph:
        rel = ctx.rel(path)
        root_id = f"app:{rel}"
        pg = PartialGraph()
        global_args: dict[str, str] = {}
        stage_args: dict[str, str] = {}
        stages: list[dict] = []
        uses: list[tuple] = []  # (stage_index, ref, locator, kind)
        for line_no, line in _logical_lines(path.read_text(errors="replace")):
            parts = line.split(None, 1)
            instr = parts[0].upper()
            rest = parts[1] if len(parts) > 1 else ""
            if instr == "ARG":
                for tok in rest.split():
                    k, _, v = tok.partition("=")
                    target = stage_args if stages else global_args
                    target[k] = v.strip('"\'') if v else global_args.get(k, "")
            elif instr == "FROM":
                toks = [t for t in rest.split() if not t.startswith("--")]
                if not toks:
                    continue
                image_raw = toks[0]
                alias = toks[2] if len(toks) >= 3 and toks[1].lower() == "as" else None
                image, missing = substitute(image_raw, global_args)
                stage_args = {}
                is_stage = image.lower() in {s["name"].lower() for s in stages if s["name"]}
                stage = {"index": len(stages), "name": alias, "base": image,
                         "base_is_stage": is_stage, "line": line_no}
                if missing:
                    stage["unresolved_args"] = missing
                stages.append(stage)
                if not is_stage and image.lower() != "scratch":
                    uses.append((stage["index"], image, f"line {line_no}: FROM {image_raw}",
                                 "from", missing))
            elif instr in ("COPY", "ADD") and stages:
                m = re.search(r"--from=(\S+)", rest)
                if m:
                    ref, missing = substitute(m.group(1), {**global_args, **stage_args})
                    names = {s["name"].lower() for s in stages if s["name"]}
                    if ref.lower() not in names and not ref.isdigit():
                        uses.append((len(stages) - 1, ref,
                                     f"line {line_no}: {instr} --from={m.group(1)}", "copy-from",
                                     missing))
        if not stages:
            raise Unsupported("no FROM instruction found")
        final = len(stages) - 1
        pg.add_root(Node(id=root_id, type=APPLICATION, ecosystem="docker", name=rel,
                         evidence=[{"file": rel, "locator": "$"}],
                         properties={"manifest": rel, "stages": stages}))
        for idx, ref, loc, kind, missing in uses:
            st = stages[idx]
            n = pg.add_node(image_node(ref, {"file": rel, "locator": loc}))
            if missing:
                n.properties["unresolved_args"] = missing
                pg.unresolved.append({"root": root_id, "name": ref,
                                      "reason": f"build ARG(s) without default: {', '.join(missing)}"})
            pg.add_edge(Edge(root_id, n.id, relation=USES_BASE_IMAGE,
                             scope="runtime" if idx == final and kind == "from" else "build",
                             properties={"stage": st["name"] or str(idx), "stage_index": idx,
                                         "kind": kind}))
        return pg


@register
class ComposeParser(Parser):
    name = "docker-compose"
    ecosystem = "docker"
    priority = 30

    def detect(self, path: Path) -> bool:
        n = path.name
        return (n.startswith("docker-compose") and n.endswith((".yml", ".yaml"))) or \
            n in ("compose.yml", "compose.yaml")

    def parse(self, path: Path, ctx) -> PartialGraph:
        import yaml
        rel = ctx.rel(path)
        root_id = f"app:{rel}"
        data = yaml.safe_load(path.read_text()) or {}
        services = data.get("services") if isinstance(data, dict) else None
        if not isinstance(services, dict):
            raise Unsupported("no services: section")
        pg = PartialGraph()
        builds = []
        for svc, spec in sorted(services.items()):
            spec = spec or {}
            if spec.get("build") is not None:
                b = spec["build"]
                builds.append({"service": svc, "context": b if isinstance(b, str) else b.get("context"),
                               "dockerfile": None if isinstance(b, str) else b.get("dockerfile")})
        pg.add_root(Node(id=root_id, type=APPLICATION, ecosystem="docker", name=rel,
                         evidence=[{"file": rel, "locator": "$"}],
                         properties={"manifest": rel, "local_builds": builds}))
        for svc, spec in sorted(services.items()):
            img = (spec or {}).get("image")
            if not img:
                continue
            ref, missing = substitute(str(img), {})
            n = pg.add_node(image_node(ref, {"file": rel, "locator": f"services.{svc}.image"}))
            if missing:
                pg.unresolved.append({"root": root_id, "name": ref,
                                      "reason": f"env variable(s) without default: {', '.join(missing)}"})
            pg.add_edge(Edge(root_id, n.id, relation=USES_IMAGE, scope="runtime",
                             properties={"service": svc}))
        return pg
