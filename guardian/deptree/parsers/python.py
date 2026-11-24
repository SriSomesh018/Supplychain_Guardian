"""Python: requirements*.txt, Pipfile.lock, poetry.lock, uv.lock, pyproject.toml, setup.cfg."""
from __future__ import annotations

import configparser
import json
import re
import tomllib
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from ..model import PartialGraph, Unsupported, purl
from ..registry import Parser, register
from ._common import edge, make_root, pkg, transitive_unresolved

ECO = "pypi"


def ppurl(name, version=None):
    return purl("pypi", canonicalize_name(name), version)


def pinned_version(req: Requirement):
    specs = list(req.specifier)
    if len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
        return specs[0].version
    return None


def add_requirement(pg, root_id, line, file, locator, scope="prod"):
    try:
        req = Requirement(line)
    except InvalidRequirement:
        pg.unsupported.append({"file": file, "reason": f"unparseable requirement at {locator}: {line!r}"})
        return
    ver = pinned_version(req)
    n = pkg(pg, ECO, canonicalize_name(req.name), ver, ppurl(req.name, ver), file, locator,
            marker=str(req.marker) if req.marker else None,
            extras=sorted(req.extras) or None, url=req.url)
    edge(pg, root_id, n.id, scope, str(req.specifier) or None)


# ------------------------------------------------------------------------ requirements

@register
class RequirementsParser(Parser):
    name = "pip-requirements"
    ecosystem = ECO
    priority = 30

    def detect(self, path: Path) -> bool:
        return path.name.startswith("requirements") and path.suffix == ".txt"

    def parse(self, path: Path, ctx) -> PartialGraph:
        pg = PartialGraph()
        rel = ctx.rel(path)
        root_id = make_root(pg, ctx, path, ECO, "manifest-only")
        scope = "dev" if re.search(r"(dev|test|lint|doc)", path.name) else "prod"
        self._read(pg, ctx, path, root_id, scope, set())
        all_pinned = all(n.version for n in pg.nodes.values() if n.type == "package")
        if all_pinned and len(pg.nodes) > 1:
            pg.nodes[root_id].properties["resolution"] = "pinned-requirements (flat)"
        transitive_unresolved(pg, root_id, "requirements files do not record the dependency graph")
        return pg

    def _read(self, pg, ctx, path, root_id, scope, seen):
        if path.resolve() in seen:
            return
        seen.add(path.resolve())
        rel = ctx.rel(path)
        lines = path.read_text(errors="replace").splitlines()
        buf = ""
        for i, raw in enumerate(lines, 1):
            line = raw.split(" #")[0].strip() if not raw.strip().startswith("#") else ""
            if line.endswith("\\"):
                buf += line[:-1] + " "
                continue
            line = (buf + line).strip()
            buf = ""
            if not line:
                continue
            line = re.sub(r"\s--hash=\S+", "", line).strip()
            if line.startswith(("-r ", "--requirement")):
                inc = path.parent / line.split(None, 1)[1].strip()
                if inc.exists() and ctx.project_dir.resolve() in inc.resolve().parents:
                    ctx.claim(inc, path, "included via -r")
                    self._read(pg, ctx, inc, root_id, scope, seen)
                else:
                    pg.unsupported.append({"file": rel, "reason": f"line {i}: include not found: {line}"})
            elif line.startswith(("-c ", "--constraint")):
                pg.nodes[root_id].properties.setdefault("constraints", []).append(line.split(None, 1)[1])
            elif line.startswith(("-e ", "--editable")):
                pg.unsupported.append({"file": rel, "reason": f"line {i}: editable install not resolved: {line}"})
            elif line.startswith("-"):
                continue  # index options etc.
            else:
                add_requirement(pg, root_id, line, rel, f"line {i}", scope)


# ------------------------------------------------------------------------- Pipfile.lock

@register
class PipfileLockParser(Parser):
    name = "pipfile-lock"
    ecosystem = ECO
    priority = 15

    def detect(self, path: Path) -> bool:
        return path.name == "Pipfile.lock"

    def parse(self, path: Path, ctx) -> PartialGraph:
        pg = PartialGraph()
        rel = ctx.rel(path)
        data = json.loads(path.read_text())
        pipfile = path.parent / "Pipfile"
        direct = {}
        if pipfile.exists():
            ctx.claim(pipfile, path, "manifest for Pipfile.lock")
            pf = tomllib.loads(pipfile.read_text())
            for sect, scope in (("packages", "prod"), ("dev-packages", "dev")):
                for n, spec in (pf.get(sect) or {}).items():
                    direct[(canonicalize_name(n), scope)] = spec if isinstance(spec, str) else spec.get("version")
        root_id = make_root(pg, ctx, path, ECO, "lockfile (flat)")
        for sect, scope in (("default", "prod"), ("develop", "dev")):
            for name, e in sorted((data.get(sect) or {}).items()):
                ver = (e.get("version") or "").lstrip("=") or None
                n = pkg(pg, ECO, canonicalize_name(name), ver, ppurl(name, ver), rel,
                        f'{sect}["{name}"]', integrity=",".join(e.get("hashes", [])[:1]) or None)
                if not direct or (canonicalize_name(name), scope) in direct:
                    edge(pg, root_id, n.id, scope, direct.get((canonicalize_name(name), scope)))
                else:
                    edge(pg, root_id, n.id, scope, None, flat_lock=True, direct=False)
        transitive_unresolved(pg, root_id, "Pipfile.lock is flat; parent of each transitive package unknown")
        return pg


# --------------------------------------------------------------- poetry.lock / uv.lock

def _pyproject_direct(pp: dict) -> list[tuple[str, str, str]]:
    out = []
    for r in (pp.get("project") or {}).get("dependencies") or []:
        out.append((r, "prod", "project.dependencies"))
    for grp, reqs in ((pp.get("project") or {}).get("optional-dependencies") or {}).items():
        out += [(r, "optional", f"project.optional-dependencies.{grp}") for r in reqs]
    for grp, reqs in (pp.get("dependency-groups") or {}).items():
        out += [(r, "dev", f"dependency-groups.{grp}") for r in reqs if isinstance(r, str)]
    poetry = (pp.get("tool") or {}).get("poetry") or {}
    for n, spec in (poetry.get("dependencies") or {}).items():
        if n.lower() != "python":
            out.append((_poetry_req(n, spec), "prod", f"tool.poetry.dependencies.{n}"))
    groups = dict(poetry.get("group") or {})
    if poetry.get("dev-dependencies"):
        groups["dev"] = {"dependencies": poetry["dev-dependencies"]}
    for g, gd in groups.items():
        for n, spec in (gd.get("dependencies") or {}).items():
            out.append((_poetry_req(n, spec), "dev", f"tool.poetry.group.{g}.dependencies.{n}"))
    return out


def _poetry_req(name, spec):
    if isinstance(spec, dict):
        spec = spec.get("version", "")
    spec = str(spec or "").strip()
    if not spec or spec == "*":
        return name
    if spec[0] in "^~":
        return f"{name}>={spec[1:]}"  # approximate for display only
    if spec[0].isdigit():
        return f"{name}=={spec}"
    return f"{name}{spec}"


def _lock_graph(pg, ctx, lock_path, root_id, packages, direct_reqs, kind):
    rel = ctx.rel(lock_path)
    by_name = {}
    for i, p in enumerate(packages):
        by_name.setdefault(canonicalize_name(p["name"]), []).append((i, p))

    def node(i, p):
        integ = None
        files = p.get("files") or p.get("wheels") or []
        if files and isinstance(files[0], dict):
            integ = files[0].get("hash")
        return pkg(pg, ECO, canonicalize_name(p["name"]), p.get("version"),
                   ppurl(p["name"], p.get("version")), rel, f"package[{i}] ({p['name']})",
                   integrity=integ)

    def first(name):
        hits = by_name.get(canonicalize_name(name))
        return hits[0] if hits else None

    for req, scope, loc in direct_reqs:
        try:
            r = Requirement(req)
        except InvalidRequirement:
            continue
        hit = first(r.name)
        if not hit:
            pg.unresolved.append({"root": root_id, "name": r.name, "scope": scope,
                                  "reason": f"declared in {loc} but not in {kind}"})
            continue
        edge(pg, root_id, node(*hit).id, scope, str(r.specifier) or None)
    for i, p in enumerate(packages):
        s = node(i, p)
        deps = p.get("dependencies") or {}
        items = deps.items() if isinstance(deps, dict) else [(d.get("name"), d.get("version") or d.get("specifier")) for d in deps]
        opt = []
        for extra, lst in (p.get("optional-dependencies") or {}).items():
            opt += [(d.get("name"), None) for d in lst] if isinstance(lst, list) and lst and isinstance(lst[0], dict) else []
        for dname, rng, scope in [(a, b, "prod") for a, b in items] + [(a, b, "optional") for a, b in opt]:
            if not dname:
                continue
            hit = first(dname)
            if not hit:
                continue
            if isinstance(rng, dict):
                rng = rng.get("version")
            edge(pg, s.id, node(*hit).id, scope, str(rng) if rng else None)


@register
class PyprojectParser(Parser):
    """pyproject.toml is the sub-root; poetry.lock / uv.lock beside it provide the graph."""
    name = "pyproject"
    ecosystem = ECO
    priority = 15

    def detect(self, path: Path) -> bool:
        return path.name == "pyproject.toml"

    def parse(self, path: Path, ctx) -> PartialGraph:
        pg = PartialGraph()
        pp = tomllib.loads(path.read_text())
        direct = _pyproject_direct(pp)
        name = (pp.get("project") or {}).get("name") or ((pp.get("tool") or {}).get("poetry") or {}).get("name")
        for lock_name in ("uv.lock", "poetry.lock"):
            lock = path.parent / lock_name
            if lock.exists():
                ctx.claim(lock, path, "lockfile")
                root_id = make_root(pg, ctx, path, ECO, "lockfile", name=name, lockfile=ctx.rel(lock))
                data = tomllib.loads(lock.read_text())
                pkgs = [p for p in data.get("package", [])
                        if not (lock_name == "uv.lock" and canonicalize_name(p["name"]) == canonicalize_name(name or "")
                                and ("editable" in (p.get("source") or {}) or "virtual" in (p.get("source") or {})))]
                _lock_graph(pg, ctx, lock, root_id, pkgs, direct, lock_name)
                return pg
        if not direct:
            raise Unsupported("pyproject.toml declares no dependencies (build-system only)")
        root_id = make_root(pg, ctx, path, ECO, "manifest-only", name=name)
        for req, scope, loc in direct:
            add_requirement(pg, root_id, req, ctx.rel(path), loc, scope)
        transitive_unresolved(pg, root_id, "no uv.lock/poetry.lock")
        return pg


@register
class PythonOrphanLockParser(Parser):
    name = "python-lock"
    ecosystem = ECO
    priority = 25

    def detect(self, path: Path) -> bool:
        return path.name in ("poetry.lock", "uv.lock")

    def parse(self, path: Path, ctx) -> PartialGraph:
        pg = PartialGraph()
        data = tomllib.loads(path.read_text())
        pkgs = data.get("package", [])
        root_id = make_root(pg, ctx, path, ECO, "lockfile (no manifest)")
        local = [p for p in pkgs if "editable" in (p.get("source") or {}) or "virtual" in (p.get("source") or {})]
        if local:
            direct = [(d["name"], "prod", "root package") for p in local for d in p.get("dependencies", [])]
            pkgs = [p for p in pkgs if p not in local]
        else:
            direct = [(p["name"], "prod", "flat") for p in pkgs]
            transitive_unresolved(pg, root_id, "no pyproject.toml: direct dependencies unknown, all shown at depth 1")
        _lock_graph(pg, ctx, path, root_id, pkgs, direct, path.name)
        return pg


@register
class SetupCfgParser(Parser):
    name = "setup-cfg"
    ecosystem = ECO
    priority = 30

    def detect(self, path: Path) -> bool:
        return path.name == "setup.cfg"

    def parse(self, path: Path, ctx) -> PartialGraph:
        cp = configparser.ConfigParser()
        cp.read_string(path.read_text())
        reqs = []
        if cp.has_option("options", "install_requires"):
            reqs += [(r, "prod", "options.install_requires") for r in cp.get("options", "install_requires").splitlines()]
        if cp.has_section("options.extras_require"):
            for k, v in cp.items("options.extras_require"):
                reqs += [(r, "optional", f"options.extras_require.{k}") for r in v.splitlines()]
        reqs = [(r.strip(), s, l) for r, s, l in reqs if r.strip() and not r.strip().startswith("#")]
        if not reqs:
            raise Unsupported("setup.cfg declares no install_requires/extras_require")
        pg = PartialGraph()
        root_id = make_root(pg, ctx, path, ECO, "manifest-only",
                            name=cp.get("metadata", "name", fallback=None))
        for r, s, l in reqs:
            add_requirement(pg, root_id, r, ctx.rel(path), l, s)
        transitive_unresolved(pg, root_id, "setup.cfg lists direct requirements only")
        return pg
