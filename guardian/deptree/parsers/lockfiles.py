"""Lockfile parsers for Go, Ruby, PHP, Rust, .NET and Java.

Lockfiles give exact versions (what CVE matching needs). Manifests without a
lockfile give direct dependencies only and are marked `version_unresolved` /
`transitive dependencies unresolved`. Build tools (mvn, gradle) are never run:
they execute project-defined code.
"""
from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

from ..model import PartialGraph, Unsupported, purl
from ..registry import Parser, register
from ._common import edge, make_root, pkg, transitive_unresolved


# ------------------------------------------------------------------------------- Go

def go_purl(module, version=None):
    ns, _, name = module.rpartition("/")
    return purl("golang", name, version, namespace=ns or None)


@register
class GoModParser(Parser):
    name = "go-mod"
    ecosystem = "golang"
    priority = 15

    def detect(self, path: Path) -> bool:
        return path.name in ("go.mod", "go.sum")

    def parse(self, path: Path, ctx) -> PartialGraph:
        if path.name == "go.sum":
            raise Unsupported("go.sum without go.mod: checksum list only, no dependency declarations")
        rel = ctx.rel(path)
        pg = PartialGraph()
        text = path.read_text()
        module = (re.search(r"^module\s+(\S+)", text, re.M) or [None, None])[1]
        sums = {}
        gosum = path.parent / "go.sum"
        if gosum.exists():
            ctx.claim(gosum, path, "checksums for go.mod")
            for line in gosum.read_text().splitlines():
                p = line.split()
                if len(p) == 3 and not p[1].endswith("/go.mod"):
                    sums[(p[0], p[1])] = p[2]
        root_id = make_root(pg, ctx, path, "golang", "go.mod (minimal version selection list)",
                            name=module, go_sum=ctx.rel(gosum) if gosum.exists() else None)
        replaces = dict(re.findall(r"^\s*(?:replace\s+)?(\S+)(?:\s+\S+)?\s+=>\s+(.+)$", text, re.M))
        in_block = False
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if s.startswith("require ("):
                in_block = True
                continue
            if in_block and s == ")":
                in_block = False
                continue
            m = None
            if in_block:
                m = re.match(r"^(\S+)\s+(\S+)(.*)$", s)
            elif s.startswith("require "):
                m = re.match(r"^require\s+(\S+)\s+(\S+)(.*)$", s)
            if not m or s.startswith("//"):
                continue
            mod, ver, rest = m.groups()
            indirect = "// indirect" in rest
            n = pkg(pg, "golang", mod, ver, go_purl(mod, ver), rel, f"line {i}",
                    integrity=sums.get((mod, ver)), replaced_by=replaces.get(mod))
            # go.mod lists every module in the build list but not who requires whom.
            edge(pg, root_id, n.id, "prod", ver, indirect=True if indirect else None)
        if any(e.properties.get("indirect") for e in pg.edges.values()):
            transitive_unresolved(pg, root_id, "go.mod marks indirect modules but not their parents "
                                               "(shown at depth 1 with indirect=true)")
        return pg


# ----------------------------------------------------------------------------- Ruby

@register
class GemfileLockParser(Parser):
    name = "gemfile-lock"
    ecosystem = "gem"
    priority = 15

    def detect(self, path: Path) -> bool:
        return path.name == "Gemfile.lock"

    def parse(self, path: Path, ctx) -> PartialGraph:
        rel = ctx.rel(path)
        pg = PartialGraph()
        gemfile = path.parent / "Gemfile"
        if gemfile.exists():
            ctx.claim(gemfile, path, "manifest for Gemfile.lock")
        root_id = make_root(pg, ctx, path, "gem", "lockfile")
        specs, direct, section, cur = {}, [], None, None
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if line and not line.startswith(" "):
                section = line.strip()
                continue
            if section in ("GEM", "GIT", "PATH"):
                m = re.match(r"^    (\S+) \(([^)]+)\)$", line)
                if m:
                    name, ver = m.groups()
                    cur = name
                    specs[name] = {"version": ver.split("-")[0], "platform_version": ver,
                                   "deps": [], "line": i, "source": section}
                    continue
                m = re.match(r"^      (\S+)(?: \(([^)]+)\))?$", line)
                if m and cur:
                    specs[cur]["deps"].append(m.groups())
            elif section == "DEPENDENCIES":
                m = re.match(r"^  (\S+?)!?(?: \(([^)]+)\))?$", line)
                if m:
                    direct.append(m.groups())

        def node(name):
            s = specs[name]
            return pkg(pg, "gem", name, s["version"], purl("gem", name, s["version"]), rel,
                       f"{s['source']} specs, line {s['line']}",
                       platform=s["platform_version"] if s["platform_version"] != s["version"] else None)

        for name, rng in direct:
            if name in specs:
                edge(pg, root_id, node(name).id, "prod", rng)
            else:
                pg.unresolved.append({"root": root_id, "name": name, "reason": "not in specs"})
        for name, s in specs.items():
            for dname, rng in s["deps"]:
                if dname in specs:
                    edge(pg, node(name).id, node(dname).id, "prod", rng)
        return pg


# ------------------------------------------------------------------------------ PHP

@register
class ComposerLockParser(Parser):
    name = "composer-lock"
    ecosystem = "composer"
    priority = 15

    def detect(self, path: Path) -> bool:
        return path.name == "composer.lock"

    def parse(self, path: Path, ctx) -> PartialGraph:
        rel = ctx.rel(path)
        pg = PartialGraph()
        data = json.loads(path.read_text())
        cj = path.parent / "composer.json"
        manifest = {}
        if cj.exists():
            ctx.claim(cj, path, "manifest for composer.lock")
            manifest = json.loads(cj.read_text())
        root_id = make_root(pg, ctx, path, "composer", "lockfile", name=manifest.get("name"))
        pkgs = {}
        for sect in ("packages", "packages-dev"):
            for i, p in enumerate(data.get(sect) or []):
                pkgs[p["name"].lower()] = (sect, i, p)

        def node(key):
            sect, i, p = pkgs[key]
            ns, _, nm = p["name"].partition("/")
            ver = str(p.get("version", "")).lstrip("v") or None
            dist = p.get("dist") or {}
            return pkg(pg, "composer", p["name"], ver, purl("composer", nm, ver, namespace=ns), rel,
                       f'{sect}[{i}] ({p["name"]})', resolved=dist.get("url"),
                       integrity=dist.get("shasum") or None)

        def is_platform(n):
            return n == "php" or n.startswith(("ext-", "lib-", "composer-"))

        if manifest:
            for field, scope in (("require", "prod"), ("require-dev", "dev")):
                for n, rng in sorted((manifest.get(field) or {}).items()):
                    if is_platform(n):
                        continue
                    if n.lower() in pkgs:
                        edge(pg, root_id, node(n.lower()).id, scope, rng)
        else:
            for key, (sect, _, _) in sorted(pkgs.items()):
                edge(pg, root_id, node(key).id, "dev" if sect == "packages-dev" else "prod",
                     flat_lock=True)
            transitive_unresolved(pg, root_id, "composer.json missing: direct dependencies unknown")
        for key, (_, _, p) in sorted(pkgs.items()):
            for n, rng in sorted((p.get("require") or {}).items()):
                if not is_platform(n) and n.lower() in pkgs:
                    edge(pg, node(key).id, node(n.lower()).id, "prod", rng)
        return pg


# ----------------------------------------------------------------------------- Rust

@register
class CargoLockParser(Parser):
    name = "cargo-lock"
    ecosystem = "cargo"
    priority = 15

    def detect(self, path: Path) -> bool:
        return path.name == "Cargo.lock"

    def parse(self, path: Path, ctx) -> PartialGraph:
        rel = ctx.rel(path)
        pg = PartialGraph()
        if (path.parent / "Cargo.toml").exists():
            ctx.claim(path.parent / "Cargo.toml", path, "manifest for Cargo.lock")
        data = tomllib.loads(path.read_text())
        pkgs = data.get("package", [])
        root_id = make_root(pg, ctx, path, "cargo", "lockfile")
        by_name: dict[str, list] = {}
        for i, p in enumerate(pkgs):
            by_name.setdefault(p["name"], []).append((i, p))

        def node(i, p):
            return pkg(pg, "cargo", p["name"], p["version"], purl("cargo", p["name"], p["version"]),
                       rel, f"package[{i}] ({p['name']} {p['version']})", resolved=p.get("source"),
                       integrity=p.get("checksum"), workspace_member=True if not p.get("source") else None)

        def find(ref):
            parts = ref.split()
            cands = by_name.get(parts[0], [])
            if len(parts) > 1:
                cands = [c for c in cands if c[1]["version"] == parts[1]]
            return cands[0] if cands else None

        for i, p in enumerate(pkgs):
            if not p.get("source"):  # workspace member
                edge(pg, root_id, node(i, p).id, "prod")
            for ref in p.get("dependencies", []):
                hit = find(ref)
                if hit:
                    edge(pg, node(i, p).id, node(*hit).id, "prod")
        return pg


# ------------------------------------------------------------------------------ .NET

@register
class NugetLockParser(Parser):
    name = "nuget-packages-lock"
    ecosystem = "nuget"
    priority = 15

    def detect(self, path: Path) -> bool:
        return path.name == "packages.lock.json"

    def parse(self, path: Path, ctx) -> PartialGraph:
        rel = ctx.rel(path)
        pg = PartialGraph()
        for proj in sorted(path.parent.glob("*.csproj")):
            ctx.claim(proj, path, "manifest for packages.lock.json")
        data = json.loads(path.read_text())
        root_id = make_root(pg, ctx, path, "nuget", "lockfile")
        for tfm, deps in sorted((data.get("dependencies") or {}).items()):
            lower = {k.lower(): k for k in deps}

            def node(name):
                e = deps[name]
                v = e.get("resolved")
                return pkg(pg, "nuget", name, v, purl("nuget", name, v), rel,
                           f'dependencies["{tfm}"]["{name}"]', integrity=e.get("contentHash"))

            for name, e in sorted(deps.items()):
                if e.get("type") == "Project":
                    continue
                if e.get("type") == "Direct":
                    edge(pg, root_id, node(name).id, "prod", e.get("requested"), target_framework=tfm)
                for d, rng in sorted((e.get("dependencies") or {}).items()):
                    if d.lower() in lower:
                        edge(pg, node(name).id, node(lower[d.lower()]).id, "prod", rng,
                             target_framework=tfm)
        return pg


@register
class CsprojParser(Parser):
    name = "csproj"
    ecosystem = "nuget"
    priority = 30

    def detect(self, path: Path) -> bool:
        return path.suffix == ".csproj"

    def parse(self, path: Path, ctx) -> PartialGraph:
        rel = ctx.rel(path)
        root = ET.fromstring(path.read_text())
        refs = [el for el in root.iter() if el.tag.split("}")[-1] == "PackageReference"]
        if not refs:
            raise Unsupported("no PackageReference elements (may use packages.config or central versions)")
        pg = PartialGraph()
        root_id = make_root(pg, ctx, path, "nuget", "manifest-only")
        for i, el in enumerate(refs):
            name = el.get("Include") or el.get("Update")
            ver = el.get("Version") or next((c.text for c in el if c.tag.split("}")[-1] == "Version"), None)
            exact = ver if ver and re.match(r"^\d[\w.\-]*$", ver) else None
            n = pkg(pg, "nuget", name, exact, purl("nuget", name, exact), rel, f"PackageReference[{i}]")
            edge(pg, root_id, n.id, "prod", ver)
        transitive_unresolved(pg, root_id, "no packages.lock.json")
        return pg


# ------------------------------------------------------------------------------ Java

def _xml_text(el, tag, ns):
    c = el.find(f"m:{tag}", ns) if ns else el.find(tag)
    return c.text.strip() if c is not None and c.text else None


@register
class PomParser(Parser):
    name = "maven-pom"
    ecosystem = "maven"
    priority = 30

    def detect(self, path: Path) -> bool:
        return path.name == "pom.xml"

    def parse(self, path: Path, ctx) -> PartialGraph:
        rel = ctx.rel(path)
        root = ET.fromstring(path.read_text())
        ns = {"m": root.tag[1:].split("}")[0]} if root.tag.startswith("{") else {}
        q = (lambda t: f"m:{t}") if ns else (lambda t: t)
        props = {}
        pe = root.find(q("properties"), ns)
        if pe is not None:
            for c in pe:
                props[c.tag.split("}")[-1]] = (c.text or "").strip()
        props["project.version"] = _xml_text(root, "version", ns) or ""

        def sub(v):
            if not v:
                return v
            return re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), v)

        managed = {}
        dm = root.find(f"{q('dependencyManagement')}/{q('dependencies')}", ns)
        if dm is not None:
            for d in dm.findall(q("dependency"), ns):
                managed[(_xml_text(d, "groupId", ns), _xml_text(d, "artifactId", ns))] = sub(_xml_text(d, "version", ns))
        pg = PartialGraph()
        root_id = make_root(pg, ctx, path, "maven", "manifest-only",
                            name=f"{_xml_text(root, 'groupId', ns)}:{_xml_text(root, 'artifactId', ns)}",
                            version=sub(_xml_text(root, "version", ns)))
        deps = root.find(q("dependencies"), ns)
        for i, d in enumerate(deps.findall(q("dependency"), ns) if deps is not None else []):
            g, a = sub(_xml_text(d, "groupId", ns)), sub(_xml_text(d, "artifactId", ns))
            v = sub(_xml_text(d, "version", ns)) or managed.get((g, a))
            exact = v if v and "${" not in v and not v.startswith(("[", "(")) else None
            scope = _xml_text(d, "scope", ns) or "compile"
            n = pkg(pg, "maven", f"{g}:{a}", exact, purl("maven", a, exact, namespace=g), rel,
                    f"dependencies.dependency[{i}]", maven_scope=scope)
            edge(pg, root_id, n.id, "dev" if scope == "test" else "prod", v)
        transitive_unresolved(pg, root_id, "pom.xml lists direct dependencies; Maven is not executed (untrusted build logic)")
        return pg


_GRADLE_DEP = re.compile(
    r"""\b(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|"""
    r"""annotationProcessor|kapt|compile|testCompile|classpath)\s*\(?\s*["']([^"':\s]+):([^"':\s]+):([^"'\s)]+)["']""")


@register
class GradleParser(Parser):
    name = "gradle"
    ecosystem = "maven"
    priority = 15

    def detect(self, path: Path) -> bool:
        return path.name in ("build.gradle", "build.gradle.kts", "gradle.lockfile")

    def parse(self, path: Path, ctx) -> PartialGraph:
        rel = ctx.rel(path)
        pg = PartialGraph()
        if path.name == "gradle.lockfile":
            root_id = make_root(pg, ctx, path, "maven", "lockfile (flat)")
            self._lockfile(pg, ctx, path, root_id, direct=None)
            return pg
        text = path.read_text()
        direct = {}
        for i, m in enumerate(_GRADLE_DEP.finditer(text)):
            conf, g, a, v = m.groups()
            direct[(g, a)] = (v, conf, f"line {text[:m.start()].count(chr(10)) + 1}")
        lock = path.parent / "gradle.lockfile"
        if lock.exists():
            ctx.claim(lock, path, "lockfile")
            root_id = make_root(pg, ctx, path, "maven", "lockfile (flat)", lockfile=ctx.rel(lock))
            self._lockfile(pg, ctx, lock, root_id, direct)
            return pg
        if not direct:
            raise Unsupported("no string-notation dependencies found (version catalogs/plugins not evaluated)")
        root_id = make_root(pg, ctx, path, "maven", "manifest-only")
        for (g, a), (v, conf, loc) in sorted(direct.items()):
            exact = v if "$" not in v and "+" not in v else None
            n = pkg(pg, "maven", f"{g}:{a}", exact, purl("maven", a, exact, namespace=g), rel, loc,
                    gradle_configuration=conf)
            edge(pg, root_id, n.id, "dev" if conf.startswith("test") else "prod", v)
        transitive_unresolved(pg, root_id, "Gradle is not executed (untrusted build logic)")
        return pg

    @staticmethod
    def _lockfile(pg, ctx, lock, root_id, direct):
        rel = ctx.rel(lock)
        for i, line in enumerate(lock.read_text().splitlines(), 1):
            if line.startswith("#") or "=" not in line or line.startswith("empty="):
                continue
            coord, confs = line.split("=", 1)
            parts = coord.split(":")
            if len(parts) != 3:
                continue
            g, a, v = parts
            scope = "dev" if all(c.startswith("test") for c in confs.split(",")) else "prod"
            n = pkg(pg, "maven", f"{g}:{a}", v, purl("maven", a, v, namespace=g), rel, f"line {i}",
                    gradle_configurations=confs.split(","))
            is_direct = direct is not None and (g, a) in direct
            edge(pg, root_id, n.id, scope, direct[(g, a)][0] if is_direct else None,
                 flat_lock=None if is_direct else True)
        transitive_unresolved(pg, root_id, "gradle.lockfile is flat; parents of transitive deps unknown")
