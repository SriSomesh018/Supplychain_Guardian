"""npm / yarn / pnpm parser.

`package.json` is the sub-root. The lockfile next to it (or a workspace lockfile in
an ancestor folder) supplies the resolved graph. Without a lockfile one is generated
in a temp dir with `npm install --package-lock-only --ignore-scripts`; that fact is
recorded on the root node.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
from pathlib import Path

from ..model import APPLICATION, PACKAGE, Edge, Node, PartialGraph, Unsupported, npm_purl
from ..registry import Parser, register

LOCK_PREFERENCE = ["npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"]
SCOPE_FIELDS = [("dependencies", "prod"), ("devDependencies", "dev"),
                ("optionalDependencies", "optional"), ("peerDependencies", "peer")]


# ----------------------------------------------------------------------------- helpers

def declared_deps(pj: dict) -> list[tuple[str, str, str]]:
    """[(name, range, scope)] from package.json. optionalDependencies override dependencies."""
    optional = set((pj.get("optionalDependencies") or {}).keys())
    out = []
    for field, scope in SCOPE_FIELDS:
        deps = pj.get(field) or {}
        if not isinstance(deps, dict):
            continue
        for name, rng in sorted(deps.items()):
            if field == "dependencies" and name in optional:
                continue
            out.append((name, str(rng), scope))
    return out


def _pkg_node(name, version, ev_file, locator, resolved=None, integrity=None, src=None,
              properties=None) -> Node:
    ev = {"file": ev_file, "locator": locator}
    if src:
        ev["source"] = src
    return Node(id=npm_purl(name, version), type=PACKAGE, ecosystem="npm", name=name,
                version=version, purl=npm_purl(name, version), resolved=resolved,
                integrity=integrity, evidence=[ev], properties=properties or {})


def _split_spec(spec: str) -> tuple[str, str]:
    """'@a/b@^1.0' -> ('@a/b', '^1.0')."""
    i = spec.find("@", 1)
    if i < 0:
        return spec, ""
    return spec[:i], spec[i + 1:]


def _unresolved(pg, root_id, src, name, rng, scope, reason):
    pg.unresolved.append({"root": root_id, "from": src, "name": name, "range": rng,
                          "scope": scope, "reason": reason})


# ----------------------------------------------------------------- package-lock v2 / v3

def _nm_name(key: str) -> str:
    idx = key.rfind("node_modules/")
    return key[idx + len("node_modules/"):] if idx >= 0 else key.rsplit("/", 1)[-1]


def _parent(key: str):
    idx = key.rfind("/node_modules/")
    if idx >= 0:
        return key[:idx]
    return "" if key else None


def resolve_node_path(packages: dict, from_key: str, name: str):
    """Node's lookup: <from>/node_modules/<name>, then walk up parent paths."""
    k = from_key
    while k is not None:
        cand = f"{k}/node_modules/{name}" if k else f"node_modules/{name}"
        if cand in packages:
            return cand
        k = _parent(k)
    return None


def parse_lock_v2(pg, lock, ev_file, root_id, declared, importer=".", src=None):
    packages = lock.get("packages") or {}
    start = "" if importer in (".", "") else importer

    def deref(key):
        seen = set()
        while key in packages and packages[key].get("link") and key not in seen:
            seen.add(key)
            key = packages[key].get("resolved", "")
        return key

    def node_for(key):
        e = packages.get(key, {})
        name = e.get("name") or _nm_name(key)
        props = {}
        if "node_modules/" not in key:
            props["workspace"] = key
        if e.get("inBundle"):
            props["bundled"] = True
        return pg.add_node(_pkg_node(name, e.get("version"), ev_file,
                                     f'packages["{key}"]', e.get("resolved"),
                                     e.get("integrity"), src, props))

    queue = []
    for name, rng, scope in declared:
        tk = resolve_node_path(packages, start, name)
        if tk is None:
            _unresolved(pg, root_id, root_id, name, rng, scope,
                        "not installed (optional/peer)" if scope in ("optional", "peer")
                        else "missing from lockfile")
            continue
        tk = deref(tk)
        n = node_for(tk)
        pg.add_edge(Edge(root_id, n.id, scope=scope, declared_range=rng))
        queue.append(tk)

    visited = set()
    while queue:
        k = queue.pop()
        if k in visited:
            continue
        visited.add(k)
        e = packages.get(k, {})
        src_node = node_for(k)
        peer_meta = e.get("peerDependenciesMeta") or {}
        for field, scope in (("dependencies", "prod"), ("optionalDependencies", "optional"),
                             ("peerDependencies", "peer")):
            for dname, drng in sorted((e.get(field) or {}).items()):
                tk = resolve_node_path(packages, k, dname)
                if tk is None:
                    if scope == "prod":
                        reason = "missing from lockfile"
                    elif scope == "peer" and peer_meta.get(dname, {}).get("optional"):
                        reason = "optional peer not installed"
                    else:
                        reason = f"{scope} dependency not installed"
                    _unresolved(pg, root_id, src_node.id, dname, drng, scope, reason)
                    continue
                tk = deref(tk)
                t = node_for(tk)
                pg.add_edge(Edge(src_node.id, t.id, scope=scope, declared_range=str(drng)))
                queue.append(tk)


# ---------------------------------------------------------------------- package-lock v1

def _v1_name_version(name, entry):
    ver = entry.get("version", "")
    if ver.startswith("npm:"):
        real, v = _split_spec(ver[4:])
        return real, v
    return name, ver or None


def parse_lock_v1(pg, lock, ev_file, root_id, declared, src=None):
    top = lock.get("dependencies") or {}
    root_chain = [(top, "dependencies")]

    def find(name, chain):
        for i in range(len(chain) - 1, -1, -1):
            deps, prefix = chain[i]
            if name in deps:
                return deps[name], f'{prefix}["{name}"]', chain[:i + 1]
        return None, None, None

    def node_for(name, entry, loc):
        real, ver = _v1_name_version(name, entry)
        props = {"bundled": True} if entry.get("bundled") else {}
        return pg.add_node(_pkg_node(real, ver, ev_file, loc, entry.get("resolved"),
                                     entry.get("integrity"), src, props))

    stack = []
    for name, rng, scope in declared:
        entry, loc, chain = find(name, root_chain)
        if entry is None:
            _unresolved(pg, root_id, root_id, name, rng, scope,
                        "not installed (optional/peer)" if scope in ("optional", "peer")
                        else "missing from lockfile")
            continue
        n = node_for(name, entry, loc)
        pg.add_edge(Edge(root_id, n.id, scope=scope, declared_range=rng))
        stack.append((name, entry, loc, chain))

    visited = set()
    while stack:
        name, entry, loc, chain = stack.pop()
        if loc in visited:
            continue
        visited.add(loc)
        src_node = node_for(name, entry, loc)
        own_chain = chain + [(entry.get("dependencies") or {}, loc + ".dependencies")]
        for dname, drng in sorted((entry.get("requires") or {}).items()):
            dentry, dloc, dchain = find(dname, own_chain)
            if dentry is None:
                _unresolved(pg, root_id, src_node.id, dname, drng, "prod", "missing from lockfile")
                continue
            t = node_for(dname, dentry, dloc)
            scope = "optional" if dentry.get("optional") else "prod"
            pg.add_edge(Edge(src_node.id, t.id, scope=scope, declared_range=str(drng)))
            stack.append((dname, dentry, dloc, dchain))


# ---------------------------------------------------------------------------- yarn v1

def _unq(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] == '"':
        return s[1:-1]
    return s


def parse_yarn_v1_text(text: str) -> dict[str, dict]:
    entries: dict[str, dict] = {}
    cur = None
    section = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        s = line.strip()
        if indent == 0:
            specs = [_unq(x) for x in s.rstrip(":").split(",")]
            cur = {"_specs": specs}
            for sp in specs:
                entries[sp] = cur
            section = None
        elif cur is None:
            continue
        elif indent == 2:
            if s.endswith(":"):
                section = _unq(s[:-1])
                cur[section] = {}
            else:
                k, _, v = s.partition(" ")
                cur[_unq(k)] = _unq(v)
                section = None
        elif section:
            k, _, v = s.partition(" ")
            cur[section][_unq(k)] = _unq(v)
    return entries


def parse_yarn_v1(pg, text, ev_file, root_id, declared, src=None):
    entries = parse_yarn_v1_text(text)

    def node_for(spec, entry):
        name, rng = _split_spec(entry["_specs"][0])
        if rng.startswith("npm:"):
            name, _ = _split_spec(rng[4:])
        return pg.add_node(_pkg_node(name, entry.get("version"), ev_file,
                                     f'yarn.lock["{entry["_specs"][0]}"]',
                                     entry.get("resolved"), entry.get("integrity"), src))

    stack = []
    for name, rng, scope in declared:
        entry = entries.get(f"{name}@{rng}")
        if entry is None:
            _unresolved(pg, root_id, root_id, name, rng, scope, "missing from yarn.lock")
            continue
        n = node_for(name, entry)
        pg.add_edge(Edge(root_id, n.id, scope=scope, declared_range=rng))
        stack.append(entry)
    visited = set()
    while stack:
        entry = stack.pop()
        if id(entry) in visited:
            continue
        visited.add(id(entry))
        s = node_for(None, entry)
        for field, scope in (("dependencies", "prod"), ("optionalDependencies", "optional")):
            for dname, drng in sorted((entry.get(field) or {}).items()):
                d = entries.get(f"{dname}@{drng}")
                if d is None:
                    _unresolved(pg, root_id, s.id, dname, drng, scope, "missing from yarn.lock")
                    continue
                t = node_for(None, d)
                pg.add_edge(Edge(s.id, t.id, scope=scope, declared_range=drng))
                stack.append(d)


# -------------------------------------------------------------------------- yarn berry

def parse_yarn_berry(pg, text, ev_file, root_id, declared, src=None):
    import yaml
    data = yaml.safe_load(text) or {}
    entries = {}
    for key, entry in data.items():
        if key == "__metadata" or not isinstance(entry, dict):
            continue
        for spec in str(key).split(","):
            entries[spec.strip()] = (str(key), entry)

    def lookup(name, rng):
        for cand in (f"{name}@{rng}", f"{name}@npm:{rng}"):
            if cand in entries:
                return entries[cand]
        return None

    def node_for(key, entry):
        res = entry.get("resolution", key.split(",")[0])
        name, _ = _split_spec(res)
        props = {"checksum_format": "yarn-berry"} if entry.get("checksum") else {}
        return pg.add_node(_pkg_node(name, str(entry.get("version")), ev_file,
                                     f'yarn.lock["{key}"]', res, entry.get("checksum"), src,
                                     props))

    stack = []
    for name, rng, scope in declared:
        hit = lookup(name, rng)
        if hit is None:
            _unresolved(pg, root_id, root_id, name, rng, scope, "missing from yarn.lock")
            continue
        n = node_for(*hit)
        pg.add_edge(Edge(root_id, n.id, scope=scope, declared_range=rng))
        stack.append(hit)
    visited = set()
    while stack:
        key, entry = stack.pop()
        if key in visited:
            continue
        visited.add(key)
        s = node_for(key, entry)
        meta = entry.get("dependenciesMeta") or {}
        for dname, drng in sorted((entry.get("dependencies") or {}).items()):
            hit = lookup(dname, str(drng))
            scope = "optional" if (meta.get(dname) or {}).get("optional") else "prod"
            if hit is None:
                _unresolved(pg, root_id, s.id, dname, drng, scope, "missing from yarn.lock")
                continue
            t = node_for(*hit)
            pg.add_edge(Edge(s.id, t.id, scope=scope, declared_range=str(drng)))
            stack.append(hit)


# ------------------------------------------------------------------------------- pnpm

def _pnpm_major(lock) -> float:
    try:
        return float(str(lock.get("lockfileVersion", "5")).split(".")[0])
    except ValueError:
        return 5.0


def _pnpm_split(key: str, major: float) -> tuple[str, str]:
    k = key.lstrip("/")
    if major < 6:
        parts = k.split("/")
        if k.startswith("@"):
            name, ver = "/".join(parts[:2]), "/".join(parts[2:])
        else:
            name, ver = parts[0], "/".join(parts[1:])
        return name, ver.split("_")[0]
    k = k.split("(")[0]
    i = k.rfind("@")
    return k[:i], k[i + 1:]


def parse_pnpm(pg, lock, ev_file, root_id, declared, importer=".", src=None):
    major = _pnpm_major(lock)
    packages = {k.lstrip("/"): (k, v or {}) for k, v in (lock.get("packages") or {}).items()}
    snapshots = {k: (k, v or {}) for k, v in (lock.get("snapshots") or {}).items()}
    if "importers" in lock:
        imp = (lock["importers"] or {}).get(importer or ".", {}) or {}
    else:
        imp = lock

    def ref_key(name, ref):
        ref = str(ref)
        if ref.startswith(("link:", "file:", "workspace:")):
            return None
        if major < 6:
            return ref[1:] if ref.startswith("/") else f"{name}/{ref}"
        if major < 9:
            return ref.lstrip("/") if ref.startswith("/") else f"{name}@{ref}"
        base = ref.split("(")[0]
        return ref if "@" in base[1:] else f"{name}@{ref}"

    def deps_entry(key):
        if major >= 9:
            return snapshots.get(key) or packages.get(key.split("(")[0])
        return packages.get(key)

    def node_for(key):
        name, ver = _pnpm_split(key, major)
        meta_key = key.split("(")[0] if major >= 9 else key
        orig, meta = packages.get(meta_key, (key, {}))
        res = meta.get("resolution") or {}
        return pg.add_node(_pkg_node(meta.get("name") or name, meta.get("version") or ver,
                                     ev_file, f'packages["{orig}"]', res.get("tarball"),
                                     res.get("integrity"), src))

    # importer dependencies
    def imp_ref(field, name):
        d = (imp.get(field) or {}).get(name)
        if isinstance(d, dict):
            return d.get("version")
        return d

    stack = []
    for name, rng, scope in declared:
        field = {"prod": "dependencies", "dev": "devDependencies",
                 "optional": "optionalDependencies", "peer": "dependencies"}[scope]
        ref = imp_ref(field, name) or imp_ref("dependencies", name)
        if ref is None:
            _unresolved(pg, root_id, root_id, name, rng, scope, "missing from pnpm-lock.yaml")
            continue
        key = ref_key(name, ref)
        if key is None:
            pg.unresolved.append({"root": root_id, "from": root_id, "name": name, "range": rng,
                                  "scope": scope, "reason": f"local link ({ref})"})
            continue
        n = node_for(key)
        pg.add_edge(Edge(root_id, n.id, scope=scope, declared_range=rng))
        stack.append(key)
    visited = set()
    while stack:
        key = stack.pop()
        if key in visited:
            continue
        visited.add(key)
        s = node_for(key)
        _, entry = deps_entry(key) or (key, {})
        for field, scope in (("dependencies", "prod"), ("optionalDependencies", "optional")):
            for dname, dref in sorted((entry.get(field) or {}).items()):
                dkey = ref_key(dname, dref)
                if dkey is None:
                    continue
                t = node_for(dkey)
                pg.add_edge(Edge(s.id, t.id, scope=scope))
                stack.append(dkey)


# ------------------------------------------------------------------ lockfile selection

def _lock_has_workspace(lock_path: Path, rel: str) -> bool:
    try:
        text = lock_path.read_text()
    except OSError:
        return False
    if lock_path.name.endswith(".json"):
        try:
            return rel in (json.loads(text).get("packages") or {})
        except ValueError:
            return False
    if lock_path.name == "pnpm-lock.yaml":
        import yaml
        return rel in ((yaml.safe_load(text) or {}).get("importers") or {})
    return f"@workspace:{rel}" in text


def find_lock(pj_path: Path, project_dir: Path):
    """Return (lock_path, importer, superseded_locks)."""
    d = pj_path.parent
    present = [d / n for n in LOCK_PREFERENCE if (d / n).exists()]
    if present:
        return present[0], ".", present[1:]
    a = d.parent
    root = project_dir.resolve()
    while True:
        for n in LOCK_PREFERENCE:
            cand = a / n
            if cand.exists():
                rel = d.resolve().relative_to(a.resolve()).as_posix()
                if _lock_has_workspace(cand, rel):
                    return cand, rel, []
        if a.resolve() == root or a.resolve() == a.parent.resolve():
            break
        a = a.parent
    return None, None, []


def parse_lockfile(pg, lock_path: Path, ev_file, root_id, declared, importer=".", src=None):
    text = lock_path.read_text()
    if lock_path.name.endswith(".json"):
        lock = json.loads(text)
        v = int(lock.get("lockfileVersion", 1) or 1)
        if v >= 2 and "packages" in lock:
            parse_lock_v2(pg, lock, ev_file, root_id, declared, importer, src)
            return f"package-lock v{v}"
        if importer not in (".", ""):
            raise Unsupported("workspace importer in lockfileVersion 1")
        parse_lock_v1(pg, lock, ev_file, root_id, declared, src)
        return "package-lock v1"
    if lock_path.name == "pnpm-lock.yaml":
        import yaml
        lock = yaml.safe_load(text) or {}
        parse_pnpm(pg, lock, ev_file, root_id, declared, importer, src)
        return f"pnpm-lock v{lock.get('lockfileVersion')}"
    if "__metadata:" in text:
        parse_yarn_berry(pg, text, ev_file, root_id, declared, src)
        return "yarn.lock berry"
    parse_yarn_v1(pg, text, ev_file, root_id, declared, src)
    return "yarn.lock v1"


# ------------------------------------------------------------------- lock generation

def _cache_name(rel: str) -> str:
    return rel.replace("/", "__")


def generate_lockfile(pj_path: Path, ctx) -> tuple[Path, dict]:
    """Generate package-lock.json from package.json alone in a temp dir.

    Only package.json is copied (no .npmrc, no sources). --ignore-scripts guarantees
    no lifecycle script from the untrusted project runs.
    """
    npm = ctx.which("npm")
    if not npm:
        raise Unsupported("no lockfile committed and npm is not available to generate one")
    raw = pj_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    rel = ctx.rel(pj_path)
    cache_dir = (ctx.out_dir / "generated-lockfiles") if ctx.out_dir else None
    if cache_dir and not ctx.options.refresh_lockfiles:
        meta_p = cache_dir / (_cache_name(rel) + ".meta.json")
        lock_p = cache_dir / (_cache_name(rel) + ".package-lock.json")
        if meta_p.exists() and lock_p.exists():
            meta = json.loads(meta_p.read_text())
            if meta.get("package_json_sha256") == digest:
                return lock_p, dict(meta, cached=True)

    tmp = Path(tempfile.mkdtemp(prefix="deptree-lock-"))
    try:
        (tmp / "package.json").write_bytes(raw)
        base = [npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit",
                "--no-fund", "--package-lock=true", "--lockfile-version=3"]
        attempts = [[], ["--legacy-peer-deps"]]
        last = None
        for extra in attempts:
            proc = ctx.run(base + extra, cwd=tmp, timeout=900)
            last = proc
            if proc.returncode == 0 and (tmp / "package-lock.json").exists():
                ver = ctx.run([npm, "--version"], cwd=tmp).stdout.strip()
                meta = {"package_json_sha256": digest, "npm_version": ver,
                        "command": " ".join(["npm"] + base[1:] + extra), "cached": False}
                if cache_dir:
                    cache_dir.mkdir(parents=True, exist_ok=True)
                    lock_p = cache_dir / (_cache_name(rel) + ".package-lock.json")
                    shutil.copy(tmp / "package-lock.json", lock_p)
                    (cache_dir / (_cache_name(rel) + ".meta.json")).write_text(
                        json.dumps({k: v for k, v in meta.items() if k != "cached"},
                                   indent=2, sort_keys=True) + "\n")
                    return lock_p, meta
                keep = Path(tempfile.mkdtemp(prefix="deptree-lock-keep-")) / "package-lock.json"
                shutil.copy(tmp / "package-lock.json", keep)
                return keep, meta
            if "ERESOLVE" not in (proc.stderr + proc.stdout):
                break
        tail = (last.stderr or last.stdout or "").strip().splitlines()[-5:] if last else []
        raise Unsupported("lockfile generation failed: " + " | ".join(tail))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------- cross-check

_TARBALL = re.compile(r"/((?:@[^/]+/)?[^/@]+)/-/[^/]+\.tgz$")


def _npm_ls_set(tree: dict) -> set[str]:
    out = set()
    stack = list((tree.get("dependencies") or {}).items())
    while stack:
        name, d = stack.pop()
        if not isinstance(d, dict) or d.get("missing") or not d.get("version"):
            continue
        real = d.get("name") or name
        m = _TARBALL.search(str(d.get("resolved") or ""))
        if m:  # aliases ("x-cjs": "npm:x@1") are keyed by alias; the tarball has the real name
            real = m.group(1)
        out.add(f"{real}@{d['version']}")
        stack.extend((d.get("dependencies") or {}).items())
    return out


def npm_ls_crosscheck(pj_path: Path, lock_path: Path, ours: set[str], ctx, root_id: str) -> dict:
    res = {"check": "npm-ls", "root": root_id}
    npm = ctx.which("npm")
    if not npm:
        return dict(res, status="skipped", reason="npm not available")
    if lock_path.name not in ("package-lock.json", "npm-shrinkwrap.json") \
            and not lock_path.name.endswith(".package-lock.json"):
        return dict(res, status="skipped", reason=f"npm ls cannot read {lock_path.name}")
    tmp = Path(tempfile.mkdtemp(prefix="deptree-ls-"))
    try:
        shutil.copy(pj_path, tmp / "package.json")
        shutil.copy(lock_path, tmp / "package-lock.json")
        proc = ctx.run([npm, "ls", "--all", "--json", "--package-lock-only"], cwd=tmp,
                       timeout=600)
        try:
            tree = json.loads(proc.stdout or "{}")
        except ValueError:
            return dict(res, status="error", reason="npm ls produced invalid JSON")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    theirs = _npm_ls_set(tree)
    only_ours = sorted(ours - theirs)
    only_theirs = sorted(theirs - ours)
    return dict(res, status="match" if not only_ours and not only_theirs else "mismatch",
                ours=len(ours), npm_ls=len(theirs), only_in_deptree=only_ours,
                only_in_npm_ls=only_theirs)


# --------------------------------------------------------------------------- parsers

@register
class NpmManifestParser(Parser):
    name = "npm-package-json"
    ecosystem = "npm"
    priority = 10

    def detect(self, path: Path) -> bool:
        return path.name == "package.json"

    def parse(self, path: Path, ctx) -> PartialGraph:
        pg = PartialGraph()
        try:
            pj = json.loads(path.read_text())
        except ValueError as e:
            raise Unsupported(f"invalid JSON: {e}")
        rel = ctx.rel(path)
        root_id = f"app:{rel}"
        props = {"manifest": rel}
        declared = declared_deps(pj)
        lock, importer, superseded = find_lock(path, ctx.project_dir)
        for s in superseded:
            ctx.claim(s, path, f"superseded by {lock.name}")
            pg.unsupported.append({"file": ctx.rel(s), "reason":
                                   f"not parsed: superseded by {ctx.rel(lock)} (lockfile precedence"
                                   f" {' > '.join(LOCK_PREFERENCE)})"})
        src = None
        if lock is not None:
            ctx.claim(lock, path, "lockfile")
            ev_file = ctx.rel(lock)
            props.update(lockfile=ev_file, resolution="lockfile",
                         lockfile_generated=False)
            if importer not in (".", ""):
                props["workspace_importer"] = importer
        else:
            if not ctx.options.generate_lockfiles:
                props.update(resolution="manifest-only", lockfile=None)
                return self._manifest_only(pg, pj, rel, root_id, props, declared,
                                           "no lockfile and generation disabled")
            try:
                lock, meta = generate_lockfile(path, ctx)
            except Unsupported as e:
                props.update(resolution="manifest-only", lockfile=None)
                return self._manifest_only(pg, pj, rel, root_id, props, declared, str(e))
            src = "generated-lockfile"
            ev_file = f"{rel} (generated package-lock.json)"
            props.update(lockfile=None, resolution="generated-lockfile",
                         lockfile_generated=True,
                         generated_with=meta.get("command"),
                         generator_npm_version=meta.get("npm_version"),
                         package_json_sha256=meta.get("package_json_sha256"))
            importer = "."
        pg.add_root(Node(id=root_id, type=APPLICATION, ecosystem="npm",
                         name=pj.get("name") or rel, version=pj.get("version"),
                         evidence=[{"file": rel, "locator": "$"}], properties=props))
        fmt = parse_lockfile(pg, lock, ev_file, root_id, declared, importer, src)
        pg.nodes[root_id].properties["lockfile_format"] = fmt
        if ctx.options.crosscheck and importer in (".", ""):
            ours = {f"{n.name}@{n.version}" for n in pg.nodes.values() if n.type == PACKAGE}
            pg.checks.append(npm_ls_crosscheck(path, lock, ours, ctx, root_id))
        return pg

    @staticmethod
    def _manifest_only(pg, pj, rel, root_id, props, declared, reason):
        pg.add_root(Node(id=root_id, type=APPLICATION, ecosystem="npm",
                         name=pj.get("name") or rel, version=pj.get("version"),
                         evidence=[{"file": rel, "locator": "$"}], properties=props))
        field = {s: f for f, s in SCOPE_FIELDS}
        for name, rng, scope in declared:
            n = pg.add_node(Node(id=npm_purl(name, None), type=PACKAGE, ecosystem="npm",
                                 name=name, purl=npm_purl(name, None),
                                 evidence=[{"file": rel, "locator": f'{field[scope]}["{name}"]'}],
                                 properties={"version_unresolved": True}))
            pg.add_edge(Edge(root_id, n.id, scope=scope, declared_range=rng))
        pg.unresolved.append({"root": root_id, "reason": f"transitive dependencies unresolved: {reason}"})
        return pg


@register
class NpmOrphanLockParser(Parser):
    """A lockfile without a package.json next to it: use the lock's own root entry."""
    name = "npm-lockfile"
    ecosystem = "npm"
    priority = 20

    def detect(self, path: Path) -> bool:
        return path.name in LOCK_PREFERENCE

    def parse(self, path: Path, ctx) -> PartialGraph:
        if path.name not in ("package-lock.json", "npm-shrinkwrap.json"):
            raise Unsupported(f"{path.name} without a package.json: direct dependencies unknown")
        lock = json.loads(path.read_text())
        rootent = (lock.get("packages") or {}).get("")
        if not rootent:
            raise Unsupported("lockfile v1 without package.json: direct dependencies unknown")
        pg = PartialGraph()
        rel = ctx.rel(path)
        root_id = f"app:{rel}"
        pg.add_root(Node(id=root_id, type=APPLICATION, ecosystem="npm",
                         name=rootent.get("name") or rel, version=rootent.get("version"),
                         evidence=[{"file": rel, "locator": 'packages[""]'}],
                         properties={"lockfile": rel, "resolution": "lockfile",
                                     "note": "package.json missing; root taken from lockfile"}))
        parse_lock_v2(pg, lock, rel, root_id, declared_deps(rootent))
        return pg
