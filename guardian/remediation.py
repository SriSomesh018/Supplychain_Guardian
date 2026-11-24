"""Remediation with human approval (Day 2).

1. plan_fixes(): for every vulnerable package with a published fix, propose the smallest code change
   that removes all of its advisories:
     - direct dependency      -> bump its range in package.json
     - transitive dependency  -> add a version-scoped npm "overrides" entry ("name@current": "fixed")
   Proposals are deterministic. The AI explains findings but never writes code.
2. A person approves or rejects each proposal in the UI (decisions are stored with reviewer + time).
3. apply_fixes(): approved changes are applied to a SANDBOX COPY of the project (never the original),
   the lockfile is regenerated with `npm install --package-lock-only --ignore-scripts`, and the
   sandbox is re-scanned to verify which advisories are actually gone. A patch file is written.
"""
from __future__ import annotations

import difflib
import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding
from .semver import _cmp, parse

FIXABLE = ("vulnerability", "malicious-package")


# ----------------------------------------------------------------------------- planning

def _fix_candidates(fixed: str) -> list[str]:
    return [v.strip() for v in (fixed or "").split(",") if parse(v.strip())]


def choose_version(current: str, fixed_lists: list[list[str]]) -> tuple[str | None, str]:
    """Smallest version >= every advisory's nearest fix; prefer staying on the current major.

    Returns (version, bump) where bump is patch | minor | major, or (None, reason)."""
    cur = parse(current)
    if cur is None:
        return None, "current version is not a plain semver"
    needed = []
    for fixes in fixed_lists:
        above = sorted((v for v in fixes if _cmp(parse(v), cur) > 0), key=lambda v: parse(v)[:3])
        if not above:
            return None, "no fixed version above the installed one"
        same_major = [v for v in above if parse(v)[0] == cur[0]]
        needed.append((same_major or above)[0])
    target = max(needed, key=lambda v: parse(v)[:3])
    t = parse(target)
    bump = "major" if t[0] != cur[0] else "minor" if t[1] != cur[1] else "patch"
    return target, bump


def _dump(pj: dict, indent: int) -> str:
    return json.dumps(pj, indent=indent, ensure_ascii=False) + "\n"


def _indent_of(text: str) -> int:
    m = re.search(r"\n( +)\"", text)
    return len(m.group(1)) if m else 2


def apply_to_manifest(pj: dict, fixes: list[dict]) -> dict:
    out = json.loads(json.dumps(pj))
    for f in fixes:
        if f["kind"] == "direct":
            out.setdefault(f["section"], {})[f["package"]] = f["new_spec"]
        else:
            out.setdefault("overrides", {})[f"{f['package']}@{f['from_version']}"] = f["to_version"]
    return out


def side_by_side(old: str, new: str, context: int = 3) -> list[dict]:
    """Rows for an old | new view: {"t": same|del|add|chg|gap, "o": old line, "n": new line, "ol"/"nl": numbers}."""
    a, b = old.splitlines(), new.splitlines()
    rows: list[dict] = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            span = list(range(i2 - i1))
            keep = span if len(span) <= 2 * context else span[:context] + [None] + span[-context:]
            for k in keep:
                if k is None:
                    rows.append({"t": "gap"})
                else:
                    rows.append({"t": "same", "o": a[i1 + k], "n": b[j1 + k], "ol": i1 + k + 1, "nl": j1 + k + 1})
        else:
            n = max(i2 - i1, j2 - j1)
            for k in range(n):
                o = a[i1 + k] if i1 + k < i2 else None
                nn = b[j1 + k] if j1 + k < j2 else None
                rows.append({"t": "chg" if o is not None and nn is not None else "del" if o is not None else "add",
                             "o": o, "n": nn, "ol": i1 + k + 1 if o is not None else None,
                             "nl": j1 + k + 1 if nn is not None else None})
    # trim leading/trailing context gaps
    while rows and rows[0]["t"] == "gap":
        rows.pop(0)
    while rows and rows[-1]["t"] == "gap":
        rows.pop()
    return rows


def unified(old: str, new: str, path: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), f"a/{path}", f"b/{path}"))


def plan_fixes(target: Path, findings: list[Finding], inv) -> dict:
    pj_path = target / "package.json"
    if not pj_path.exists():
        return {"fixes": [], "skipped": [], "error": "package.json not found"}
    text = pj_path.read_text(encoding="utf-8")
    pj = json.loads(text)
    indent = _indent_of(text)

    lock_path = target / "package-lock.json"
    lock_pkgs = (json.loads(lock_path.read_text(encoding="utf-8")).get("packages") or {}) if lock_path.exists() else {}

    def bundled_in(name: str, ver: str) -> list[str]:
        """Parents whose tarball ships this name@version (npm overrides cannot change bundled code)."""
        out = set()
        for k, v in lock_pkgs.items():
            if k.endswith(f"node_modules/{name}") and v.get("version") == ver and v.get("inBundle"):
                out.add(k.split("node_modules/")[1].rstrip("/"))
        return sorted(out)

    groups: dict[str, list[Finding]] = {}
    for f in findings:
        if f.category in FIXABLE and "@" in f.component[1:]:
            groups.setdefault(f.component, []).append(f)

    fixes, skipped = [], []
    for label, fs in groups.items():
        name, _, ver = label.rpartition("@")
        comps = [c for c in inv.components.values() if c.name == name and c.version == ver]
        direct = any(c.direct for c in comps)
        lists = [_fix_candidates(f.fixed_version) for f in fs]
        covered = [f for f, l in zip(fs, lists) if l]
        uncovered = [f for f, l in zip(fs, lists) if not l]
        if not covered:
            skipped.append({"package": label, "reason": "no fixed version published"
                            + ("; remove or replace this package manually" if any(f.category == "malicious-package" for f in fs) else ""),
                            "findings": [f.id for f in fs]})
            continue
        lists = [l for l in lists if l]
        to, bump = choose_version(ver, lists)
        if to is None:
            skipped.append({"package": label, "reason": bump, "findings": [f.id for f in fs]})
            continue
        fix = {"id": f"FIX-{label}", "package": name, "from_version": ver, "to_version": to, "bump": bump,
               "file": "package.json", "findings": [f.id for f in fs],
               "advisories": sorted({f.vuln_ids[0] for f in covered if f.vuln_ids}),
               "not_covered": sorted({f.vuln_ids[0] for f in uncovered if f.vuln_ids}),
               "max_risk": max(f.risk_score for f in fs), "max_level": max(fs, key=lambda f: f.risk_score).risk_level,
               "scope": "runtime" if any(f.scope == "runtime" for f in fs) else "dev"}
        if direct:
            section = next((s for s in ("dependencies", "devDependencies", "optionalDependencies")
                            if name in (pj.get(s) or {})), "dependencies")
            old_spec = (pj.get(section) or {}).get(name, "")
            prefix = old_spec[0] if old_spec[:1] in ("^", "~") else ""
            fix.update(kind="direct", section=section, old_spec=old_spec, new_spec=f"{prefix}{to}",
                       summary=f"Upgrade {name} {ver} → {to} in package.json ({section})")
        else:
            fix.update(kind="override", section="overrides", old_spec=None, new_spec=to,
                       summary=f"Pin transitive {name}@{ver} to {to} with an npm override")
        fix["bundled_in"] = bundled_in(name, ver) if fix["kind"] == "override" else []
        new_text = _dump(apply_to_manifest(pj, [fix]), indent)
        fix["diff"] = side_by_side(text, new_text)
        fix["why"] = (f"Fixes {len(fix['advisories'])} advisor{'y' if len(fix['advisories']) == 1 else 'ies'} "
                      f"({', '.join(fix['advisories'][:4])}{'…' if len(fix['advisories']) > 4 else ''}). "
                      + {"patch": "Patch release: lowest risk of breaking changes.",
                         "minor": "Minor release: new features possible, breaking changes unlikely.",
                         "major": "MAJOR version change: breaking changes likely, test carefully before approving."}[bump]
                      + (f" Not covered (no fixed version known): {', '.join(fix['not_covered'][:4])}; the sandbox "
                         "re-scan will show whether they remain." if fix["not_covered"] else "")
                      + (f" Note: copies bundled inside {', '.join(fix['bundled_in'])} cannot be changed by an override; "
                         f"upgrade {'that package' if len(fix['bundled_in']) == 1 else 'those packages'} to remove them."
                         if fix["bundled_in"] else ""))
        fixes.append(fix)
    fixes.sort(key=lambda x: (-x["max_risk"], x["bump"] == "major", x["package"]))
    return {"fixes": fixes, "skipped": sorted(skipped, key=lambda s: s["package"]),
            "policy": "Fixes are proposals. Nothing is changed until a person approves it, and approved fixes are "
                      "applied to a sandbox copy, never to the original repository."}


# ----------------------------------------------------------------------------- decisions

def load_decisions(out: Path) -> dict:
    p = out / "approvals.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def record_decision(out: Path, fix_id: str, decision: str, reviewer: str = "", comment: str = "") -> dict:
    if decision not in ("approved", "rejected", "pending"):
        raise ValueError("decision must be approved, rejected or pending")
    d = load_decisions(out)
    entry = {"decision": decision, "reviewer": (reviewer or "anonymous")[:80], "comment": (comment or "")[:500],
             "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    history = d.get(fix_id, {}).get("history", [])
    d[fix_id] = {**entry, "history": history + [entry]}
    (out / "approvals.json").write_text(json.dumps(d, indent=2), encoding="utf-8")
    return d[fix_id]


# ----------------------------------------------------------------------------- sandbox apply + verify

def _run_npm(cwd: Path) -> tuple[bool, str]:
    npm = shutil.which("npm")
    if not npm:
        return False, "npm is not installed, so the lockfile cannot be regenerated"
    base = [npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"]
    for extra in ([], ["--legacy-peer-deps"]):
        p = subprocess.run(base + extra, cwd=cwd, capture_output=True, text=True, timeout=600)
        if p.returncode == 0:
            return True, " ".join(["npm"] + base[1:] + extra)
        if "ERESOLVE" not in (p.stdout + p.stderr):
            break
    tail = (p.stderr or p.stdout).strip().splitlines()[-3:]
    return False, "npm could not regenerate the lockfile: " + " | ".join(tail)


def apply_fixes(target: Path, out: Path, plan: dict, decisions: dict, rescan) -> dict:
    """Apply approved fixes in out/sandbox, regenerate the lockfile, re-scan, write remediation.patch.

    `rescan(sandbox) -> {"name@version": [advisory ids]}` and `versions(sandbox)` come from the caller,
    so this module stays free of network code (and is easy to test)."""
    approved = [f for f in plan.get("fixes", []) if decisions.get(f["id"], {}).get("decision") == "approved"]
    if not approved:
        return {"ok": False, "error": "No fixes are approved yet."}
    sandbox = out / "sandbox"
    if sandbox.exists():
        shutil.rmtree(sandbox)
    shutil.copytree(target, sandbox, ignore=shutil.ignore_patterns("node_modules", ".git"))

    pj_old = (target / "package.json").read_text(encoding="utf-8")
    lock_old = (target / "package-lock.json").read_text(encoding="utf-8") if (target / "package-lock.json").exists() else ""
    pj_new = _dump(apply_to_manifest(json.loads(pj_old), approved), _indent_of(pj_old))
    (sandbox / "package.json").write_text(pj_new, encoding="utf-8")
    ok, how = _run_npm(sandbox)
    if not ok:
        return {"ok": False, "error": how, "approved": [f["id"] for f in approved]}
    lock_new = (sandbox / "package-lock.json").read_text(encoding="utf-8")

    remaining, installed = rescan(sandbox)
    results = []
    for f in approved:
        now = sorted(installed.get(f["package"], []), key=lambda v: parse(v)[:3] if parse(v) else (0, 0, 0))
        still_old = f["from_version"] in now
        left = sorted(set(f["advisories"]) & set(remaining.get(f"{f['package']}@{f['from_version']}", []))) if still_old else []
        if not still_old:
            status = "resolved"            # the vulnerable version is gone from the lockfile
        elif any(v != f["from_version"] for v in now):
            status = "partly resolved"     # some copies upgraded, the old version is still installed somewhere
        else:
            status = "not applied"         # npm kept the old version (e.g. override did not match)
        note = ""
        if status != "resolved" and f.get("bundled_in"):
            note = f"Remaining copies are bundled inside {', '.join(f['bundled_in'])}; upgrade them to remove these."
        elif status == "not applied":
            note = "npm kept the old version; check the dependency that requires it."
        results.append({"id": f["id"], "package": f["package"], "from_version": f["from_version"], "to_version": f["to_version"],
                        "installed_now": now, "status": status, "advisories_fixed": len(f["advisories"]) - len(left),
                        "advisories_left": left, "note": note})
    patch = unified(pj_old, pj_new, "package.json") + unified(lock_old, lock_new, "package-lock.json")
    (out / "remediation.patch").write_text(patch, encoding="utf-8")
    result = {"ok": True, "applied_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "lockfile_command": how, "sandbox": str(sandbox), "results": results,
              "resolved": sum(r["status"] == "resolved" for r in results), "total": len(results),
              "package_json_diff": side_by_side(pj_old, pj_new), "patch_file": "remediation.patch",
              "patch_lines": patch.count("\n")}
    (out / "remediation_result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
