"""Minimal npm semver range matching, enough for advisory `vulnerable_versions` strings.

Supports: comparators (<, <=, >, >=, =), plain versions, space-separated AND, `||` OR,
hyphen ranges (1.2.3 - 2.3.4), `*` / empty. Pre-release tags sort before the release."""
from __future__ import annotations

import re

_V = re.compile(r"^v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$")


def parse(v: str) -> tuple | None:
    m = _V.match(v.strip())
    if not m:
        return None
    major, minor, patch, pre = m.groups()
    num = lambda x: 0 if x in (None, "x", "*") else int(x)
    pre_key = (1,) if not pre else (0, tuple(int(p) if p.isdigit() else p for p in pre.split(".")))
    return (num(major), num(minor), num(patch), pre_key)


def _cmp(a: tuple, b: tuple) -> int:
    a3, b3 = a[:3], b[:3]
    if a3 != b3:
        return -1 if a3 < b3 else 1
    try:
        return (a[3] > b[3]) - (a[3] < b[3])
    except TypeError:  # mixed str/int pre-release identifiers
        return (str(a[3]) > str(b[3])) - (str(a[3]) < str(b[3]))


def _comparator(ver: tuple, comp: str) -> bool:
    m = re.match(r"^(<=|>=|<|>|=)?\s*(.+)$", comp.strip())
    if not m:
        return False
    op, target = m.group(1) or "=", parse(m.group(2))
    if target is None:
        return False
    c = _cmp(ver, target)
    return {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "=": c == 0}[op]


def satisfies(version: str, rng: str) -> bool:
    ver = parse(version)
    if ver is None:
        return False
    rng = (rng or "").strip()
    if rng in ("", "*", "x"):
        return True
    for alt in rng.split("||"):
        alt = alt.strip()
        if not alt:
            continue
        hy = re.match(r"^(\S+)\s+-\s+(\S+)$", alt)
        if hy:
            comps = [f">={hy.group(1)}", f"<={hy.group(2)}"]
        else:
            comps = re.findall(r"(?:<=|>=|<|>|=)?\s*[^\s<>=]+", alt)
        if comps and all(_comparator(ver, c) for c in comps):
            return True
    return False
