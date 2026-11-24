"""Exploit intelligence for CVE findings.

- CISA KEV: CVEs known to be exploited in the wild (catalog cached for 24 h)
- FIRST EPSS: probability that a CVE is exploited in the next 30 days (cached per day)
Results are attached as verified evidence and used by the deterministic risk model."""
from __future__ import annotations

import json
import time
from datetime import date
from pathlib import Path

import requests

from .models import Evidence, Finding

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


class ThreatIntel:
    def __init__(self, cache_dir: Path, session: requests.Session | None = None):
        self.cache = cache_dir / "intel"
        self.cache.mkdir(parents=True, exist_ok=True)
        self.s = session or requests.Session()

    def kev(self) -> dict[str, dict]:
        p = self.cache / "kev.json"
        if p.exists() and time.time() - p.stat().st_mtime < 86400:
            data = json.loads(p.read_text(encoding="utf-8"))
        else:
            r = self.s.get(KEV_URL, timeout=60)
            r.raise_for_status()
            data = r.json()
            p.write_text(json.dumps(data), encoding="utf-8")
        return {v["cveID"]: v for v in data.get("vulnerabilities", [])}

    def epss(self, cves: list[str]) -> dict[str, dict]:
        p = self.cache / f"epss-{date.today().isoformat()}.json"
        known: dict[str, dict] = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        todo = [c for c in sorted(set(cves)) if c not in known]
        for i in range(0, len(todo), 100):
            chunk = todo[i:i + 100]
            r = self.s.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=60)
            r.raise_for_status()
            for row in r.json().get("data", []):
                known[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"]),
                                     "date": row.get("date")}
            for c in chunk:
                known.setdefault(c, {})
        p.write_text(json.dumps(known), encoding="utf-8")
        return {c: known.get(c, {}) for c in cves}


def enrich(findings: list[Finding], intel: ThreatIntel) -> dict:
    """Attach KEV / EPSS evidence to vulnerability findings. Returns stats."""
    vulns = [f for f in findings if f.category == "vulnerability"]
    cves = sorted({i for f in vulns for i in f.vuln_ids if i.startswith("CVE-")})
    stats = {"cves": len(cves), "kev_matches": 0, "epss_scored": 0, "epss_high": 0, "errors": []}
    if not cves:
        return stats
    try:
        kev = intel.kev()
    except Exception as e:
        kev = {}
        stats["errors"].append(f"CISA KEV unavailable: {type(e).__name__}")
    try:
        epss = intel.epss(cves)
    except Exception as e:
        epss = {}
        stats["errors"].append(f"FIRST EPSS unavailable: {type(e).__name__}")
    if not kev and not epss:
        raise RuntimeError("; ".join(stats["errors"]) or "no threat-intel source reachable")
    for f in vulns:
        ids = [i for i in f.vuln_ids if i.startswith("CVE-")]
        k = next((kev[i] for i in ids if i in kev), None)
        if k:
            f.kev = True
            f.evidence.append(Evidence(source="CISA KEV", detail=f"{k['cveID']} is in CISA's Known Exploited Vulnerabilities "
                                       f"catalog (added {k.get('dateAdded')})" + ("; used in ransomware campaigns"
                                       if k.get("knownRansomwareCampaignUse") == "Known" else ""),
                                       data={"cve": k["cveID"], "date_added": k.get("dateAdded"),
                                             "ransomware": k.get("knownRansomwareCampaignUse")}))
            stats["kev_matches"] += 1
        scored = [(epss[i]["epss"], epss[i]["percentile"], i) for i in ids if epss.get(i, {}).get("epss") is not None]
        if scored:
            e, pct, cve = max(scored)
            f.epss, f.epss_percentile = e, pct
            f.evidence.append(Evidence(source="FIRST EPSS", detail=f"{cve}: {e:.1%} probability of exploitation in the "
                                       f"next 30 days (higher than {pct:.0%} of all CVEs)",
                                       data={"cve": cve, "epss": e, "percentile": pct}))
            stats["epss_scored"] += 1
            stats["epss_high"] += e >= 0.1
    return stats
