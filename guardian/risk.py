"""Initial (Day 1) risk scoring - deterministic and explainable.

score = base(severity or CVSS) + context modifiers, clamped to 0..100.
Every adjustment is written to `risk_rationale`, so a reviewer can see why."""
from __future__ import annotations

from .models import Finding

BASE = {"CRITICAL": 85, "HIGH": 65, "MEDIUM": 40, "LOW": 20, "INFO": 5}
ADVISORY_SOURCES = ("OSV.dev", "GitHub Advisory DB")
HIGH_CONFIDENCE_SOURCES = ("OSV.dev", "GitHub Advisory DB", "Trivy", "lockfile-diff", "Dockerfile rule", "workflow rule",
                           "lockfile-rule", "manifest-rule")


def level(score: int) -> str:
    return ("Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 35
            else "Low" if score >= 15 else "Info")


def score_finding(f: Finding) -> None:
    why: list[str] = []
    if f.cvss is not None and f.category == "vulnerability":
        s = f.cvss * 10
        why.append(f"base {s:.0f} from CVSS {f.cvss}")
    else:
        s = BASE.get(f.severity, 20)
        why.append(f"base {s} from severity {f.severity}")

    if f.category == "malicious-package":
        s = max(s, 95)
        why.append("known malicious package (OSV/OpenSSF malware feed) -> floor 95")
    if f.scope == "runtime":
        s += 10
        why.append("+10 ships in the production image (`npm install --production`)")
    elif f.scope == "dev":
        s -= 25
        why.append("-25 dev/test-only dependency (not in production image, still runs on dev & CI machines)")
    elif f.scope == "ci":
        data = {k: v for e in f.evidence for k, v in e.data.items()}
        if data.get("receives_secret") or data.get("trigger") == "pull_request_target":
            s += 10
            why.append("+10 CI step has access to repository secrets")
    if f.evidence and f.evidence[0].data.get("direct"):
        s += 5
        why.append("+5 direct dependency of the app")
    if f.changed:
        s += 10
        why.append("+10 newly introduced compared with the trusted baseline")
    if f.kev:
        s += 15
        why.append("+15 actively exploited in the wild (CISA Known Exploited Vulnerabilities)")
    elif f.epss is not None:
        if f.epss >= 0.5:
            s += 10
            why.append(f"+10 high exploitation likelihood (EPSS {f.epss:.0%})")
        elif f.epss >= 0.1:
            s += 5
            why.append(f"+5 elevated exploitation likelihood (EPSS {f.epss:.0%})")
        elif f.epss < 0.01:
            s -= 5
            why.append(f"-5 low exploitation likelihood (EPSS {f.epss:.2%})")
    if f.category == "vulnerability" and not f.fixed_version:
        s += 5
        why.append("+5 no fixed version published")

    f.risk_score = max(0, min(100, round(s)))
    f.risk_level = level(f.risk_score)
    f.risk_rationale = why

    srcs = [e.source for e in f.evidence]
    if sum(1 for a in ADVISORY_SOURCES if any(src.startswith(a) for src in srcs)) >= 2:
        f.confidence = "High (2 sources)"
    elif any(src.startswith(HIGH_CONFIDENCE_SOURCES) for src in srcs):
        f.confidence = "High"
    elif "npm downloads API" in srcs:
        f.confidence = "Medium-High"
    else:
        f.confidence = "Medium"


CATEGORY_PRIORITY = {"malicious-package": 0, "suspicious-change": 1, "ci-cd": 2, "container": 3,
                     "vulnerability": 4, "manifest-hygiene": 5}


def rank(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        score_finding(f)
    # ties (many items hit the 100 cap) are broken by: newly introduced, category, CVSS, scope
    return sorted(findings, key=lambda f: (-f.risk_score, not f.changed,
                                           CATEGORY_PRIORITY.get(f.category, 9),
                                           -(f.cvss or 0), f.scope != "runtime", f.id))
