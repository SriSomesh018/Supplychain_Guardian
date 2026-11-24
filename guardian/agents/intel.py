"""Agent 6 - Threat intelligence: is anyone exploiting these CVEs, and are the packages healthy?

Exploitation (attached to CVE findings, used by the risk model):
- CISA KEV: known to be exploited in the wild (+15)
- FIRST EPSS: probability of exploitation in the next 30 days (+10 / +5 / -5)
Package health (deps.dev): deprecated versions, licenses, OpenSSF Scorecard of direct dependencies.
Runs after the vulnerability agent, in parallel with the integrity agent."""
from __future__ import annotations

from ..depsdev import DepsDevClient, health_check
from ..threat_intel import ThreatIntel, enrich
from .base import Agent, friendly_error


class ThreatIntelAgent(Agent):
    id = "intel"
    name = "Threat intelligence agent"
    role = "Check real-world exploitation for every CVE (CISA KEV, FIRST EPSS) and the health of every package (deps.dev)."
    step = "intel"
    tools = ["CISA KEV catalog", "FIRST EPSS API", "deps.dev package health", "OpenSSF Scorecard"]
    max_attempts = 2
    service = "the threat-intelligence feeds"

    def run(self, state: dict) -> dict:
        vulns = state.get("vulns") or []
        cves = {i for f in vulns if f.category == "vulnerability" for i in f.vuln_ids if i.startswith("CVE-")}
        self.emit("running", f"Checking {len(cves)} CVEs against CISA KEV and FIRST EPSS, and package health on deps.dev")
        st = {"cves": 0, "kev_matches": 0, "epss_scored": 0, "epss_high": 0}
        exploit_err = None
        if cves:
            try:
                st = enrich(vulns, ThreatIntel(self.ctx.cache))
                self.warnings.extend(st.pop("errors", []) or [])
            except Exception as e:
                exploit_err = e
                self.warnings.append(friendly_error(e, "CISA KEV / FIRST EPSS"))
        health, hst = [], {}
        try:
            health, hst = health_check(state["inv"], state["graph"], DepsDevClient(self.ctx.cache), state.get("depsdev") or {})
        except Exception as e:
            self.warnings.append(friendly_error(e, "deps.dev"))
            if exploit_err:
                raise
        st["health"] = hst
        self.emit("done", f"{st['kev_matches']} actively exploited (KEV), {st['epss_high']} with EPSS ≥ 10%, "
                          f"{hst.get('deprecated', 0)} deprecated, {hst.get('low_scorecard', 0)} weak direct dependencies",
                  {"cves": st["cves"], "kev": st["kev_matches"], "epss ≥ 10%": st["epss_high"],
                   "deprecated": hst.get("deprecated"), "low scorecard": hst.get("low_scorecard")})
        self.summary = (f"{st['cves']} CVEs checked: {st['kev_matches']} in CISA KEV, {st['epss_scored']} scored by EPSS "
                        f"({st['epss_high']} at 10%+). {hst.get('deprecated', 0)} deprecated versions, "
                        f"{hst.get('scorecards_checked', 0)} Scorecards checked ({hst.get('low_scorecard', 0)} below 3/10).")
        self.outputs = {**{k: v for k, v in st.items() if k != "health"}, **{k: v for k, v in hst.items()}}
        return {"intel": st, "health_findings": health}

    def fallback(self, state: dict) -> dict:
        return {"intel": {"error": "threat-intelligence feeds unreachable"}, "health_findings": []}
