# Software Supply Chain Guardian (Team 17)

*Know what you build. Trust what you ship.* Amrita × Bosch BGSW Hackathon.

**Team 17:** Avinash Pala (BL.EN.U4AIE23062) · Nandana Thachilath M (CB.SC.U4AIE23151) ·
SriSomesh (CB.AI.U4AID23141) · Gowtham Kumaresan (CB.AI.U4AID23009) · Vijay Srinivas P (CB.SC.U4AIE23263)

## Day 1 scope: "Build the Guardian's Eyes"
> *Show us what is in the application, what changed, and what appears risky.*

| Day 1 requirement | Where it is covered |
|---|---|
| Analyse manifests and lockfiles; direct and transitive deps; names and versions | `guardian/discover.py` |
| SBOM (CycloneDX) | `output/sbom.cdx.json` (`guardian/sbom.py`), cross-checked with **Syft** |
| Dependency graph; where each component comes from | `guardian/graph.py`, plus the interactive graph in the report |
| Inspect at least one container image or CI/CD workflow | Dockerfile rules, a **Trivy** scan of `node:12-alpine`, GitHub Actions rules (`guardian/container_ci.py`) |
| Known vulnerabilities: CVE, severity, fixes; trace transitive deps to source | OSV.dev (`guardian/vulns.py`); every finding carries its dependency path(s) |
| At least one supply-chain anomaly | typosquat, install script, integrity change, non-registry source, injected transitive dep, `pull_request_target`, `curl \| sh` (`guardian/anomalies.py`) |
| Present evidence: component, path, evidence, initial risk level | `output/report.html` + `output/guardian_report.json` |
| Separate verified evidence from AI inference | green "Verified evidence" vs purple "AI inference" blocks; the JSON has separate `evidence` and `ai` fields |

## Architecture

```
targets/nodegoat-baseline ─┐                      (trusted state)
targets/nodegoat-modified ─┤                      (state under review)
                           ▼
 [1] Discovery agent     package.json + package-lock.json -> components, edges, runtime/dev scope
 [2] SBOM + Graph        CycloneDX 1.5 JSON, networkx graph, dependency paths   (+ Syft cross-check)
 [3] Vulnerability agent OSV.dev batch query -> CVE/GHSA/MAL, CVSS, fixed versions
 [4] Anomaly agent       typosquat (edit distance + npm downloads API), install scripts, sources,
                         integrity, lockfile diff vs baseline, Dockerfile + GitHub Actions rules,
                         Trivy container image scan
     Risk scorer         deterministic, explainable 0-100 score + rationale + confidence
 [5] AI explainer        Gemini (Flash). Top-N findings only, 1 cached request, retry/backoff,
                         hallucinated-ID guardrail, deterministic fallback
                           ▼
 output/report.html  ·  output/guardian_report.json  ·  output/sbom*.cdx.json  ·  output/trivy-*.json
```

### Six agents, orchestrated with LangGraph

```
START → [1] Discovery ─┬─► [2] Vulnerability ─► [3] Threat intelligence ─┬─► merge ─(baseline?)─► [5] Change detection ─► [6] Risk & explanation → report
                       └─► [4] Supply-chain integrity ───────────────────┘        └──(no)───────────────────────┘         (Gemini via LangChain)
```

| Agent | Job | Sources / tools |
|---|---|---|
| 1 Discovery | inventory, dependency graph, SBOM, full multi-manifest graph | lockfile parser, networkx, CycloneDX, Syft, deptree |
| 2 Vulnerability | CVE / GHSA / malware per name@version, cross-checked across 3 sources | OSV.dev, GitHub Advisory DB (npm bulk API), deps.dev |
| 3 Threat intelligence | real-world exploitation and package health | CISA KEV, FIRST EPSS, deps.dev (deprecation, licenses, OpenSSF Scorecard) |
| 4 Supply-chain integrity | typosquats, install scripts, sources, hashes, Dockerfile and CI rules | rapidfuzz + npm downloads, rules, Trivy |
| 5 Change detection | what is new since the last known-good copy (runs only with a baseline) | lockfile diff, baseline re-scan |
| 6 Risk & explanation | deterministic 0-100 score, then Gemini explains the top findings | risk model, `langchain-google-genai`, guardrails |

All external sources are free and need no API key (Sonatype OSS Index was evaluated but now requires an account).
The risk score uses exploit intelligence: +15 if the CVE is in CISA KEV, +10/+5 for EPSS ≥ 50% / ≥ 10%, -5 for EPSS < 1%,
and confidence is "High (2 sources)" when two advisory databases agree.

**Failure handling.** Network agents retry with backoff (LangGraph `RetryPolicy`). If one advisory source fails, the
others' results are kept and a warning is recorded. If an agent still fails, it degrades: its step shows a clear error,
the scan continues, and the results page shows a "Partial results" bar. Only a discovery failure stops the scan, with
the failed step named.

**Tests.** `python -m pytest tests` runs 45 offline tests (all external services are faked): semver matching, advisory
cross-checks, KEV/EPSS enrichment, risk scoring, agent order and parallelism, retries and degradation, baseline
detection, the Gemini client (model fallback, key redaction), the Flask API, and an end-to-end scan.

### Fixes with human approval (Day 2)

After the AI reasoning and next step, every vulnerable package with a published fix gets a **proposed code change**:

- direct dependency → its version range is bumped in `package.json`
- transitive dependency → a version-scoped npm `overrides` entry (`"minimist@1.2.0": "1.2.6"`)

The reviewer sees the **current and proposed code side by side**, which advisories the fix closes, whether it is a
patch, minor or MAJOR update, and any limits (e.g. copies bundled inside another package cannot be overridden).
They **approve or reject** each fix with their name and an optional comment; decisions are logged with history in
`output/<repo>/approvals.json`.

**Apply approved fixes in a sandbox** copies the project to `output/<repo>/sandbox/` (the original is never changed),
regenerates the lockfile with `npm install --package-lock-only --ignore-scripts`, re-scans it, and reports each fix as
*resolved*, *partly resolved* or *not applied*. The combined change is saved as `remediation.patch` to review and apply
by hand. Proposals are deterministic: the AI explains, it never writes code. Code: `guardian/remediation.py`.

Design rules:
- **Scores and facts come only from deterministic tools.** The LLM explains and never scores.
- **Nothing from the target is installed or executed.** We parse files only.
- **The tampered scenario is local only.** Nothing is pushed or published, and the injected URLs use reserved addresses (`203.0.113.0/24`, `*.example`).
- **Secrets stay in `.env`**, which is git-ignored and never written to reports.

## Target application
[OWASP NodeGoat](https://github.com/OWASP/NodeGoat) (upstream commit `c5cb68a`): Node.js/Express with
`package-lock.json` v2 (1,479 packages, depth 13), a multi-stage `Dockerfile` and 2 GitHub workflows.

`scripts/make_scenario.py` creates:
- `targets/nodegoat-baseline`: an untouched copy.
- `targets/nodegoat-modified`: the same app with simulated supply-chain attacks:
  | # | Injected change | Expected detection |
  |---|---|---|
  | A | `expresss` typosquat direct dependency with install script | typosquat + install script + new dependency |
  | B | `postinstall` that runs `curl … \| sh` | dangerous lifecycle script |
  | C | `underscore` integrity hash + registry changed, same version | integrity change + non-registry source |
  | D | `flatmap-stream@0.1.1` (real 2018 malware) injected under `express` | OSV malicious package + new transitive dep |
  | E | Dockerfile `node:latest`, `wget … \| sh`, root user | container rules |
  | F | `release.yml` with `pull_request_target` + unpinned 3rd-party action + secret | CI rules |

## Setup (Windows)
Prerequisites: Python 3.11+, git, and optionally Trivy and Syft (`winget install AquaSecurity.Trivy Anchore.Syft`).

```powershell
python -m pip install -r requirements.txt
# optional AI layer: create .env (never commit it)
#   GEMINI_API_KEY=...
#   GEMINI_MODEL=gemini-3.5-flash
#   GEMINI_FALLBACK_MODELS=gemini-3.5-flash,gemini-3.1-flash-lite   (optional; used on 404/503/429)
python scripts\check_llm.py    # verify key + model (never prints the key)
python scripts\list_models.py  # list Flash models available to your key
.\run_day1.ps1                 # clone (if needed) -> build scenario -> scan -> open report
```

**Interactive web app (recommended for the demo):**
```powershell
.\run_app.ps1                  # http://127.0.0.1:8765 : paste a GitHub URL or pick NodeGoat / Juice Shop
```
The landing page starts a live scan, shows each step in plain language, and then opens the results:
The Journey (guided story) · Files (JSON tree viewer) · How We Discovered · Supply Chain ·
Dependency Graph (tree/network) · Vulnerabilities (bubble map) · Suspicious Changes (case files) · All Findings · Final Report.
Repos without a lockfile are resolved with `npm install --package-lock-only --ignore-scripts` (no code runs).
Each scan of a GitHub URL is snapshotted, and the next scan of the same repo shows what changed.

**Full Graph tab.** Every scan also maps every manifest in the repository (npm, Dockerfiles,
docker-compose, GitHub Actions, plus Python/Go/Java/Ruby/PHP/Rust/.NET when present) into one radial graph:
project → ecosystem → manifest → packages by depth. Node size is the number of dependents, and colour is the
worst Guardian finding on that package. Click a node to see every path to it, its evidence, and its findings.
The engine is vendored in `guardian/deptree/` and writes `output/<repo>/deptree_graph.json` (npm graphs are
cross-checked with `npm ls`). If it fails, the rest of the scan is unaffected.

Manual CLI run and options:
```powershell
python -m guardian scan --target targets\nodegoat-modified --baseline targets\nodegoat-baseline `
       [--syft] [--top 8] [--no-llm] [--no-trivy] [--fail-on-critical]
```

## Outputs
| File | Content |
|---|---|
| `output/report.html` | Human-readable report: checkpoint panels, top findings with evidence/AI, graph, filterable table |
| `output/guardian_report.json` | Machine-readable report (`supply-chain-guardian/report/v1`) |
| `output/sbom.cdx.json` / `sbom.baseline.cdx.json` | CycloneDX 1.5 SBOMs (current / baseline) |
| `output/sbom.syft.cdx.json` | Independent Syft SBOM (cross-check) |
| `output/trivy-image-node_12-alpine.json` | Raw Trivy image scan |

## Risk score
`base` = CVSS×10 (vulns) or severity (85/65/40/20) · malicious package → floor 95 · **+10** runtime (in prod image) ·
**−25** dev-only · **+10** CI step with secrets · **+5** direct dependency · **+10** new vs baseline · **+5** no fix ·
exploit intelligence: **+15** in CISA KEV (exploited in the wild), else FIRST EPSS **+10** (≥50%) / **+5** (≥10%) / **−5** (<1%).
Levels: ≥80 Critical, ≥60 High, ≥35 Medium, ≥15 Low. The rationale is stored on every finding. Confidence is
"High (2 sources)" when OSV.dev and the GitHub Advisory DB agree.

## Responsible AI and security
- The LLM receives only the top-N findings' verified evidence (no source code, no secrets) in a single request, cached on disk under `.cache/llm`.
- The prompt forbids adding facts. Advisory IDs that are not in the evidence are removed automatically and listed.
- If the API fails or hits a rate limit, a deterministic template is used and the report says so.
- The AI never changes scores, files or dependencies. Every fix requires **human approval** and is applied only to a sandbox copy.

## Known limitations
- Risk scoring and fixes are npm-only (lockfile v2/v3); other ecosystems appear in the Full Graph inventory only. No reachability analysis yet.
- A fix can be *partly resolved* when another package pins its own copy (e.g. `express@4.16.4` pins `body-parser@1.18.3`): upgrade the parent too.
- The typosquat reference list is curated (`guardian/data/popular_npm.txt`). Lookalikes with ≥50k weekly downloads are treated as legitimate.
- Docker is not installed on the dev machine, so the image is scanned remotely by Trivy and the Dockerfile is analysed statically.
- `node:latest` is flagged but not scanned (a floating tag gives a non-reproducible result).

## Status and next steps
Done: discover → detect (3 advisory sources + exploit intelligence) → prioritise → explain → propose fix →
**human approve/reject** → apply in sandbox → re-scan → patch file.
Next: reachability analysis, build and test the sandbox in Docker, before/after SBOM diff in the report.
