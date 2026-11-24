"""Local web app: pick a preset or paste a GitHub URL, watch the scan step by step, explore results.

Binds to 127.0.0.1 only. One scan at a time. File endpoints are whitelisted."""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import traceback
import uuid
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_file, send_from_directory

from .pipeline import STEPS, copy_baseline, run_scan
from .agents.base import AgentFailed, friendly_error
from .repo import PRESETS, TARGETS, FetchError, clone, ensure_lockfile, save_snapshot, slug_for, snapshot_dir

ROOT = Path(__file__).resolve().parents[1]
WEB = Path(__file__).parent / "web"
STATIC = Path(__file__).parent / "static"
OUTPUT = ROOT / "output"

app = Flask(__name__)
JOBS: dict[str, dict] = {}
SCAN_LOCK = threading.Lock()


def _report_path(slug: str) -> Path:
    if not slug.replace("-", "").replace("_", "").replace(".", "").isalnum():
        abort(400)
    return OUTPUT / slug / "guardian_report.json"


def _job_emit(job: dict):
    def emit(step, status, message, metrics=None):
        job["events"].append({"step": step, "status": status, "message": message,
                              "metrics": metrics or {}, "t": round(time.time() - job["started"], 1)})
    return emit


def _run_job(job: dict, preset: str | None, url: str | None) -> None:
    emit = _job_emit(job)
    try:
        with SCAN_LOCK:
            if preset == "nodegoat":
                up = TARGETS / "nodegoat-upstream"
                emit("fetch", "running", "Using OWASP NodeGoat and preparing the simulated attack scenario")
                if not up.exists():
                    clone_dest, _ = clone(PRESETS["nodegoat"]["url"], emit)
                    clone_dest.rename(up)
                subprocess.run([sys.executable, str(ROOT / "scripts" / "make_scenario.py")], check=True,
                               capture_output=True, timeout=120)
                commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=up, capture_output=True,
                                        text=True).stdout.strip()
                emit("fetch", "done", f"NodeGoat @ {commit or 'local'}: trusted copy + tampered copy ready",
                     {"commit": commit})
                slug, target, baseline = "nodegoat", TARGETS / "nodegoat-modified", TARGETS / "nodegoat-baseline"
                lock_status = "found"
                meta = {"url": PRESETS["nodegoat"]["url"], "commit": commit, "preset": "nodegoat", "slug": slug,
                        "baseline_label": "trusted copy (before the simulated attack)"}
            else:
                url = PRESETS[preset]["url"] if preset else url
                slug = slug_for(url)
                target, commit = clone(url, emit)
                emit("fetch", "done", f"Downloaded {url.split('github.com/')[-1]} @ {commit}", {"commit": commit})
                lock_status = ensure_lockfile(target, emit)
                baseline = None
                snap = snapshot_dir(slug)
                if snap.exists():
                    baseline = copy_baseline(snap, TARGETS / f"{slug}__baseline")
                meta = {"url": url, "commit": commit, "preset": preset, "slug": slug,
                        "baseline_label": "previous Guardian scan of this repository"}
            out = OUTPUT / slug
            run_scan(target, out, baseline, emit=emit, meta=meta, lock_status=lock_status)
            if preset != "nodegoat":
                save_snapshot(target, slug)
        job.update(status="done", slug=slug)
    except FetchError as e:
        job.update(status="error", error=str(e), failed_step="fetch")
    except AgentFailed as e:
        job.update(status="error", error=e.message, failed_step=e.step, failed_agent=e.agent)
    except Exception as e:  # surface, never crash the server
        traceback.print_exc()
        running = [ev["step"] for ev in job["events"] if ev["status"] == "running"]
        job.update(status="error", error=friendly_error(e), failed_step=running[-1] if running else None,
                   detail=f"{type(e).__name__}: {str(e)[:300]}")


@app.get("/")
def index():
    return send_file(WEB / "app.html")


@app.get("/static/<path:name>")
def static_files(name):
    return send_from_directory(STATIC, name)


@app.get("/api/presets")
def presets():
    out = []
    for p in PRESETS.values():
        rp = OUTPUT / ("nodegoat" if p["id"] == "nodegoat" else slug_for(p["url"])) / "guardian_report.json"
        last = None
        if rp.exists():
            r = json.loads(rp.read_text(encoding="utf-8"))
            last = {"slug": r["target"].get("slug") or rp.parent.name, "generated_at": r["generated_at"],
                    "components": r["checkpoint"]["what_is_in_the_app"]["total_components"],
                    "findings": len(r["findings"])}
        out.append({**p, "last": last})
    return jsonify({"presets": out, "steps": STEPS})


@app.get("/api/history")
def history():
    items = []
    for rp in sorted(OUTPUT.glob("*/guardian_report.json"), key=lambda p: -p.stat().st_mtime):
        r = json.loads(rp.read_text(encoding="utf-8"))
        items.append({"slug": rp.parent.name, "name": r["target"]["name"], "url": r["target"].get("upstream"),
                      "generated_at": r["generated_at"], "findings": len(r["findings"])})
    return jsonify(items)


@app.post("/api/scan")
def start_scan():
    body = request.get_json(silent=True) or {}
    preset, url = body.get("preset"), (body.get("url") or "").strip()
    if preset and preset not in PRESETS:
        return jsonify({"error": "unknown preset"}), 400
    if not preset:
        try:
            slug_for(url)
        except FetchError as e:
            return jsonify({"error": str(e)}), 400
    if SCAN_LOCK.locked():
        return jsonify({"error": "A scan is already running. Please wait for it to finish."}), 409
    jid = uuid.uuid4().hex[:12]
    job = {"id": jid, "status": "running", "events": [], "started": time.time(), "slug": None, "error": None,
           "target": PRESETS[preset]["name"] if preset else url}
    JOBS[jid] = job
    threading.Thread(target=_run_job, args=(job, preset, url), daemon=True).start()
    return jsonify({"job": jid})


@app.get("/api/jobs/<jid>")
def job_status(jid):
    job = JOBS.get(jid) or abort(404)
    return jsonify({k: v for k, v in job.items() if k != "started"})


@app.get("/api/report/<slug>")
def report(slug):
    p = _report_path(slug)
    if not p.exists():
        abort(404)
    return send_file(p, mimetype="application/json")


@app.get("/api/report/<slug>/output/<name>")
def output_file(slug, name):
    p = _report_path(slug)
    r = json.loads(p.read_text(encoding="utf-8"))
    if name not in {f["name"] for f in r.get("files", {}).get("outputs", [])}:
        abort(404)
    return send_from_directory(p.parent, name, as_attachment=request.args.get("dl") == "1")


@app.get("/api/report/<slug>/input")
def input_file(slug):
    p = _report_path(slug)
    r = json.loads(p.read_text(encoding="utf-8"))
    name = request.args.get("name", "")
    if name not in {f["name"] for f in r.get("files", {}).get("inputs", [])}:
        abort(404)
    target = Path(r["target"]["path"]).resolve()
    f = (target / name).resolve()
    if target not in f.parents or not f.exists():
        abort(404)
    return send_file(f, mimetype="text/plain")


# ------------------------------------------------------------------ remediation (human approval)
FIX_LOCK = threading.Lock()


def _rescan(sandbox: Path):
    """Advisories still present in the sandbox, and installed versions per package."""
    from .discover import discover
    from .graph import DepGraph
    from .vulns import scan_vulnerabilities
    inv = discover(sandbox)
    findings, _ = scan_vulnerabilities(inv, DepGraph(inv), ROOT / ".cache")
    remaining: dict[str, list[str]] = {}
    for f in findings:
        remaining.setdefault(f.component, []).extend(f.vuln_ids)
    installed: dict[str, list[str]] = {}
    for c in inv.components.values():
        installed.setdefault(c.name, [])
        if c.version not in installed[c.name]:
            installed[c.name].append(c.version)
    return remaining, installed


def _fix_state(slug: str) -> dict:
    from .remediation import load_decisions
    p = _report_path(slug)
    if not p.exists():
        abort(404)
    r = json.loads(p.read_text(encoding="utf-8"))
    res = p.parent / "remediation_result.json"
    return {"plan": r.get("remediation") or {"fixes": [], "skipped": []}, "decisions": load_decisions(p.parent),
            "result": json.loads(res.read_text(encoding="utf-8")) if res.exists() else None,
            "target": r["target"]["path"], "dir": p.parent}


@app.get("/api/report/<slug>/fixes")
def fixes(slug):
    st = _fix_state(slug)
    return jsonify({k: v for k, v in st.items() if k not in ("target", "dir")})


@app.post("/api/report/<slug>/fixes/<path:fix_id>/decision")
def fix_decision(slug, fix_id):
    from .remediation import record_decision
    st = _fix_state(slug)
    if fix_id not in {f["id"] for f in st["plan"]["fixes"]}:
        return jsonify({"error": "unknown fix"}), 404
    body = request.get_json(silent=True) or {}
    try:
        entry = record_decision(st["dir"], fix_id, body.get("decision", ""), body.get("reviewer", ""), body.get("comment", ""))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(entry)


@app.post("/api/report/<slug>/fixes/apply")
def fix_apply(slug):
    from .remediation import apply_fixes
    st = _fix_state(slug)
    if not FIX_LOCK.acquire(blocking=False):
        return jsonify({"error": "Fixes are already being applied. Please wait."}), 409
    try:
        result = apply_fixes(Path(st["target"]), st["dir"], st["plan"], st["decisions"], _rescan)
    except Exception as e:
        traceback.print_exc()
        result = {"ok": False, "error": friendly_error(e)}
    finally:
        FIX_LOCK.release()
    return jsonify(result), (200 if result.get("ok") else 400)


@app.get("/api/report/<slug>/fixes/patch")
def fix_patch(slug):
    p = _report_path(slug).parent / "remediation.patch"
    if not p.exists():
        abort(404)
    return send_file(p, mimetype="text/plain", as_attachment=True, download_name=f"{slug}-remediation.patch")


def serve(port: int = 8765) -> None:
    OUTPUT.mkdir(exist_ok=True)
    print(f"Supply Chain Guardian running at http://127.0.0.1:{port}  (Ctrl+C to stop)")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
