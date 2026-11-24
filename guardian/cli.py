"""Guardian CLI.

  python -m guardian scan --target targets/nodegoat-modified --baseline targets/nodegoat-baseline
  python -m guardian serve            # web app at http://127.0.0.1:8765
"""
from __future__ import annotations

import argparse
import time
from pathlib import Path

from .models import SEVERITY_ORDER

ROOT = Path(__file__).resolve().parents[1]


def _emit(step, status, message, metrics=None):
    line = f"[guardian {time.strftime('%H:%M:%S')}] {step:<8} {status:<7} {message}"
    try:
        print(line, flush=True)
    except UnicodeEncodeError:  # legacy Windows consoles (cp1252) cannot print e.g. "≥"
        print(line.encode("ascii", "replace").decode("ascii"), flush=True)


def scan(args) -> int:
    from .pipeline import run_scan
    from .report import write_html
    out = Path(args.out)
    report = run_scan(Path(args.target), out, Path(args.baseline) if args.baseline else None, emit=_emit,
                      top=args.top, use_llm=not args.no_llm, use_trivy=not args.no_trivy, use_syft=args.syft,
                      meta={"url": "https://github.com/OWASP/NodeGoat"})
    write_html(report, report["graph"], out / "report.html")
    _emit("report", "done", f"Static report -> {out / 'report.html'}")
    worst = max((SEVERITY_ORDER.get(f["severity"], 0) for f in report["findings"]), default=0)
    return 2 if worst >= SEVERITY_ORDER["CRITICAL"] and args.fail_on_critical else 0


def main() -> None:
    p = argparse.ArgumentParser(prog="guardian", description="Software Supply Chain Guardian")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="discover, detect and report (static HTML + JSON)")
    s.add_argument("--target", required=True, help="app directory with package.json + package-lock.json")
    s.add_argument("--baseline", help="trusted earlier copy of the app, for change detection")
    s.add_argument("--out", default=str(ROOT / "output"))
    s.add_argument("--top", type=int, default=8, help="findings sent to the LLM (free-tier budget)")
    s.add_argument("--no-llm", action="store_true", help="skip Gemini, use deterministic explanations")
    s.add_argument("--no-trivy", action="store_true", help="skip container image scan")
    s.add_argument("--syft", action="store_true", help="cross-check the SBOM with Syft")
    s.add_argument("--fail-on-critical", action="store_true", help="exit 2 if any CRITICAL finding")
    v = sub.add_parser("serve", help="run the interactive web app")
    v.add_argument("--port", type=int, default=8765)
    args = p.parse_args()
    if args.cmd == "serve":
        from .server import serve
        serve(args.port)
    else:
        raise SystemExit(scan(args))


if __name__ == "__main__":
    main()
