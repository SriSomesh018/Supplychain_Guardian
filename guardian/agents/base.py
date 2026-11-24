"""Agent base class and the shared scan context.

Every agent is a LangGraph node: it reads the shared state, calls its tools (the deterministic
Guardian modules, or Gemini for the explainer), returns a partial state update, and appends one
trace record describing what it did. The trace is stored in the report and shown in the UI.

Failure handling
- network errors are retried by LangGraph's RetryPolicy (the agent raises RetryableAgentError)
- after the last attempt a non-critical agent degrades: it reports a clear error on its step,
  returns safe empty outputs, and the scan continues
- a critical agent (discovery) stops the scan with AgentFailed and a plain-language message
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import requests


@dataclass
class ScanContext:
    target: Path
    out: Path
    baseline: Path | None
    cache: Path
    emit: Callable[..., None]
    meta: dict = field(default_factory=dict)
    top: int = 8
    use_llm: bool = True
    use_trivy: bool = True
    use_syft: bool = True
    lock_status: str = "found"
    retry_interval: float = 1.0   # first LangGraph retry delay (seconds), doubled each attempt
    t0: float = field(default_factory=time.time)


class RetryableAgentError(Exception):
    """Raised to ask the LangGraph RetryPolicy for another attempt."""


class AgentFailed(Exception):
    """A critical agent failed: the scan cannot continue."""

    def __init__(self, agent: str, step: str, message: str):
        super().__init__(f"{agent} failed: {message}")
        self.agent, self.step, self.message = agent, step, message


NETWORK_ERRORS = (requests.ConnectionError, requests.Timeout, socket.timeout, TimeoutError, ConnectionError)


def is_network_error(e: BaseException) -> bool:
    if isinstance(e, NETWORK_ERRORS):
        return True
    if isinstance(e, requests.HTTPError) and e.response is not None:
        return e.response.status_code in (429, 500, 502, 503, 504)
    return False


def friendly_error(e: BaseException, service: str = "") -> str:
    """One plain sentence a user can act on."""
    where = f" {service}" if service else ""
    if isinstance(e, (requests.ConnectionError, ConnectionError)):
        return f"Could not reach{where or ' the service'} (network unavailable or blocked)."
    if isinstance(e, (requests.Timeout, socket.timeout, TimeoutError)):
        return f"{(service or 'The service')} did not answer in time."
    if isinstance(e, requests.HTTPError) and e.response is not None:
        code = e.response.status_code
        if code == 429:
            return f"{(service or 'The service')} is rate-limiting requests. Try again in a minute."
        return f"{(service or 'The service')} returned HTTP {code}."
    if isinstance(e, FileNotFoundError):
        return f"Required file not found: {getattr(e, 'filename', '') or e}."
    text = str(e).strip() or type(e).__name__
    return text[:220]


class Agent:
    """Subclasses set the class attributes and implement run(state) -> dict."""
    id = ""
    name = ""
    role = ""
    step = ""            # UI step id this agent reports progress under
    tools: list[str] = []
    uses_llm = False
    critical = False     # True: failure stops the scan
    max_attempts = 1     # >1: network errors are retried by LangGraph
    service = ""         # used in error messages

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.summary = ""
        self.outputs: dict = {}
        self.warnings: list[str] = []
        self._attempt = 0
        self._started: float | None = None

    def emit(self, status: str, message: str, metrics: dict | None = None, step: str | None = None):
        # progress reporting must never fail an agent (e.g. a console that cannot print a character)
        try:
            self.ctx.emit(step or self.step, status, message, metrics)
        except Exception:  # pragma: no cover - defensive
            pass

    def run(self, state: dict) -> dict:  # pragma: no cover - interface
        raise NotImplementedError

    def fallback(self, state: dict) -> dict:
        """Safe empty outputs used when the agent degrades."""
        return {}

    def __call__(self, state: dict) -> dict:
        self._attempt += 1
        if self._started is None:
            self._started = time.time()
        rec = {"id": self.id, "name": self.name, "role": self.role, "tools": list(self.tools),
               "uses_llm": self.uses_llm, "started_s": round(self._started - self.ctx.t0, 2),
               "attempts": self._attempt}
        try:
            update = self.run(state) or {}
            rec["status"] = "done"
        except Exception as e:
            if self._attempt < self.max_attempts and is_network_error(e):
                self.emit("running", f"{friendly_error(e, self.service)} Retrying "
                                     f"(attempt {self._attempt + 1} of {self.max_attempts})")
                raise RetryableAgentError(str(e)) from e
            msg = friendly_error(e, self.service)
            if self.critical:
                self.emit("error", msg)
                raise AgentFailed(self.name, self.step, msg) from e
            self.emit("error", f"{msg} The scan continued without this agent's results.")
            update = self.fallback(state)
            rec.update(status="error", error=msg, degraded=True)
        rec.update(duration_s=round(time.time() - self._started, 2), summary=self.summary,
                   outputs=self.outputs)
        if self.warnings:
            rec["warnings"] = list(self.warnings)
        return {**update, "trace": [rec]}
