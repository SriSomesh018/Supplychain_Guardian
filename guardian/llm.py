"""Single entry point for every LLM call (Gemini, free tier).

- key + model read from .env (never logged, never written to reports)
- on-disk response cache keyed by sha256(prompt)
- retry with exponential backoff on 429 / 5xx / timeouts
- model fallback chain: GEMINI_MODEL first, then GEMINI_FALLBACK_MODELS
  (handles retired models (404), overloaded models (503) and per-model rate limits (429))
- returns None on total failure so callers can use their deterministic fallback
- transport: LangChain (langchain-google-genai ChatGoogleGenerativeAI) when installed, plain REST otherwise
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import re
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

DEFAULT_MODEL = "gemini-3.5-flash"
DEFAULT_FALLBACKS = "gemini-3.5-flash,gemini-3.1-flash-lite,gemini-flash-lite-latest"
ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

try:  # LangChain is the preferred client; REST stays as a fallback transport
    from langchain_core.messages import HumanMessage
    from langchain_google_genai import ChatGoogleGenerativeAI
    HAVE_LANGCHAIN = True
except ImportError:  # pragma: no cover
    HAVE_LANGCHAIN = False


def _status_code(text: str) -> int | None:
    m = re.search(r"\b(400|401|403|404|429|500|502|503|504)\b", text)
    return int(m.group(1)) if m else None


def _strip_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else t[3:]
        t = t.rsplit("```", 1)[0]
    return t.strip()


class LLM:
    def __init__(self, cache_dir: Path, max_retries: int = 3):
        self.key = os.getenv("GEMINI_API_KEY", "").strip()
        primary = os.getenv("GEMINI_MODEL", "").strip() or DEFAULT_MODEL
        fallbacks = os.getenv("GEMINI_FALLBACK_MODELS", DEFAULT_FALLBACKS).split(",")
        self.models = list(dict.fromkeys([primary] + [m.strip() for m in fallbacks if m.strip()]))
        self.model = primary          # model that actually answered (updated on success)
        self.cache = cache_dir / "llm"
        self.cache.mkdir(parents=True, exist_ok=True)
        self.max_retries = max_retries
        self.calls = {"api": 0, "cache_hits": 0, "failures": 0}
        self.attempts: list[str] = []  # audit trail: model -> outcome
        self.last_error = ""
        self.backend = "LangChain (langchain-google-genai)" if HAVE_LANGCHAIN else "REST (generativelanguage.googleapis.com)"

    def _redact(self, text: str) -> str:
        return text.replace(self.key, "***") if self.key else text

    def _call_langchain(self, model: str, prompt: str, temperature: float) -> tuple[dict | None, bool]:
        """Same contract as _call, through LangChain's Gemini chat model."""
        base = dict(model=model, google_api_key=self.key, temperature=temperature,
                    response_mime_type="application/json", max_retries=0, timeout=150)
        try:  # explaining given evidence needs little reasoning: low thinking is ~2x faster on Gemini 3
            chat = ChatGoogleGenerativeAI(**base, **({"thinking_level": "low"} if "gemini-3" in model else {}))
        except Exception:
            chat = ChatGoogleGenerativeAI(**base)
        delay = 2.0
        for attempt in range(1, self.max_retries + 1):
            try:
                self.calls["api"] += 1
                msg = chat.invoke([HumanMessage(content=prompt)])
                t = msg.text  # langchain-core >= 1.x: property (a str); older versions: method
                text = str(t) if isinstance(t, str) else t()
                data = json.loads(_strip_fences(text))
                self.attempts.append(f"{model}: ok")
                return data, False
            except ValueError as e:  # malformed JSON: retry
                self.last_error = f"{model} invalid JSON: {str(e)[:120]}"
            except Exception as e:  # API errors surface as exceptions carrying the HTTP status
                msg_text = self._redact(str(e))
                code = _status_code(msg_text)
                self.last_error = f"{model} {type(e).__name__}: {msg_text[:160]}"
                if code == 404 or "not found" in msg_text.lower():
                    self.attempts.append(f"{model}: not available (404)")
                    return None, True
                if code in (400, 401, 403):
                    self.attempts.append(f"{model}: HTTP {code}")
                    return None, False
                if code == 503 and attempt >= 2:
                    self.attempts.append(f"{model}: overloaded (503)")
                    return None, True
            if attempt < self.max_retries:
                time.sleep(delay + random.uniform(0, 1))
                delay *= 2
        self.attempts.append(f"{model}: failed after {self.max_retries} attempts")
        return None, True

    @property
    def enabled(self) -> bool:
        return bool(self.key)

    def _call(self, model: str, body: dict) -> tuple[dict | None, bool]:
        """-> (parsed json | None, try_next_model)"""
        delay = 2.0
        for attempt in range(1, self.max_retries + 1):
            try:
                self.calls["api"] += 1
                r = requests.post(ENDPOINT.format(model=model), json=body, timeout=120,
                                  headers={"x-goog-api-key": self.key})
                if r.status_code == 200:
                    parts = r.json()["candidates"][0]["content"]["parts"]
                    text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
                    self.attempts.append(f"{model}: ok")
                    return json.loads(text), False
                self.last_error = f"{model} HTTP {r.status_code}: {r.text[:160]}"
                if r.status_code == 404:
                    self.attempts.append(f"{model}: not available (404)")
                    return None, True
                if r.status_code in (400, 401, 403):
                    self.attempts.append(f"{model}: HTTP {r.status_code}")
                    return None, False  # bad key / request: other models won't help
                if r.status_code == 503 and attempt >= 2:
                    self.attempts.append(f"{model}: overloaded (503)")
                    return None, True
            except (requests.RequestException, KeyError, IndexError, ValueError) as e:
                self.last_error = f"{model} {type(e).__name__}: {str(e)[:160]}"
            if attempt < self.max_retries:
                time.sleep(delay + random.uniform(0, 1))
                delay *= 2
        self.attempts.append(f"{model}: failed after {self.max_retries} attempts")
        return None, True

    def generate_json(self, prompt: str, temperature: float = 0.2) -> dict | None:
        digest = hashlib.sha256(prompt.encode()).hexdigest()
        cached = self.cache / f"{digest}.json"
        if cached.exists():
            self.calls["cache_hits"] += 1
            entry = json.loads(cached.read_text(encoding="utf-8"))
            self.model = entry.get("_model", self.model)
            self.attempts.append(f"{self.model}: cache hit")
            return entry["response"] if "response" in entry else entry
        if not self.enabled:
            self.last_error = "GEMINI_API_KEY not set"
            return None

        body = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": temperature, "responseMimeType": "application/json"},
        }
        for model in self.models:
            if HAVE_LANGCHAIN:
                data, next_model = self._call_langchain(model, prompt, temperature)
            else:
                data, next_model = self._call(model, body)
            if data is not None:
                self.model = model
                self.last_error = ""
                cached.write_text(json.dumps({"_model": model, "response": data}, indent=2), encoding="utf-8")
                return data
            if not next_model:
                break
        self.calls["failures"] += 1
        return None
