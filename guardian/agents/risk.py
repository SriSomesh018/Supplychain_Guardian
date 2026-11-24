"""Agent 5 - Risk and explanation.

Scores every finding with the deterministic, explainable risk model, then asks Gemini (through
LangChain) to explain the top findings from verified evidence only. The model never changes a
score; invented advisory IDs and unsupported evidence claims are removed by guardrails."""
from __future__ import annotations

from ..explain import explain
from ..llm import LLM
from ..risk import rank
from .base import Agent


class RiskExplainAgent(Agent):
    id = "risk"
    name = "Risk and explanation agent"
    role = "Rank every finding with a deterministic 0-100 score, then have Gemini explain the top ones from evidence only."
    step = "ai"
    tools = ["deterministic risk scorer", "Gemini via LangChain (langchain-google-genai)",
             "hallucinated-ID guardrail", "evidence-claim guardrail", "response cache"]
    uses_llm = True

    def run(self, state: dict) -> dict:
        c = self.ctx
        ranked = rank(state["findings"])
        self.emit("running", f"Sending the top {c.top} findings (evidence only) to the AI for explanation")
        llm = LLM(c.cache)
        if not c.use_llm:
            llm.key = ""
        context = {"app": f"{state['inv'].app_name}@{state['inv'].app_version}", "ecosystem": "npm (Node.js)",
                   "deployment": "Docker image; production install excludes devDependencies",
                   "inventory": state["stats"], "changes_vs_baseline": state.get("changes") or {}}
        ai_status = explain(ranked, context, llm, top_n=c.top)
        ai_status["backend"] = llm.backend
        ai_status["attempts"] = list(llm.attempts)
        self.emit("done", f"Explained by {ai_status['model']}" if ai_status["mode"] == "llm"
                  else "AI unavailable: used deterministic explanations",
                  {"mode": ai_status["mode"], "model": ai_status["model"]})
        levels: dict[str, int] = {}
        for f in ranked:
            levels[f.risk_level] = levels.get(f.risk_level, 0) + 1
        explained = sum(1 for f in ranked if f.ai)
        self.summary = (f"{len(ranked)} findings ranked ({levels.get('Critical', 0)} critical); "
                        + (f"{explained} explained by {ai_status['model']}." if ai_status["mode"] == "llm"
                           else "AI unavailable, deterministic explanations used."))
        self.outputs = {"ranked": len(ranked), "by_level": levels, "llm_mode": ai_status["mode"],
                        "model": ai_status["model"] if ai_status["mode"] == "llm" else None,
                        "sent_to_llm": ai_status.get("sent_findings"), "api_calls": (ai_status.get("calls") or {}).get("api"),
                        "cache_hits": (ai_status.get("calls") or {}).get("cache_hits")}
        return {"ranked": ranked, "ai_status": ai_status}

    def fallback(self, state: dict) -> dict:
        ranked = rank(state["findings"])  # deterministic scoring never needs the network
        return {"ranked": ranked, "ai_status": {"mode": "fallback", "model": "", "sent_findings": 0,
                                                "calls": {}, "error": "explanation agent failed"}}
