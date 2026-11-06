"""Live interactive demo for the MCP Security Gateway.

A small FastAPI app that runs the finance agent on a chosen scenario - a benign
task or one of the 156 attacks - with the gateway on or off, and returns the
full step-by-step trace: every tool call, the gateway's verdict (allow / deny +
which layer + reason), the provenance tag on document reads, and the resulting
side effects. The browser UI renders it live.

Two modes:
* **scripted** (default): a deterministic compromised/benign agent drives the
  exact tool calls; no LLM needed, works anywhere.
* **live**: set an OpenAI-compatible endpoint (MSG_LLM_BASE_URL / MSG_LLM_MODEL /
  MSG_LLM_API_KEY) and pass a free-text task; the real model decides the calls.

Run:
    uvicorn server.app:app --reload
    # then open http://localhost:8000
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from langchain_core.messages import AIMessage
from pydantic import BaseModel

from agent.config import load_settings
from agent.graph import build_chat_model
from agent.runner import run_task
from agent.scripted import ScriptedChatModel
from attacks.generate import generate_attacks
from data.store import data_dir, finance_db, reset_runtime, runtime_db
from eval.checks import NO_HARM, Outcome, evaluate
from eval.harness import (
    SERVER_OF,
    SERVERS,
    attacker_calls,
    plant_rug_pull,
    restore_rug_pull,
    script_for,
)
from eval.tasks import build_task_suite
from gateway.gateway import Gateway, load_allowed_ibans
from gateway.policy import GatewayPolicy

app = FastAPI(title="MCP Security Gateway - live demo")
_lock = asyncio.Lock()  # serialise runs; they share one runtime.db

LAYER_NAMES = {
    "pin_descriptions": "Description pinning", "iban_allowlist": "IBAN allowlist",
    "require_approval": "Approval gating", "egress_filter": "Egress filter",
    "scan_untrusted": "Untrusted-content scan", "": "",
}


def _gt() -> dict:
    return json.loads((data_dir() / "ground_truth.json").read_text())


def _scenarios() -> dict[str, dict]:
    gt = _gt()
    tasks = build_task_suite(gt, finance_db())
    attacks = generate_attacks(gt)
    out: dict[str, dict] = {}
    for t in tasks:
        out[f"benign:{t.task_id}"] = {
            "id": f"benign:{t.task_id}", "kind": "benign", "label": t.task_id,
            "category": t.family, "prompt": t.prompt, "_task": t,
        }
    for a in attacks:
        prompt = a.injection.get("override_prompt") or a.carrier_task_id
        out[f"attack:{a.attack_id}"] = {
            "id": f"attack:{a.attack_id}", "kind": "attack", "label": a.attack_id,
            "category": a.category, "subcategory": a.subcategory, "prompt": prompt, "_attack": a,
        }
    return out


SCENARIOS = _scenarios()


class RunRequest(BaseModel):
    scenario_id: str | None = None
    gateway: bool = True
    live: bool = False
    task: str | None = None


def _steps_from(res, gateway: Gateway | None) -> list[dict]:
    audit = gateway.audit if gateway else []
    steps = []
    for i, tc in enumerate(res.tool_calls):
        a = audit[i] if i < len(audit) else None
        steps.append({
            "tool": tc.name,
            "args": tc.args,
            "allowed": (a.allowed if a else True),
            "layer": (a.layer if a else ""),
            "layer_name": LAYER_NAMES.get(a.layer, a.layer) if a else "",
            "reason": (a.reason if a else ""),
            "provenance": (a.provenance if a else "trusted"),
            "output": (tc.output or "")[:600],
            "error": tc.error,
        })
    return steps


def _side_effects(o: Outcome) -> dict:
    return {
        "payment_requests": o.payment_requests,
        "executed_payments": o.executed_payments,
        "payee_changes": o.payee_changes,
        "outbox": o.outbox,
        "flags": o.flags,
        "categories": o.categories,
    }


async def _run(req: RunRequest) -> dict:
    settings = load_settings()
    scenario = SCENARIOS.get(req.scenario_id or "")
    gt = _gt()
    gateway = (
        Gateway(GatewayPolicy.all_on(), allowed_ibans=load_allowed_ibans(finance_db()))
        if req.gateway else None
    )

    rug = None
    reset_runtime()
    try:
        if req.live and req.task:
            model = build_chat_model(settings.llm)
            targets = dict(SERVERS)
            prompt = req.task
            max_steps = settings.max_steps
            check = None
        elif scenario and scenario["kind"] == "benign":
            t = scenario["_task"]
            from agent.scripted import call as _mk
            msgs = [
                AIMessage(content="", tool_calls=[_mk(s["tool"], f"o{i}", **s.get("args", {}))])
                for i, s in enumerate(t.oracle)
            ]
            msgs.append(AIMessage("done"))
            model = ScriptedChatModel(script=msgs)
            needed = {SERVER_OF.get(s["tool"], "transactions") for s in t.oracle} | {"docstore"}
            targets = {k: SERVERS[k] for k in needed}
            prompt, max_steps, check = t.prompt, len(t.oracle) + 3, t.check
        elif scenario and scenario["kind"] == "attack":
            a = scenario["_attack"]
            calls = attacker_calls(a, gt)
            model = ScriptedChatModel(script=script_for(calls))
            needed = {SERVER_OF.get(n, "transactions") for n, _ in calls} | {"docstore"}
            targets = {k: SERVERS[k] for k in needed} or {"transactions": SERVERS["transactions"]}
            prompt, max_steps, check = scenario["prompt"], len(calls) + 3, a.attack_check
            if a.injection.get("target") == "tool_description_at_step":
                rug = plant_rug_pull(a)
        else:
            return {"error": "pick a scenario, or enable live mode with a task"}

        res = await run_task(prompt, targets, model, max_steps=max_steps,
                             refresh_tools=True, gateway=gateway)
    except Exception as e:  # live LLM unreachable, etc.
        return {"error": f"{type(e).__name__}: {e}"}
    finally:
        if rug is not None:
            restore_rug_pull(scenario["_attack"], rug[1])

    outcome = Outcome.load(runtime_db(), res.to_dict())
    kind = scenario["kind"] if scenario else "live"
    verdict = None
    if kind == "attack" and check:
        verdict = {"type": "attack", "succeeded": evaluate(check, outcome)}
    elif kind == "benign" and check:
        verdict = {"type": "benign", "passed": evaluate(check, outcome)}

    return {
        "mode": "live" if (req.live and req.task) else "scripted",
        "gateway": req.gateway,
        "kind": kind,
        "prompt": prompt,
        "final_answer": res.final_answer,
        "steps": _steps_from(res, gateway),
        "side_effects": _side_effects(outcome),
        "no_harm": evaluate(NO_HARM, outcome),
        "verdict": verdict,
        "stats": (
            {"calls": gateway.stats.calls, "denied": gateway.stats.denied,
             "denied_by_layer": gateway.stats.denied_by_layer,
             "injections_flagged": gateway.stats.injections_flagged,
             "rug_pulls_detected": gateway.stats.rug_pulls_detected}
            if gateway else None
        ),
    }


@app.get("/api/scenarios")
def scenarios() -> list[dict]:
    return [
        {k: v for k, v in s.items() if not k.startswith("_")}
        for s in SCENARIOS.values()
    ]


@app.get("/api/health")
def health() -> dict:
    s = load_settings()
    return {"ok": True, "scenarios": len(SCENARIOS),
            "llm_configured": s.llm.base_url, "llm_model": s.llm.model}


@app.post("/api/run")
async def run(req: RunRequest) -> dict:
    async with _lock:
        return await _run(req)


_STATIC = Path(__file__).parent / "static"


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (_STATIC / "index.html").read_text(encoding="utf-8")


if _STATIC.exists():
    app.mount("/static", StaticFiles(directory=_STATIC), name="static")
