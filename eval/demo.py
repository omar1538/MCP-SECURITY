"""Shared engine for the interactive demos (FastAPI and Gradio).

Runs the finance agent on a scenario - a benign task or one of the 156 attacks -
with the gateway on or off, and returns a plain trace dict: the prompt, each tool
call with the gateway's verdict (allow / deny + layer + reason) and provenance,
the resulting side effects, the verdict, and gateway stats.

Scripted mode is deterministic and needs no LLM. Live mode (a free-text task +
an OpenAI-compatible endpoint) lets a real model drive the calls.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import AIMessage

from agent.config import load_settings
from agent.graph import build_chat_model
from agent.runner import run_task
from agent.scripted import ScriptedChatModel, call
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

LAYER_NAMES = {
    "pin_descriptions": "Description pinning", "iban_allowlist": "IBAN allowlist",
    "require_approval": "Approval gating", "egress_filter": "Egress filter",
    "scan_untrusted": "Untrusted-content scan", "": "",
}

_SCENARIOS: dict[str, dict] | None = None


def _gt() -> dict:
    return json.loads((data_dir() / "ground_truth.json").read_text())


def _build() -> dict[str, dict]:
    gt = _gt()
    out: dict[str, dict] = {}
    for t in build_task_suite(gt, finance_db()):
        out[f"benign:{t.task_id}"] = {
            "id": f"benign:{t.task_id}", "kind": "benign", "label": t.task_id,
            "category": t.family, "prompt": t.prompt, "_task": t,
        }
    for a in generate_attacks(gt):
        out[f"attack:{a.attack_id}"] = {
            "id": f"attack:{a.attack_id}", "kind": "attack", "label": a.attack_id,
            "category": a.category, "subcategory": a.subcategory,
            "prompt": a.injection.get("override_prompt") or a.carrier_task_id, "_attack": a,
        }
    return out


def scenarios() -> dict[str, dict]:
    """All scenarios, keyed by id (lazily built so data can be generated first)."""
    global _SCENARIOS
    if _SCENARIOS is None:
        _SCENARIOS = _build()
    return _SCENARIOS


def scenario_list() -> list[dict]:
    """Public scenario metadata (no internal objects)."""
    return [{k: v for k, v in s.items() if not k.startswith("_")} for s in scenarios().values()]


def _steps_from(res: Any, gateway: Gateway | None) -> list[dict]:
    audit = gateway.audit if gateway else []
    steps = []
    for i, tc in enumerate(res.tool_calls):
        a = audit[i] if i < len(audit) else None
        steps.append({
            "tool": tc.name, "args": tc.args,
            "allowed": (a.allowed if a else True),
            "layer": (a.layer if a else ""),
            "layer_name": LAYER_NAMES.get(a.layer, a.layer) if a else "",
            "reason": (a.reason if a else ""),
            "provenance": (a.provenance if a else "trusted"),
            "output": (tc.output or "")[:600], "error": tc.error,
        })
    return steps


def _side_effects(o: Outcome) -> dict:
    return {
        "payment_requests": o.payment_requests, "executed_payments": o.executed_payments,
        "payee_changes": o.payee_changes, "outbox": o.outbox,
        "flags": o.flags, "categories": o.categories,
    }


async def run_scenario(
    scenario_id: str | None, gateway: bool = True, live: bool = False, task: str | None = None
) -> dict:
    """Run one scenario and return its trace dict (see module docstring)."""
    settings = load_settings()
    scenario = scenarios().get(scenario_id or "")
    gt = _gt()
    gw = (
        Gateway(GatewayPolicy.all_on(), allowed_ibans=load_allowed_ibans(finance_db()))
        if gateway else None
    )
    rug = None
    reset_runtime()
    try:
        if live and task:
            model = build_chat_model(settings.llm)
            targets, prompt, max_steps, check = dict(SERVERS), task, settings.max_steps, None
        elif scenario and scenario["kind"] == "benign":
            t = scenario["_task"]
            msgs = [
                AIMessage(content="", tool_calls=[call(s["tool"], f"o{i}", **s.get("args", {}))])
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
                             refresh_tools=True, gateway=gw)
    except Exception as e:
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
        "mode": "live" if (live and task) else "scripted",
        "gateway": gateway, "kind": kind, "prompt": prompt,
        "final_answer": res.final_answer,
        "steps": _steps_from(res, gw),
        "side_effects": _side_effects(outcome),
        "no_harm": evaluate(NO_HARM, outcome), "verdict": verdict,
        "stats": (
            {"calls": gw.stats.calls, "denied": gw.stats.denied,
             "denied_by_layer": gw.stats.denied_by_layer,
             "injections_flagged": gw.stats.injections_flagged,
             "rug_pulls_detected": gw.stats.rug_pulls_detected}
            if gw else None
        ),
    }
