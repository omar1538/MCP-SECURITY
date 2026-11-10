"""Live interactive demo (FastAPI) for the MCP Security Gateway.

A thin HTTP + static-UI layer over :mod:`eval.demo`. Runs the finance agent on a
chosen scenario with the gateway on or off and returns the full trace. See
``eval.demo`` for the engine; the Gradio Space (``deploy/hf-gradio``) uses the
same engine.

Run:
    uvicorn server.app:app --reload   # then open http://localhost:8000
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agent.config import load_settings
from eval.demo import run_scenario, scenario_list, scenarios

app = FastAPI(title="MCP Security Gateway - live demo")
_lock = asyncio.Lock()  # serialise runs; they share one runtime.db


class RunRequest(BaseModel):
    scenario_id: str | None = None
    gateway: bool = True
    live: bool = False
    task: str | None = None


@app.get("/api/scenarios")
def scenarios_endpoint() -> list[dict]:
    return scenario_list()


@app.get("/api/health")
def health() -> dict:
    s = load_settings()
    return {"ok": True, "scenarios": len(scenarios()),
            "llm_configured": s.llm.base_url, "llm_model": s.llm.model}


@app.post("/api/run")
async def run(req: RunRequest) -> dict:
    async with _lock:
        return await run_scenario(req.scenario_id, req.gateway, req.live, req.task)


_STATIC = Path(__file__).parent / "static"


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (_STATIC / "index.html").read_text(encoding="utf-8")


if _STATIC.exists():
    app.mount("/static", StaticFiles(directory=_STATIC), name="static")
