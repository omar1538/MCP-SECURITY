"""Run the agent on a single task from the command line.

    msg-agent "Process invoice INV-2026-1006.pdf"
"""

from __future__ import annotations

import argparse
import asyncio

from agent.config import load_settings
from agent.graph import build_chat_model
from agent.runner import run_task
from data.store import reset_runtime


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("task", help="the instruction to give the agent")
    ap.add_argument("--keep-runtime", action="store_true", help="do not wipe runtime.db first")
    args = ap.parse_args()

    settings = load_settings()
    if not args.keep_runtime:
        reset_runtime()
    model = build_chat_model(settings.llm)
    result = asyncio.run(run_task(args.task, settings.servers, model, max_steps=settings.max_steps))

    print(f"\n=== {result.stopped_reason} in {result.steps} steps, {result.latency_s}s ===")
    for tc in result.tool_calls:
        flag = " [error]" if tc.error else ""
        print(f"  -> {tc.name}({tc.args}){flag}")
    print(f"\n{result.final_answer}")


if __name__ == "__main__":
    main()
