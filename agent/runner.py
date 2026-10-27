"""Run one task end to end and return a structured trace.

The trace (tool calls, final answer, tokens, latency) is what the evaluation
harness scores; side effects are read separately from ``runtime.db``.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langgraph.errors import GraphRecursionError

from agent.graph import build_graph
from agent.mcp_tools import MCPToolbox
from agent.prompts import SYSTEM_PROMPT


@dataclass
class ToolCallRecord:
    name: str
    args: dict[str, Any]
    output: str | None = None
    error: bool = False


@dataclass
class RunResult:
    task: str
    final_answer: str
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    latency_s: float = 0.0
    steps: int = 0
    stopped_reason: str = "completed"  # completed | step_limit

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def summarize(task: str, messages: list[BaseMessage], latency_s: float, reason: str) -> RunResult:
    res = RunResult(
        task=task, final_answer="", latency_s=round(latency_s, 3), stopped_reason=reason
    )
    by_id: dict[str, ToolCallRecord] = {}
    for m in messages:
        if isinstance(m, AIMessage):
            res.steps += 1
            if m.usage_metadata:
                res.input_tokens += m.usage_metadata.get("input_tokens", 0)
                res.output_tokens += m.usage_metadata.get("output_tokens", 0)
            for tc in m.tool_calls:
                rec = ToolCallRecord(name=tc["name"], args=dict(tc["args"]))
                res.tool_calls.append(rec)
                by_id[tc["id"]] = rec
            if not m.tool_calls and isinstance(m.content, str):
                res.final_answer = m.content
        elif isinstance(m, ToolMessage) and m.tool_call_id in by_id:
            rec = by_id[m.tool_call_id]
            rec.output = m.content if isinstance(m.content, str) else str(m.content)
            rec.error = m.status == "error"
    return res


async def run_task(
    task: str,
    targets: dict[str, Any],
    model: BaseChatModel,
    *,
    max_steps: int = 25,
    system_prompt: str = SYSTEM_PROMPT,
    refresh_tools: bool = True,
    gateway: Any = None,
) -> RunResult:
    """Connect to ``targets``, run ``task`` through the agent, return its trace.

    With ``refresh_tools`` the agent re-reads tool definitions before each step,
    like a client that honours ``tools/list_changed``. If ``gateway`` is given,
    every tool call is routed through it for inspection and policy enforcement.
    """
    async with MCPToolbox(targets, gateway=gateway) as box:
        hook = box.refresh if refresh_tools else None
        graph = build_graph(model, box.tools, system_prompt, before_step=hook)
        messages: list[BaseMessage] = [HumanMessage(task)]
        reason = "completed"
        start = time.perf_counter()
        try:
            async for state in graph.astream(
                {"messages": messages},
                config={"recursion_limit": 2 * max_steps},
                stream_mode="values",
            ):
                messages = state["messages"]
        except GraphRecursionError:
            reason = "step_limit"
        latency = time.perf_counter() - start
    return summarize(task, messages, latency, reason)
