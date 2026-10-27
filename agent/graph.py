"""The LangGraph financial-operations agent.

A plain tool-calling loop, written out explicitly rather than hidden behind a
prebuilt helper, so the evaluation can see (and later instrument) every step::

    START -> agent --(tool calls?)--> tools -> agent -> ... -> END
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import SystemMessage
from langchain_core.tools import BaseTool
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import ToolNode, tools_condition

from agent.config import LLMConfig
from agent.prompts import SYSTEM_PROMPT


def build_chat_model(cfg: LLMConfig) -> BaseChatModel:
    """Any OpenAI-compatible endpoint: Ollama, vLLM, OpenAI, OpenRouter..."""
    return ChatOpenAI(
        base_url=cfg.base_url,
        model=cfg.model,
        api_key=cfg.api_key,
        temperature=cfg.temperature,
        timeout=cfg.timeout_s,
        stream_usage=True,
    )


def build_graph(
    model: BaseChatModel,
    tools: Sequence[BaseTool],
    system_prompt: str = SYSTEM_PROMPT,
    before_step: Callable[[], Awaitable[None]] | None = None,
) -> CompiledStateGraph:
    """Compile the agent loop.

    ``before_step`` runs before every model call; the runner uses it to re-list
    tool definitions, so tools are re-bound each step with their current text.
    """

    async def agent(state: MessagesState) -> dict:
        if before_step is not None:
            await before_step()
        bound = model.bind_tools(list(tools))
        response = await bound.ainvoke([SystemMessage(system_prompt), *state["messages"]])
        return {"messages": [response]}

    graph = StateGraph(MessagesState)
    graph.add_node("agent", agent)
    graph.add_node("tools", ToolNode(list(tools), handle_tool_errors=True))
    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", tools_condition, {"tools": "tools", END: END})
    graph.add_edge("tools", "agent")
    return graph.compile()
