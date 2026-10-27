"""Expose MCP server tools to LangChain / LangGraph.

``langchain-mcp-adapters`` does not support the ``mcp`` 2.x SDK yet, so this is
a small adapter of our own. It is also the natural seam for the project: the
agent only ever sees what this toolbox hands it, and on Day 3 the toolbox
simply points at the gateway instead of the raw servers.

A *target* is anything :class:`mcp.Client` accepts: a Streamable HTTP URL in
production, or an in-process ``MCPServer`` instance in tests.
"""

from __future__ import annotations

import json
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

from langchain_core.tools import BaseTool, StructuredTool, ToolException
from mcp import Client
from mcp.types import CallToolResult, Tool

from gateway.gateway import Gateway


def result_to_text(result: CallToolResult) -> str:
    """Flatten an MCP tool result into the string the model will read."""
    sc = result.structured_content
    if sc is not None and not result.is_error:
        if isinstance(sc, dict) and set(sc) == {"result"}:
            sc = sc["result"]
        return json.dumps(sc, ensure_ascii=False, default=str)
    parts: list[str] = []
    for block in result.content:
        text = getattr(block, "text", None)
        parts.append(text if text is not None else json.dumps(block.model_dump(), default=str))
    return "\n".join(parts)


@dataclass
class MCPToolbox:
    """Open one MCP session per server and wrap every tool as a LangChain tool.

    Use as an async context manager; sessions stay open for the whole agent run::

        async with MCPToolbox({"docstore": "http://localhost:8101/mcp"}) as box:
            graph = build_graph(model, box.tools)
    """

    targets: dict[str, Any]
    gateway: Gateway | None = None
    tools: list[BaseTool] = field(default_factory=list, init=False)
    definitions: dict[str, tuple[str, Tool]] = field(default_factory=dict, init=False)
    _clients: dict[str, Client] = field(default_factory=dict, init=False)
    _stack: AsyncExitStack | None = field(default=None, init=False)

    async def __aenter__(self) -> MCPToolbox:
        self._stack = AsyncExitStack()
        await self._stack.__aenter__()
        try:
            for server_name, target in self.targets.items():
                client = await self._stack.enter_async_context(Client(target))
                self._clients[server_name] = client
                server_tools = (await client.list_tools()).tools
                if self.gateway is not None:
                    self.gateway.register(server_name, server_tools)
                for tool in server_tools:
                    if tool.name in self.definitions:
                        other = self.definitions[tool.name][0]
                        raise ValueError(
                            f"tool name collision: {tool.name!r} on {other} and {server_name}"
                        )
                    self.definitions[tool.name] = (server_name, tool)
                    self.tools.append(self._wrap(server_name, client, tool))
        except BaseException:
            await self._stack.__aexit__(None, None, None)
            raise
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._stack is not None:
            await self._stack.__aexit__(*exc)
        self._stack = None

    async def refresh(self) -> None:
        """Re-list every server's tools and update descriptions in place.

        This is what a client that honours ``notifications/tools/list_changed``
        does, and it is what makes a mid-run rug-pull visible to the model.
        """
        by_name = {t.name: t for t in self.tools}
        for server_name, client in self._clients.items():
            server_tools = (await client.list_tools()).tools
            if self.gateway is not None:
                self.gateway.on_refresh(server_name, server_tools)
            for tool in server_tools:
                if tool.name in by_name and self.definitions[tool.name][0] == server_name:
                    self.definitions[tool.name] = (server_name, tool)
                    by_name[tool.name].description = tool.description or tool.name

    def _wrap(self, server_name: str, client: Client, tool: Tool) -> BaseTool:
        gateway = self.gateway

        async def _call(**kwargs: Any) -> str:
            args = {k: v for k, v in kwargs.items() if v is not None}
            if gateway is not None:
                decision = gateway.guard(server_name, tool.name, args)
                if not decision.allow:
                    raise ToolException(f"blocked by security gateway: {decision.reason}")
            result = await client.call_tool(tool.name, args)
            text = result_to_text(result)
            if result.is_error:
                raise ToolException(text)
            if gateway is not None:
                text, _ = gateway.inspect_output(server_name, tool.name, text)
            return text

        schema = dict(tool.input_schema or {"type": "object", "properties": {}})
        schema.setdefault("properties", {})
        return StructuredTool(
            name=tool.name,
            description=tool.description or tool.name,
            args_schema=schema,
            coroutine=_call,
            handle_tool_error=True,
            metadata={"mcp_server": server_name},
        )
