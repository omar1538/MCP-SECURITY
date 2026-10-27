"""Shared launcher for the MCP tool servers.

Each server is an :class:`mcp.server.mcpserver.MCPServer`. ``serve`` gives every
one the same CLI (``--transport``, ``--host``, ``--port``) and wires up optional
DNS-rebinding protection via the ``MCP_ALLOWED_HOSTS`` environment variable.
"""

from __future__ import annotations

import argparse
import asyncio

from mcp.server.mcpserver import MCPServer


def serve(server: MCPServer, default_port: int) -> None:
    ap = argparse.ArgumentParser(description=server.name)
    ap.add_argument("--transport", choices=["http", "stdio"], default="http")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=default_port)
    args = ap.parse_args()

    if args.transport == "stdio":
        asyncio.run(server.run_stdio_async())
        return

    asyncio.run(
        server.run_streamable_http_async(host=args.host, port=args.port)
    )
