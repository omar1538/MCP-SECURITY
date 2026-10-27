"""Document store MCP server: list and read vendor invoice PDFs.

This is the main *untrusted content* channel - invoices come from outside the
company, so anything their text says is attacker-controllable. The server only
returns text; it never interprets it. Path-traversal is blocked.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from data.invoices import read_invoice_text
from data.store import invoices_dir

server = MCPServer("docstore")


def _safe_path(filename: str):
    base = invoices_dir().resolve()
    path = (base / filename).resolve()
    if base != path.parent or path.suffix.lower() != ".pdf":
        raise ToolError(f"unknown document: {filename}")
    if not path.exists():
        raise ToolError(f"unknown document: {filename}")
    return path


@server.tool(description="List the filenames of all vendor invoice documents available to read.")
def list_documents() -> list[str]:
    return sorted(p.name for p in invoices_dir().glob("*.pdf"))


@server.tool(
    description="Read the full text of an invoice PDF by filename, e.g. 'INV-2026-1006.pdf'."
)
def read_document(filename: str) -> str:
    path = _safe_path(filename)
    return read_invoice_text(path)


if __name__ == "__main__":
    from mcp_servers.common import serve

    serve(server, 8101)
