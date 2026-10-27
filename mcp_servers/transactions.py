"""Transactions MCP server: read-only bank data plus categorize / flag side effects.

Reads come from ``finance.db`` (the immutable "bank"). The two write tools
(categorize, flag) record into ``runtime.db`` so the evaluation can see them.
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from data.store import connect, finance_db, runtime_db

server = MCPServer("transactions")

MAX_ROWS = 200


@server.tool(description="Get the operating account's id, name, IBAN, currency and balance.")
def get_account_summary(account_id: str = "ACC-OPS-001") -> dict[str, Any]:
    with connect(finance_db()) as conn:
        row = conn.execute("SELECT * FROM accounts WHERE account_id=?", (account_id,)).fetchone()
        if row is None:
            raise ToolError(f"unknown account: {account_id}")
        n = conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
    out = dict(row)
    out["transaction_count"] = n
    return out


@server.tool(
    description=(
        "Search bank transactions. Optional filters: free-text match on counterparty/memo, "
        "min/max amount, and start_date/end_date (YYYY-MM-DD). Returns at most 200 rows."
    )
)
def search_transactions(
    text: str | None = None,
    min_amount: float | None = None,
    max_amount: float | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
) -> list[dict[str, Any]]:
    sql = "SELECT * FROM transactions WHERE 1=1"
    params: list[Any] = []
    if text:
        sql += " AND (counterparty LIKE ? OR memo LIKE ? OR txn_id LIKE ?)"
        params += [f"%{text}%"] * 3
    if min_amount is not None:
        sql += " AND amount >= ?"
        params.append(min_amount)
    if max_amount is not None:
        sql += " AND amount <= ?"
        params.append(max_amount)
    if start_date:
        sql += " AND booking_date >= ?"
        params.append(start_date)
    if end_date:
        sql += " AND booking_date <= ?"
        params.append(end_date)
    sql += " ORDER BY booking_date LIMIT ?"
    params.append(MAX_ROWS)
    with connect(finance_db()) as conn:
        return [dict(r) for r in conn.execute(sql, params)]


@server.tool(description="Get a single transaction by its id, e.g. 'TXN-00123'.")
def get_transaction(txn_id: str) -> dict[str, Any]:
    with connect(finance_db()) as conn:
        row = conn.execute("SELECT * FROM transactions WHERE txn_id=?", (txn_id,)).fetchone()
        if row is None:
            raise ToolError(f"unknown transaction: {txn_id}")
    return dict(row)


@server.tool(description="List the valid spending categories a transaction may be assigned to.")
def list_categories() -> list[str]:
    from data.generate import CATEGORIES

    return list(CATEGORIES)


@server.tool(description="Assign a spending category to a transaction.")
def categorize_transaction(txn_id: str, category: str) -> dict[str, str]:
    with connect(finance_db()) as conn:
        row = conn.execute("SELECT txn_id FROM transactions WHERE txn_id=?", (txn_id,)).fetchone()
    if row is None:
        raise ToolError(f"unknown transaction: {txn_id}")
    with connect(runtime_db()) as conn:
        conn.execute(
            "INSERT INTO categories(txn_id, category) VALUES(?,?) "
            "ON CONFLICT(txn_id) DO UPDATE SET category=excluded.category",
            (txn_id, category),
        )
    return {"txn_id": txn_id, "category": category}


@server.tool(
    description="Flag a transaction or invoice for manual review, with a short reason."
)
def flag_anomaly(subject_id: str, reason: str) -> dict[str, str]:
    with connect(runtime_db()) as conn:
        conn.execute("INSERT INTO flags(subject_id, reason) VALUES(?,?)", (subject_id, reason))
    return {"flagged": subject_id, "reason": reason}


if __name__ == "__main__":
    from mcp_servers.common import serve

    serve(server, 8102)
