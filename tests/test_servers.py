"""Tests for the MCP tool servers, exercised in-process via mcp.Client."""

from __future__ import annotations

from mcp import Client

from data.store import runtime_db
from eval.checks import Outcome
from mcp_servers.docstore import server as docstore
from mcp_servers.notify import server as notify
from mcp_servers.payments import server as payments
from mcp_servers.transactions import server as txns


async def _call(server, name, **args):
    async with Client(server) as c:
        res = await c.call_tool(name, args)
        sc = res.structured_content
        if isinstance(sc, dict) and set(sc) == {"result"}:
            sc = sc["result"]
        return sc, res.is_error


class TestDocstore:
    async def test_list(self, data_dir):
        docs, err = await _call(docstore, "list_documents")
        assert not err and len(docs) == 20

    async def test_read(self, data_dir, ground_truth):
        f = ground_truth["invoices"][0]["file"]
        text, err = await _call(docstore, "read_document", filename=f)
        assert not err and "INVOICE" in text

    async def test_path_traversal_blocked(self, data_dir):
        _, err = await _call(docstore, "read_document", filename="../finance.db")
        assert err


class TestTransactions:
    async def test_account_summary(self, data_dir):
        acc, err = await _call(txns, "get_account_summary", account_id="ACC-OPS-001")
        assert not err and acc["transaction_count"] == 348

    async def test_search_limit(self, data_dir):
        rows, err = await _call(txns, "search_transactions")
        assert not err and len(rows) <= 200

    async def test_categorize_records(self, data_dir):
        await _call(txns, "categorize_transaction", txn_id="TXN-00001", category="Software")
        o = Outcome.load(runtime_db())
        assert o.categories.get("TXN-00001") == "Software"

    async def test_flag_records(self, data_dir):
        await _call(txns, "flag_anomaly", subject_id="TXN-00009", reason="weird")
        o = Outcome.load(runtime_db())
        assert any(f["subject_id"] == "TXN-00009" for f in o.flags)


class TestPayments:
    async def test_create_request(self, data_dir):
        res, err = await _call(payments, "create_payment_request",
                               payee_name="V", iban="FR76123", amount=100.0, reference="R")
        assert not err and res["status"] == "pending_approval"

    async def test_execute_needs_request(self, data_dir):
        _, err = await _call(payments, "execute_payment", request_id=99999)
        assert err


class TestNotify:
    async def test_email_to_outbox(self, data_dir):
        await _call(notify, "send_email", recipient="x@evil.example", subject="s", body="b")
        o = Outcome.load(runtime_db())
        assert any(m["recipient"] == "x@evil.example" for m in o.outbox)
