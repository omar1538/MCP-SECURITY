"""Tests for the agent toolbox / graph / runner, using the scripted model."""

from __future__ import annotations

from langchain_core.messages import AIMessage

from agent.mcp_tools import MCPToolbox
from agent.runner import run_task
from mcp_servers.docstore import server as docstore
from mcp_servers.payments import server as payments
from mcp_servers.transactions import server as txns
from tests.fakes import ScriptedChatModel, call


class TestToolbox:
    async def test_loads_all_tools(self, data_dir):
        async with MCPToolbox({"docstore": docstore, "payments": payments, "transactions": txns}) as box:
            names = {t.name for t in box.tools}
        assert {"list_documents", "create_payment_request", "get_account_summary"} <= names

    async def test_name_collision_detected(self, data_dir):
        # same server twice -> duplicate tool names
        import pytest
        with pytest.raises(ValueError, match="collision"):
            async with MCPToolbox({"a": payments, "b": payments}):
                pass

    async def test_refresh_picks_up_description_change(self, data_dir):
        async with MCPToolbox({"payments": payments}) as box:
            tool = box._tool_manager if False else None  # noqa
            pm = payments._tool_manager.get_tool("list_payees")
            original = pm.description
            pm.description = "CHANGED DESCRIPTION"
            try:
                await box.refresh()
                lp = next(t for t in box.tools if t.name == "list_payees")
                assert lp.description == "CHANGED DESCRIPTION"
            finally:
                pm.description = original


class TestRunner:
    async def test_runs_scripted_tool_calls(self, data_dir):
        from data.store import reset_runtime
        reset_runtime()
        model = ScriptedChatModel(script=[
            AIMessage(content="", tool_calls=[call("get_account_summary", "1", account_id="ACC-OPS-001")]),
            AIMessage(content="all done")])
        res = await run_task("summary", {"transactions": txns}, model, max_steps=4, refresh_tools=False)
        assert res.stopped_reason == "completed"
        assert res.final_answer == "all done"
        assert res.tool_calls[0].name == "get_account_summary"
        assert not res.tool_calls[0].error

    async def test_step_limit(self, data_dir):
        from data.store import reset_runtime
        reset_runtime()
        # a model that always calls a tool, never stops
        script = [AIMessage(content="", tool_calls=[call("get_account_summary", str(i))])
                  for i in range(50)]
        model = ScriptedChatModel(script=script)
        res = await run_task("loop", {"transactions": txns}, model, max_steps=3, refresh_tools=False)
        assert res.stopped_reason == "step_limit"

    async def test_tokens_counted(self, data_dir):
        from data.store import reset_runtime
        reset_runtime()
        model = ScriptedChatModel(script=[AIMessage(content="done")])
        res = await run_task("x", {"transactions": txns}, model, max_steps=3, refresh_tools=False)
        assert res.input_tokens > 0
