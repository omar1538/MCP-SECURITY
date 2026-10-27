"""A scripted chat model, so agent tests run offline and deterministically."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import Field


def call(name: str, call_id: str, **args: Any) -> dict:
    return {"name": name, "args": args, "id": call_id, "type": "tool_call"}


class ScriptedChatModel(BaseChatModel):
    """Returns the queued AI messages in order and records what it was shown."""

    script: list[AIMessage]
    seen: list[list[BaseMessage]] = Field(default_factory=list)

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> ScriptedChatModel:
        return self

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        self.seen.append(list(messages))
        msg = self.script.pop(0) if self.script else AIMessage("done")
        usage = {"input_tokens": 100, "output_tokens": 10, "total_tokens": 110}
        msg = msg.model_copy(update={"usage_metadata": usage})
        return ChatResult(generations=[ChatGeneration(message=msg)])
