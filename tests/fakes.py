"""Back-compat re-export: the scripted model now lives in ``agent.scripted``."""

from __future__ import annotations

from agent.scripted import ScriptedChatModel, call

__all__ = ["ScriptedChatModel", "call"]
