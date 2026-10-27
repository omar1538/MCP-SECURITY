"""Runtime configuration, read from environment variables.

MCP endpoints
    ``MSG_MCP_SERVERS`` - JSON object ``{"name": "url", ...}``. Defaults to the four
    local servers. From Day 3 this points at the gateway instead.

LLM (any OpenAI-compatible endpoint: Ollama, vLLM, OpenAI, OpenRouter...)
    ``MSG_LLM_BASE_URL`` (default Ollama ``http://localhost:11434/v1``)
    ``MSG_LLM_MODEL``    (default ``qwen2.5:7b-instruct``)
    ``MSG_LLM_API_KEY``  (default ``ollama``; Ollama ignores it)

The agent is deliberately model-agnostic: swapping a retired model for a new one
is a one-line env change (MSG_LLM_MODEL / MSG_LLM_BASE_URL), no code edits.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

DEFAULT_SERVERS = {
    "docstore": "http://localhost:8101/mcp",
    "transactions": "http://localhost:8102/mcp",
    "payments": "http://localhost:8103/mcp",
    "notify": "http://localhost:8104/mcp",
}


@dataclass(frozen=True)
class LLMConfig:
    base_url: str = "http://localhost:11434/v1"
    model: str = "qwen2.5:7b-instruct"
    api_key: str = "ollama"
    temperature: float = 0.0
    timeout_s: float = 120.0


@dataclass(frozen=True)
class Settings:
    servers: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_SERVERS))
    llm: LLMConfig = field(default_factory=LLMConfig)
    max_steps: int = 25


def load_settings() -> Settings:
    servers = dict(DEFAULT_SERVERS)
    if raw := os.environ.get("MSG_MCP_SERVERS"):
        servers = json.loads(raw)
    llm = LLMConfig(
        base_url=os.environ.get("MSG_LLM_BASE_URL", LLMConfig.base_url),
        model=os.environ.get("MSG_LLM_MODEL", LLMConfig.model),
        api_key=os.environ.get("MSG_LLM_API_KEY", LLMConfig.api_key),
        temperature=float(os.environ.get("MSG_LLM_TEMPERATURE", LLMConfig.temperature)),
    )
    return Settings(servers=servers, llm=llm, max_steps=int(os.environ.get("MSG_MAX_STEPS", 25)))
