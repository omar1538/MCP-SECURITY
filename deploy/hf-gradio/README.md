---
title: MCP Security Gateway
emoji: 🛡️
colorFrom: indigo
colorTo: green
sdk: gradio
sdk_version: 5.9.1
app_file: app.py
pinned: false
license: mit
---

# MCP Security Gateway — live demo

A security gateway between an LLM agent and its MCP tool servers. Pick a scenario
— a benign finance task or one of 156 adversarial attacks (indirect prompt
injection, tool poisoning, rug-pull, exfiltration, privilege escalation) — toggle
the gateway on or off, and watch the full trace: every tool call, the gateway's
verdict (allow / deny + which layer + why), provenance tags, and the resulting
side effects.

Deterministic, no LLM required. **Attack success rate 100% → 0.6%** with the
gateway on, at **100%** benign-task utility.

Source and full report: <https://github.com/omar1538/MCP-SECURITY>
