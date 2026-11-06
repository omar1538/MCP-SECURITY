---
title: MCP Security Gateway
emoji: 🛡️
colorFrom: indigo
colorTo: green
sdk: docker
app_port: 7860
pinned: false
license: mit
---

# MCP Security Gateway — live demo

A security gateway that sits between an LLM agent and its MCP tool servers.
This Space runs a money-moving finance agent on benign tasks and on 156
adversarial attacks (indirect prompt injection, tool poisoning, rug-pull,
exfiltration, privilege escalation), with the gateway on or off, and shows the
full trace: every tool call, the gateway's verdict (allow / deny + which layer +
why), provenance tags, and the resulting side effects.

Pick a scenario, toggle the gateway, and watch the same attack succeed, then get
blocked. Runs deterministically — no LLM required.

**Headline:** attack success rate **100% → 0.6%** with the gateway on, at **100%**
benign-task utility.

Source and full report: <https://github.com/omar1538/MCP-SECURITY>
