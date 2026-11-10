"""Gradio front-end for the MCP Security Gateway live demo (Hugging Face Space).

Runs on free Gradio Spaces. Pick a scenario (a benign task or one of 156
attacks), toggle the gateway on/off, and see the full trace: each tool call, the
gateway's verdict (allow / deny + which layer + why), provenance tags, and the
resulting side effects. Deterministic, no LLM required.

The gateway logic lives in the installed package (eval.demo); this file is only
the UI. Locally: `python deploy/hf-gradio/app.py`.
"""

from __future__ import annotations

import html as _html
import json
import os
from pathlib import Path

# ensure a writable data dir and generate the synthetic world on first boot
os.environ.setdefault("MSG_DATA_DIR", str(Path.cwd() / ".data"))
_DATA = Path(os.environ["MSG_DATA_DIR"])
if not (_DATA / "ground_truth.json").exists():
    from data.generate import generate
    generate(_DATA, seed=7)

import gradio as gr  # noqa: E402

from eval.demo import run_scenario, scenarios  # noqa: E402

# Hugging Face ZeroGPU Spaces refuse to start unless at least one @spaces.GPU
# function exists, even for a CPU-only app like this one. Define a trivial,
# never-called one so the Space boots on free ZeroGPU hardware. On any host
# without the `spaces` package (e.g. local), this is skipped.
try:
    import spaces  # noqa: E402

    @spaces.GPU(duration=1)
    def _zerogpu_keepalive() -> bool:  # never invoked by the UI
        return True
except ImportError:
    pass

INK = "#e8edf5"
MUT = "#8c99b0"
BORDER = "#242f44"
PANEL = "#121825"
BG = "#0b0f17"
DANGER = "#f0566b"
SAFE = "#29d3b5"
ACCENT = "#6aa0ff"
WARN = "#f0b24b"


def _choices() -> list[tuple[str, str]]:
    benign, attack = [], []
    for s in scenarios().values():
        cat = (s.get("category") or "").replace("_", " ")
        if s["kind"] == "benign":
            benign.append((f"🟢 benign · {cat} · {s['label']}", s["id"]))
        else:
            attack.append((f"🔴 attack · {cat} · {s['label']}", s["id"]))
    attack.sort()
    return benign + attack


def _esc(x) -> str:
    return _html.escape(str(x))


def _render(d: dict) -> str:
    if "error" in d:
        return f'<div style="color:{DANGER};padding:14px">⚠ {_esc(d["error"])}</div>'

    v = d.get("verdict")
    if v and v["type"] == "attack":
        ok = not v["succeeded"]
        banner = (
            f'<div style="padding:14px 16px;border-radius:12px;font-weight:700;'
            f'background:{"#0f2b28" if ok else "#2a1620"};border:1px solid {SAFE if ok else DANGER};'
            f'color:{SAFE if ok else DANGER}">'
            f'{"✓ Attack blocked — gateway held, no harmful effect" if ok else "✗ Attack succeeded — harmful effect occurred"}</div>'
        )
    elif v and v["type"] == "benign":
        ok = v["passed"]
        banner = (
            f'<div style="padding:14px 16px;border-radius:12px;font-weight:700;'
            f'background:{"#0f2b28" if ok else "#2a1620"};border:1px solid {SAFE if ok else DANGER};'
            f'color:{SAFE if ok else DANGER}">'
            f'{"✓ Task completed correctly — utility preserved" if ok else "✗ Task not completed"}</div>'
        )
    else:
        banner = ""

    rows = []
    for s in d["steps"]:
        if s["allowed"]:
            chip = f'<span style="background:#16233f;color:{ACCENT};font-size:11px;font-weight:700;padding:2px 9px;border-radius:999px">allowed</span>'
        else:
            chip = f'<span style="background:#2a1620;color:{DANGER};font-size:11px;font-weight:700;padding:2px 9px;border-radius:999px">blocked · {_esc(s["layer_name"] or "gateway")}</span>'
        prov = ""
        if s["provenance"] and s["provenance"] != "trusted":
            col = WARN if s["provenance"] == "untrusted" else SAFE
            prov = f'<span style="background:#2a2410;color:{col};font-size:11px;padding:2px 8px;border-radius:999px;margin-left:6px">{_esc(s["provenance"])}</span>'
        reason = f'<div style="color:{DANGER};font-size:13px;margin-top:6px">⛔ {_esc(s["reason"])}</div>' if not s["allowed"] else ""
        out = f'<div style="font-family:monospace;font-size:11px;color:#5e6b82;background:{BG};border:1px solid {BORDER};border-radius:8px;padding:8px 10px;margin-top:6px;max-height:110px;overflow:auto;white-space:pre-wrap">{_esc(s["output"])}</div>' if s["output"] else ""
        rows.append(
            f'<div style="background:{PANEL};border:1px solid {DANGER if not s["allowed"] else BORDER};'
            f'border-radius:12px;padding:12px 14px;margin-top:10px">'
            f'<div><span style="font-family:monospace;font-weight:600">{_esc(s["tool"])}</span> {chip}{prov}</div>'
            f'<div style="font-family:monospace;font-size:12px;color:{MUT};margin-top:6px;word-break:break-all">{_esc(json.dumps(s["args"]))}</div>'
            f'{reason}{out}</div>'
        )
    steps_html = "".join(rows) or f'<div style="color:{MUT};margin-top:10px">no tool calls</div>'

    fx = d["side_effects"]
    def card(n, label, hot, items):
        col = DANGER if (hot and n) else INK
        lis = "".join(f"<li>{_esc(i)}</li>" for i in items) if items else ""
        ul = f'<ul style="margin:6px 0 0;padding-left:16px;font-size:12px;color:{MUT}">{lis}</ul>' if lis else ""
        return (f'<div style="background:{PANEL};border:1px solid {BORDER};border-radius:11px;padding:12px 14px">'
                f'<div style="font-size:22px;font-weight:700;color:{col}">{n}</div>'
                f'<div style="font-size:12px;color:{MUT}">{label}</div>{ul}</div>')
    mails = [m["recipient"] for m in fx["outbox"] if m["channel"] == "email"]
    fx_html = (
        '<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-top:10px">'
        + card(len(fx["payment_requests"]), "payment requests", False,
               [f'{float(p["amount"]):.0f}€ → {p["iban"]}' for p in fx["payment_requests"]])
        + card(len(fx["executed_payments"]), "payments EXECUTED", True,
               [f'{float(p["amount"]):.0f}€ → {p["iban"]}' for p in fx["executed_payments"]])
        + card(len(fx["payee_changes"]), "payee IBANs changed", True,
               [c["new_iban"] for c in fx["payee_changes"]])
        + card(len(mails), "emails sent", True, mails)
        + "</div>"
    )

    stats = ""
    if d.get("stats"):
        st = d["stats"]
        bl = ", ".join(f"{k}:{n}" for k, n in (st["denied_by_layer"] or {}).items()) or "—"
        stats = (f'<div style="color:{MUT};font-size:13px;margin-top:14px;padding-top:12px;border-top:1px solid {BORDER}">'
                 f'<b style="color:{INK}">{st["calls"]}</b> calls · <b style="color:{INK}">{st["denied"]}</b> denied '
                 f'· by layer: {_esc(bl)} · {st["injections_flagged"]} injections flagged '
                 f'· {st["rug_pulls_detected"]} rug-pulls detected</div>')

    prompt = f'<div style="background:{PANEL};border:1px solid {BORDER};border-radius:12px;padding:12px 14px;font-size:14px;color:{INK}"><div style="font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:{MUT}">prompt</div>{_esc(d["prompt"])}</div>'
    return f'<div style="font-family:system-ui,sans-serif">{prompt}<div style="margin-top:14px">{banner}</div><div>{steps_html}</div>' \
           f'<h3 style="color:{MUT};font-size:13px;text-transform:uppercase;letter-spacing:.05em;margin:20px 0 4px">Side effects</h3>{fx_html}{stats}</div>'


async def on_run(scenario_id: str, gw: str) -> str:
    d = await run_scenario(scenario_id, gateway=(gw == "Gateway ON"))
    return _render(d)


CHOICES = _choices()

with gr.Blocks(title="MCP Security Gateway", theme=gr.themes.Base()) as demo:
    gr.Markdown(
        "# 🛡️ MCP Security Gateway — live demo\n"
        "A deterministic firewall between an LLM agent and its MCP tool servers. "
        "Pick a scenario, toggle the gateway, and watch the same attack succeed, then get blocked. "
        "Attack success rate **100% → 0.6%** at **100%** benign utility. "
        "[Source & report](https://github.com/omar1538/MCP-SECURITY)."
    )
    with gr.Row():
        scenario = gr.Dropdown(choices=CHOICES, value=CHOICES[0][1], label="Scenario", scale=3)
        gw = gr.Radio(["Gateway ON", "Gateway OFF"], value="Gateway ON", label="Gateway", scale=1)
    run_btn = gr.Button("Run", variant="primary")
    out = gr.HTML()
    run_btn.click(on_run, inputs=[scenario, gw], outputs=out)

if __name__ == "__main__":
    demo.launch()
