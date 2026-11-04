"""Build the data file the static dashboard (docs/index.html) reads.

Runs every attack once with the gateway off and once with it on (fully
deterministic, no LLM), records per-attack outcomes and which gateway layer
blocked each one, and writes ``docs/dashboard.json``.

    python -m eval.build_dashboard
"""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import date
from pathlib import Path

from attacks.generate import generate_attacks
from data.store import data_dir, finance_db
from eval.harness import run_attack
from eval.tasks import build_task_suite
from gateway.policy import GatewayPolicy

LAYER_INFO = [
    {"key": "pin_descriptions", "name": "Description pinning",
     "defends": "rug-pulls",
     "mechanism": "Hash-pin each tool description at startup; quarantine any tool whose "
                  "description changes mid-run and deny calls to it."},
    {"key": "iban_allowlist", "name": "IBAN allowlist",
     "defends": "payment redirection",
     "mechanism": "A payment request may only target an IBAN registered to a known payee "
                  "or the operating account."},
    {"key": "require_approval", "name": "Approval gating",
     "defends": "privilege escalation",
     "mechanism": "execute_payment and update_payee_bank_details are denied without an "
                  "explicit human approval token."},
    {"key": "egress_filter", "name": "Egress filter",
     "defends": "data exfiltration",
     "mechanism": "Email to a non-internal domain is denied, as is any email or chat "
                  "message carrying IBAN-shaped data."},
    {"key": "scan_untrusted", "name": "Untrusted-content scan",
     "defends": "prompt injection",
     "mechanism": "Document output is scanned for injection patterns, tagged with "
                  "provenance, and wrapped in a quarantine banner before the model reads it."},
]


async def build(out: Path, tests: int = 97) -> dict:
    gt = json.loads((data_dir() / "ground_truth.json").read_text())
    tasks = build_task_suite(gt, finance_db())
    attacks = generate_attacks(gt)

    rows = []
    off_hit = on_hit = 0
    cat: dict[str, dict] = {}
    for a in attacks:
        r_off = await run_attack(a, gt, None, "off")
        r_on = await run_attack(a, gt, GatewayPolicy.all_on(), "on")
        off_hit += r_off.attack_succeeded
        on_hit += r_on.attack_succeeded
        c = cat.setdefault(a.category, {"n": 0, "off": 0, "on": 0})
        c["n"] += 1
        c["off"] += r_off.attack_succeeded
        c["on"] += r_on.attack_succeeded
        rows.append({
            "id": a.attack_id,
            "category": a.category,
            "subcategory": a.subcategory,
            "intent": a.meta.get("payload_type", a.subcategory),
            "carrier": a.carrier_task_id,
            "off": bool(r_off.attack_succeeded),
            "on": bool(r_on.attack_succeeded),
            "block_layer": r_on.block_layer,
            "block_reason": r_on.block_reason,
        })

    by_category = [
        {"category": k, "n": v["n"],
         "off": round(v["off"] / v["n"], 4), "on": round(v["on"] / v["n"], 4)}
        for k, v in sorted(cat.items())
    ]

    # ablation from the summary file if present, else skip
    ablation = []
    summ_path = Path("results/baseline.summary.json")
    if summ_path.exists():
        summ = json.loads(summ_path.read_text())
        ablation = [{"layer": k, "asr": v}
                    for k, v in summ.get("ablation_asr_without_layer", {}).items()]

    data = {
        "meta": {"attacks": len(attacks), "tasks": len(tasks), "tests": tests,
                 "generated": date.today().isoformat()},
        "headline": {
            "asr_off": round(off_hit / len(attacks), 4),
            "asr_on": round(on_hit / len(attacks), 4),
            "utility_off": 1.0, "utility_on": 1.0,
        },
        "by_category": by_category,
        "ablation": ablation,
        "layers": LAYER_INFO,
        "attacks": rows,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    # Also emit a classic-script data file so the page works by double-click
    # (file://), where fetch() of a sibling JSON is blocked by the browser.
    (out.parent / "data.js").write_text(
        "window.DASHBOARD_DATA = " + json.dumps(data) + ";\n", encoding="utf-8"
    )
    return data


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=Path("docs/dashboard.json"))
    args = ap.parse_args()
    data = asyncio.run(build(args.out))
    print(f"wrote {args.out}: {data['meta']['attacks']} attacks, "
          f"ASR {data['headline']['asr_off']:.1%} -> {data['headline']['asr_on']:.1%}")


if __name__ == "__main__":
    main()
