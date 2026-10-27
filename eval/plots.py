"""Render result plots from a harness summary JSON.

    python -m eval.plots --summary results/baseline.summary.json --out results/
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

INK = "#1b2a4a"
OFF = "#d1495b"
ON = "#2a9d8f"


def plot_asr_by_category(summary: dict, out: Path) -> Path:
    off = summary["asr_by_category_off"]
    on = summary["asr_by_category_on"]
    cats = list(off)
    labels = [c.replace("_", "\n") for c in cats]
    x = range(len(cats))
    w = 0.38
    fig, ax = plt.subplots(figsize=(9, 4.5))
    ax.bar([i - w / 2 for i in x], [off[c] * 100 for c in cats], w, label="gateway off", color=OFF)
    ax.bar([i + w / 2 for i in x], [on.get(c, 0) * 100 for c in cats], w,
           label="gateway on", color=ON)
    ax.set_ylabel("Attack success rate (%)")
    ax.set_title("Attack success rate by category, gateway off vs on")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylim(0, 105)
    ax.legend()
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    p = out / "asr_by_category.png"
    fig.savefig(p, dpi=130)
    plt.close(fig)
    return p


def plot_ablation(summary: dict, out: Path) -> Path:
    abl = summary["ablation_asr_without_layer"]
    full = summary["asr_gateway_on"]
    layers = list(abl)
    vals = [abl[la] * 100 for la in layers]
    fig, ax = plt.subplots(figsize=(8, 4.2))
    ax.bar([la.replace("_", "\n") for la in layers], vals, color=INK)
    ax.axhline(full * 100, color=ON, linestyle="--", label=f"all layers on ({full:.1%})")
    ax.set_ylabel("Attack success rate (%)")
    ax.set_title("Ablation: ASR with one layer removed\n"
                 "(taller bar = that layer carried more of the defense)")
    ax.legend()
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    p = out / "ablation.png"
    fig.savefig(p, dpi=130)
    plt.close(fig)
    return p


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--summary", type=Path, default=Path("results/baseline.summary.json"))
    ap.add_argument("--out", type=Path, default=Path("results"))
    args = ap.parse_args()
    summary = json.loads(args.summary.read_text())
    args.out.mkdir(parents=True, exist_ok=True)
    print("wrote", plot_asr_by_category(summary, args.out))
    print("wrote", plot_ablation(summary, args.out))


if __name__ == "__main__":
    main()
