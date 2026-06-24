#!/usr/bin/env python3
"""Render an ATT&CK-style coverage matrix PNG from the two-tier corpus.

Self-contained: reads detections/ (authored, fixture-tested) and vendored/
(SigmaHQ corpus, convert+coverage only), groups each technique under the
tactic(s) it is tagged with, and draws a Navigator-style dot grid. Authored
techniques are highlighted in green (the showcase); vendored-only techniques are
shaded blue by how many rules reference them. Writes coverage/coverage.png.

Run: python tools/generate_coverage_png.py
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import yaml

REPO = Path(__file__).resolve().parents[1]
DETECTIONS = REPO / "detections"
VENDORED = REPO / "vendored"
OUT = REPO / "coverage" / "coverage.png"

TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
TACTIC_RE = re.compile(r"^attack\.([a-z_-]+)$", re.IGNORECASE)

# SigmaHQ tags tactics with hyphens and two non-ATT&CK tokens that both fall
# under Defense Evasion (TA0005): "stealth" (general evasion) and
# "defense-impairment" (T1562 Impair Defenses).
TACTIC_ALIASES = {"stealth": "defense_evasion", "defense_impairment": "defense_evasion"}

# ATT&CK enterprise tactics in kill-chain order.
TACTIC_ORDER = [
    ("reconnaissance", "Recon"),
    ("resource_development", "Resource\nDev"),
    ("initial_access", "Initial\nAccess"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege_escalation", "Priv\nEsc"),
    ("defense_evasion", "Defense\nEvasion"),
    ("credential_access", "Cred\nAccess"),
    ("discovery", "Discovery"),
    ("lateral_movement", "Lateral\nMovement"),
    ("collection", "Collection"),
    ("command_and_control", "C2"),
    ("exfiltration", "Exfil"),
    ("impact", "Impact"),
]

CELLS_PER_ROW = 6


def norm_tactic(token: str) -> str:
    token = token.lower().replace("-", "_")
    return TACTIC_ALIASES.get(token, token)


def scan(root: Path):
    """Return (tech->rule_count, (tactic, tech) pairs, n_rules) for a corpus."""
    counts: Counter = Counter()
    pairs: set[tuple[str, str]] = set()
    n_rules = 0
    for rule in list(root.rglob("*.yml")) + list(root.rglob("*.yaml")):
        try:
            doc = yaml.safe_load(rule.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        techs, tactics = [], []
        for tag in doc.get("tags") or []:
            if not isinstance(tag, str):
                continue
            tag = tag.strip()
            mt = TECHNIQUE_RE.match(tag)
            if mt:
                techs.append(mt.group(1).upper())
                continue
            ma = TACTIC_RE.match(tag)
            if ma:
                tactics.append(norm_tactic(ma.group(1)))
        if techs:
            n_rules += 1
        for t in techs:
            counts[t] += 1
            for tac in tactics:
                pairs.add((tac, t))
    return counts, pairs, n_rules


def main() -> int:
    a_counts, a_pairs, n_auth_rules = scan(DETECTIONS)
    v_counts, v_pairs, n_vend_rules = scan(VENDORED)

    by_tactic: dict[str, set[str]] = defaultdict(set)
    for tac, tech in a_pairs | v_pairs:
        by_tactic[tac].add(tech)
    authored = {tech for _, tech in a_pairs}

    columns = [(k, name) for k, name in TACTIC_ORDER if by_tactic.get(k)]
    if not columns:
        print("no tagged techniques found")
        return 1

    max_v = max(v_counts.values(), default=1)
    blues = plt.get_cmap("Blues")
    AUTH = "#2ea043"  # green — authored + fixture-tested

    n_cols = len(columns)
    max_rows = max(-(-len(by_tactic[k]) // CELLS_PER_ROW) for k, _ in columns)
    cell, gap = 0.12, 0.02
    col_w = 1.0
    top = 2.2  # header band
    fig_w = n_cols * col_w + 0.4
    fig_h = max_rows * (cell + gap) + top + 1.0
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    ax.set_xlim(0, n_cols)
    ax.set_ylim(0, max_rows * (cell + gap) + top)
    ax.axis("off")
    y0 = max_rows * (cell + gap)

    n_auth_t = len(authored)
    n_total_t = len({t for s in by_tactic.values() for t in s})
    n_vend_only = n_total_t - n_auth_t

    ax.text(0, y0 + 1.55, "Detection Coverage — MITRE ATT&CK",
            fontsize=17, fontweight="bold", va="bottom")
    ax.text(0, y0 + 1.2,
            f"{n_total_t} techniques across {n_cols} tactics  "
            f"·  {n_auth_t} authored (fixture-tested) + {n_vend_only} vendored",
            fontsize=10, color="#444", va="bottom")
    ax.text(0, y0 + 0.92,
            f"{n_auth_rules} authored rules  ·  {n_vend_rules} vendored SigmaHQ rules",
            fontsize=9, color="#777", va="bottom")

    for ci, (key, name) in enumerate(columns):
        techs = by_tactic[key]
        n_a = len(techs & authored)
        ax.text(ci + 0.5, y0 + 0.42, name, fontsize=7.5, fontweight="bold",
                ha="center", va="bottom", linespacing=0.95)
        ax.text(ci + 0.5, y0 + 0.22, f"{n_a}/{len(techs)}", fontsize=7.5,
                color="#888", ha="center", va="bottom")
        ax.add_patch(plt.Rectangle((ci + 0.02, y0 + 0.1), col_w - 0.02, 0.06,
                                   color="#31507a"))
        # authored first (so the showcase sits at the top of each column)
        ordered = sorted(techs & authored) + sorted(techs - authored)
        sub_w = (col_w - 0.02) / CELLS_PER_ROW
        for idx, tech in enumerate(ordered):
            row, col = divmod(idx, CELLS_PER_ROW)
            x = ci + 0.02 + col * sub_w
            y = y0 - (row + 1) * (cell + gap)
            if tech in authored:
                face, edge = AUTH, "#1a6e2e"
            else:
                shade = 0.30 + 0.55 * (v_counts[tech] / max_v)
                face, edge = blues(shade), "white"
            ax.add_patch(plt.Rectangle((x, y), sub_w - 0.012, cell,
                                       facecolor=face, edgecolor=edge, linewidth=0.4))

    legend = [
        mpatches.Patch(facecolor=AUTH, edgecolor="#1a6e2e",
                       label="Authored — ATT&CK-mapped + fixture-tested"),
        mpatches.Patch(facecolor=blues(0.65), edgecolor="white",
                       label="Vendored — SigmaHQ corpus (shade = # rules)"),
    ]
    ax.legend(handles=legend, loc="lower left", bbox_to_anchor=(0, -0.04),
              frameon=False, fontsize=8.5, ncol=2, handlelength=1.2)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, dpi=140, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"Wrote {OUT.relative_to(REPO)} — {n_total_t} techniques "
          f"({n_auth_t} authored + {n_vend_only} vendored) across {n_cols} tactics.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
