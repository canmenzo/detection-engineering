"""Render an ATT&CK-style coverage matrix PNG from the two-tier corpus.

Self-contained: reads detections/ (authored, fixture-tested) and vendored/
(SigmaHQ corpus, convert + coverage only), groups each technique under the
tactic(s) it is tagged with, and draws a Navigator-style dot grid. Authored
techniques are green (the showcase); vendored-only techniques are shaded blue by
how many rules reference them.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.patches as mpatches
import matplotlib.pyplot as plt

from detkit.attack import TACTICS
from detkit.paths import COVERAGE_PNG, DETECTIONS, REPO, VENDORED
from detkit.rules import load_corpus

CELLS_PER_ROW = 6
AUTHORED_COLOUR = "#2ea043"


@dataclass(frozen=True)
class Scan:
    counts: Counter[str]
    pairs: set[tuple[str, str]]
    n_rules: int


def scan(root: Path) -> Scan:
    """Technique counts, (tactic, technique) pairs, and tagged-rule count."""
    counts: Counter[str] = Counter()
    pairs: set[tuple[str, str]] = set()
    n_rules = 0
    for rule in load_corpus(root):
        if rule.techniques:
            n_rules += 1
        for technique in rule.techniques:
            counts[technique] += 1
            for tactic in rule.tactics:
                pairs.add((tactic, technique))
    return Scan(counts, pairs, n_rules)


def run() -> int:
    authored_scan = scan(DETECTIONS)
    vendored_scan = scan(VENDORED)

    by_tactic: dict[str, set[str]] = defaultdict(set)
    for tactic, technique in authored_scan.pairs | vendored_scan.pairs:
        by_tactic[tactic].add(technique)
    authored = {technique for _, technique in authored_scan.pairs}

    columns = [t for t in TACTICS if by_tactic.get(t.shortname)]
    if not columns:
        print("no tagged techniques found")
        return 1

    max_vendored = max(vendored_scan.counts.values(), default=1)
    blues = plt.get_cmap("Blues")

    n_cols = len(columns)
    max_rows = max(-(-len(by_tactic[t.shortname]) // CELLS_PER_ROW) for t in columns)
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

    n_authored_techniques = len(authored)
    n_total_techniques = len({t for s in by_tactic.values() for t in s})
    n_vendored_only = n_total_techniques - n_authored_techniques

    # The headline is the authored corpus. The vendored tier is real work — 2,399
    # rules run through conversion at scale — but it is other people's detection
    # content, and leading with the combined number invites the reader to credit
    # it here. It gets its own line, clearly labelled.
    ax.text(0, y0 + 1.55,
            f"Detection Coverage — {n_authored_techniques} ATT&CK techniques authored "
            f"and fixture-tested",
            fontsize=16, fontweight="bold", va="bottom")
    ax.text(0, y0 + 1.2,
            f"{authored_scan.n_rules} authored rules, each scored against labelled "
            f"events for precision, recall and false-positive rate",
            fontsize=10, color="#444", va="bottom")
    ax.text(0, y0 + 0.92,
            f"Shaded cells: {n_vendored_only} further techniques covered only by the "
            f"vendored SigmaHQ corpus ({vendored_scan.n_rules} third-party rules, "
            f"not authored here and not fixture-tested)",
            fontsize=8.5, color="#8a8a8a", va="bottom")

    for ci, column in enumerate(columns):
        techniques = by_tactic[column.shortname]
        n_authored_here = len(techniques & authored)
        ax.text(ci + 0.5, y0 + 0.42, column.matrix_label, fontsize=7.5, fontweight="bold",
                ha="center", va="bottom", linespacing=0.95)
        ax.text(ci + 0.5, y0 + 0.22, f"{n_authored_here}/{len(techniques)}", fontsize=7.5,
                color="#888", ha="center", va="bottom")
        ax.add_patch(mpatches.Rectangle((ci + 0.02, y0 + 0.1), col_w - 0.02, 0.06,
                                        color="#31507a"))
        # authored first (so the showcase sits at the top of each column)
        ordered = sorted(techniques & authored) + sorted(techniques - authored)
        sub_w = (col_w - 0.02) / CELLS_PER_ROW
        for idx, technique in enumerate(ordered):
            row, col = divmod(idx, CELLS_PER_ROW)
            x = ci + 0.02 + col * sub_w
            y = y0 - (row + 1) * (cell + gap)
            face: str | tuple[float, float, float, float]
            if technique in authored:
                face, edge = AUTHORED_COLOUR, "#1a6e2e"
            else:
                shade = 0.30 + 0.55 * (vendored_scan.counts[technique] / max_vendored)
                face, edge = blues(shade), "white"
            ax.add_patch(mpatches.Rectangle((x, y), sub_w - 0.012, cell,
                                            facecolor=face, edgecolor=edge, linewidth=0.4))

    legend = [
        mpatches.Patch(facecolor=AUTHORED_COLOUR, edgecolor="#1a6e2e",
                       label="Authored here — ATT&CK-mapped, fixture-tested, eval-scored"),
        mpatches.Patch(facecolor=blues(0.65), edgecolor="white",
                       label="Vendored SigmaHQ — third-party, convert-tested only"),
    ]
    ax.legend(handles=legend, loc="lower left", bbox_to_anchor=(0, -0.04),
              frameon=False, fontsize=8.5, ncol=2, handlelength=1.2)

    COVERAGE_PNG.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(COVERAGE_PNG, dpi=140, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"Wrote {COVERAGE_PNG.relative_to(REPO)} — {n_total_techniques} techniques "
          f"({n_authored_techniques} authored + {n_vendored_only} vendored) "
          f"across {n_cols} tactics.")
    return 0
