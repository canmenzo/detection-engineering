#!/usr/bin/env python3
"""Render an ATT&CK-style coverage matrix PNG from the detection corpus.

Self-contained: reads detections/, groups each technique under the tactic(s) it
is tagged with, colours each cell by how many detections reference it, and writes
coverage/coverage.png. No external ATT&CK Navigator site required.

Run: python tools/generate_coverage_png.py
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import yaml

REPO = Path(__file__).resolve().parents[1]
DETECTIONS = REPO / "detections"
OUT = REPO / "coverage" / "coverage.png"

TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
TACTIC_RE = re.compile(r"^attack\.([a-z_]+)$", re.IGNORECASE)

# ATT&CK enterprise tactics in kill-chain order (subset we tag).
TACTIC_ORDER = [
    ("reconnaissance", "Reconnaissance"),
    ("resource_development", "Resource Development"),
    ("initial_access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege_escalation", "Privilege Escalation"),
    ("defense_evasion", "Defense Evasion"),
    ("credential_access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral_movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command_and_control", "Command & Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]

# Short labels for the techniques we cover (extend as the corpus grows).
TECH_NAMES = {
    "T1003.001": "LSASS Memory",
    "T1003.006": "DCSync",
    "T1027": "Obfuscated Files",
    "T1053.005": "Scheduled Task",
    "T1059.001": "PowerShell",
    "T1070.001": "Clear Event Logs",
    "T1098": "Account Manipulation",
    "T1105": "Ingress Tool Transfer",
    "T1136.001": "Create Local Account",
    "T1140": "Deobfuscate/Decode",
    "T1543.003": "Windows Service",
    "T1558.003": "Kerberoasting",
    "T1562.001": "Disable/Modify Tools",
    "T1562.004": "Disable Firewall",
}


def collect():
    """Return (counts per technique, set of (tactic, technique) pairs)."""
    counts: Counter = Counter()
    pairs: set[tuple[str, str]] = set()
    for rule in sorted(DETECTIONS.rglob("*.yml")) + sorted(DETECTIONS.rglob("*.yaml")):
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
                tactics.append(ma.group(1).lower())
        for t in techs:
            counts[t] += 1
            for tac in tactics:
                pairs.add((tac, t))
    return counts, pairs


def main() -> int:
    counts, pairs = collect()
    by_tactic: dict[str, list[str]] = defaultdict(list)
    for tac, tech in pairs:
        by_tactic[tac].append(tech)

    columns = [(key, name) for key, name in TACTIC_ORDER if by_tactic.get(key)]
    if not columns:
        print("no tagged techniques found")
        return 1

    max_count = max(counts.values(), default=1)
    cmap = plt.get_cmap("Blues")

    n_cols = len(columns)
    max_rows = max(len(by_tactic[k]) for k, _ in columns)
    cell_w, cell_h = 2.2, 0.62
    fig_w = n_cols * cell_w + 0.5
    fig_h = (max_rows + 2) * cell_h + 1.0
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    ax.set_xlim(0, n_cols)
    ax.set_ylim(0, max_rows + 1.4)
    ax.axis("off")

    n_tech = len(counts)
    n_det = sum(counts.values())
    ax.text(0, max_rows + 1.05, "Detection Coverage — MITRE ATT&CK",
            fontsize=15, fontweight="bold", va="bottom")
    ax.text(0, max_rows + 0.7,
            f"{n_det} detections · {n_tech} techniques · {n_cols} tactics",
            fontsize=9, color="#555", va="bottom")

    for ci, (key, name) in enumerate(columns):
        ax.text(ci + 0.5, max_rows + 0.25, name, fontsize=9, fontweight="bold",
                ha="center", va="bottom", wrap=True)
        ax.add_patch(plt.Rectangle((ci + 0.03, max_rows + 0.1), 0.94, 0.1,
                                   color="#31507a"))
        for ri, tech in enumerate(sorted(by_tactic[key])):
            y = max_rows - 1 - ri
            n = counts[tech]
            shade = 0.25 + 0.6 * (n / max_count)
            face = cmap(shade)
            ax.add_patch(plt.Rectangle((ci + 0.03, y + 0.08), 0.94, 0.82,
                                       facecolor=face, edgecolor="white"))
            label = TECH_NAMES.get(tech, tech)
            txt_color = "white" if shade > 0.55 else "#11243d"
            ax.text(ci + 0.08, y + 0.6, tech, fontsize=7.5, color=txt_color,
                    fontweight="bold", va="center")
            ax.text(ci + 0.08, y + 0.3, label, fontsize=6.8, color=txt_color,
                    va="center")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"Wrote {OUT.relative_to(REPO)} — {n_tech} techniques across {n_cols} tactics.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
