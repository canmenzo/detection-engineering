"""Generate an ATT&CK Navigator layer from the authored corpus.

Scores each covered technique by the number of detections referencing it.
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Any

from detkit.paths import ATTACK_VERSION_FILE, DETECTIONS, NAVIGATOR_LAYER, REPO
from detkit.rules import load_corpus


def technique_counts() -> Counter[str]:
    counts: Counter[str] = Counter()
    for rule in load_corpus(DETECTIONS):
        for technique in rule.techniques:
            counts[technique] += 1
    return counts


def build_layer(counts: Counter[str]) -> dict[str, Any]:
    max_score = max(counts.values(), default=1)
    techniques = [
        {
            "techniqueID": tid,
            "score": n,
            "comment": f"{n} detection{'s' if n != 1 else ''}",
            "enabled": True,
        }
        for tid, n in sorted(counts.items())
    ]
    return {
        "name": "Detection Coverage",
        "description": "Auto-generated from detections/ — do not edit by hand.",
        # ATT&CK release comes from the repo pin, not a hardcoded number that
        # goes stale silently. The metadata gate fails if the pin drifts.
        "versions": {
            "navigator": "4.9.1",
            "layer": "4.5",
            "attack": ATTACK_VERSION_FILE.read_text(encoding="utf-8").strip().split(".")[0],
        },
        "domain": "enterprise-attack",
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66b1ff", "#0b5cad"],
            "minValue": 0,
            "maxValue": max_score,
        },
        "legendItems": [],
    }


def run() -> int:
    counts = technique_counts()
    layer = build_layer(counts)
    NAVIGATOR_LAYER.parent.mkdir(parents=True, exist_ok=True)
    NAVIGATOR_LAYER.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {NAVIGATOR_LAYER.relative_to(REPO)} — {len(counts)} technique(s) covered.")
    for tid, n in sorted(counts.items()):
        print(f"  {tid}: {n}")
    return 0
