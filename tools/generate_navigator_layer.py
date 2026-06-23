#!/usr/bin/env python3
"""Generate an ATT&CK Navigator layer from the detection corpus.

Walks detections/, collects every attack.tXXXX[.XXX] technique tag, scores each
covered technique by the number of detections that reference it, and writes a
Navigator-compatible JSON layer to coverage/navigator_layer.json.

Run: python tools/generate_navigator_layer.py
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
DETECTIONS = REPO / "detections"
OUT = REPO / "coverage" / "navigator_layer.json"

TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def collect() -> Counter:
    counts: Counter = Counter()
    for rule in sorted(DETECTIONS.rglob("*.yml")) + sorted(DETECTIONS.rglob("*.yaml")):
        try:
            doc = yaml.safe_load(rule.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        for tag in doc.get("tags") or []:
            if not isinstance(tag, str):
                continue
            m = TECHNIQUE_RE.match(tag.strip())
            if m:
                counts[m.group(1).upper()] += 1
    return counts


def build_layer(counts: Counter) -> dict:
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
        "versions": {"navigator": "4.9.1", "layer": "4.5", "attack": "16"},
        "domain": "enterprise-attack",
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66b1ff", "#0b5cad"],
            "minValue": 0,
            "maxValue": max_score,
        },
        "legendItems": [],
    }


def main() -> int:
    counts = collect()
    layer = build_layer(counts)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OUT.relative_to(REPO)} — {len(counts)} technique(s) covered.")
    for tid, n in sorted(counts.items()):
        print(f"  {tid}: {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
