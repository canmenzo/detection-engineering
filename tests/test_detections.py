"""Detection unit tests.

For each rule with a tests/fixtures/<stem>/sample_sources.yml manifest, every
pinned sample is fetched and scanned:
  - expect: fire   -> rule MUST produce >= 1 hit
  - expect: silent -> rule MUST produce 0 hits
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from conftest import DETECTIONS, FIXTURES, fetch_sample, requires_hayabusa


def _cases():
    cases = []
    rules = sorted(DETECTIONS.rglob("*.yml")) + sorted(DETECTIONS.rglob("*.yaml"))
    by_stem = {r.stem: r for r in rules}
    for manifest in sorted(FIXTURES.glob("*/sample_sources.yml")):
        stem = manifest.parent.name
        rule = by_stem.get(stem)
        if rule is None:
            continue
        doc = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        for sample in doc.get("samples", []):
            cases.append(pytest.param(rule, sample, id=f"{stem}-{sample['name']}"))
    return cases


CASES = _cases()


@requires_hayabusa
@pytest.mark.skipif(not CASES, reason="no fixture manifests present")
@pytest.mark.parametrize("rule,sample", CASES)
def test_detection(hit_counter, rule: Path, sample: dict):
    evtx = fetch_sample(sample)
    hits = hit_counter(rule, evtx)
    if sample["expect"] == "fire":
        assert hits > 0, f"{rule.stem} did NOT fire on TP sample {sample['name']}"
    elif sample["expect"] == "silent":
        assert hits == 0, (
            f"{rule.stem} fired on negative sample {sample['name']} "
            f"({hits} hit(s)) — false positive"
        )
    else:
        pytest.fail(f"unknown expect value: {sample['expect']!r}")
