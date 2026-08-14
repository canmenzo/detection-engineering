"""Detection tests.

For each rule with a tests/fixtures/<stem>/sample_sources.yml manifest, every
pinned sample is fetched and scanned:
  - expect: fire   -> rule MUST produce >= 1 hit
  - expect: silent -> rule MUST produce 0 hits
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from detkit.paths import DETECTIONS, FIXTURES
from detkit.rules import rule_paths
from harness import fetch_sample, requires_hayabusa


def _cases() -> list[Any]:
    cases = []
    by_stem = {path.stem: path for path in rule_paths(DETECTIONS)}
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
def test_detection(
    hit_counter: Callable[[Path, Path], int], rule: Path, sample: dict[str, Any]
) -> None:
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
