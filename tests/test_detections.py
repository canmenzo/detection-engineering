"""Detection unit tests.

For each rule with EVTX fixtures:
  - true_positive.evtx  -> rule MUST fire
  - benign.evtx         -> rule MUST stay silent

Fixtures are discovered automatically: tests/fixtures/<rule_stem>/{true_positive,benign}.evtx
"""
from __future__ import annotations

from pathlib import Path

import pytest

from conftest import DETECTIONS, FIXTURES, requires_hayabusa


def _rules_with_fixtures():
    cases = []
    rules = sorted(DETECTIONS.rglob("*.yml")) + sorted(DETECTIONS.rglob("*.yaml"))
    for rule in rules:
        folder = FIXTURES / rule.stem
        tp = folder / "true_positive.evtx"
        benign = folder / "benign.evtx"
        if tp.exists():
            cases.append(pytest.param(rule, tp, True, id=f"{rule.stem}-tp"))
        if benign.exists():
            cases.append(pytest.param(rule, benign, False, id=f"{rule.stem}-benign"))
    return cases


CASES = _rules_with_fixtures()


@requires_hayabusa
@pytest.mark.skipif(not CASES, reason="no EVTX fixtures present yet")
@pytest.mark.parametrize("rule,evtx,should_fire", CASES)
def test_detection(rule_runner, rule: Path, evtx: Path, should_fire: bool):
    detections = rule_runner(rule, evtx)
    fired = len(detections) > 0
    if should_fire:
        assert fired, f"{rule.stem} did NOT fire on true-positive fixture {evtx.name}"
    else:
        assert not fired, (
            f"{rule.stem} fired on benign fixture {evtx.name} "
            f"({len(detections)} detection(s)) — false positive"
        )
