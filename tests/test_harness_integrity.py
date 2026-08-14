"""Tests for the test harness itself.

The detection suite's central claim is "every rule is verified". Nothing used to
assert that the suite actually ran: with the Hayabusa binary missing every case
skipped and pytest still exited 0, and if fixture discovery ever returned nothing
the parametrised suite collapsed to zero cases — also green.

These tests need no Hayabusa. They fail when the wiring is wrong.
"""
from __future__ import annotations

import yaml

from conftest import DETECTIONS, FIXTURES, REPO
from test_detections import CASES

CONVERSION_ONLY = REPO / "tests" / "conversion_only.txt"


def _rule_stems() -> set[str]:
    rules = list(DETECTIONS.rglob("*.yml")) + list(DETECTIONS.rglob("*.yaml"))
    return {r.stem for r in rules}


def _conversion_only() -> set[str]:
    if not CONVERSION_ONLY.exists():
        return set()
    return {
        stripped
        for line in CONVERSION_ONLY.read_text(encoding="utf-8").splitlines()
        if (stripped := line.split("#", 1)[0].strip())
    }


def _declared_samples() -> dict[str, int]:
    counts = {}
    for manifest in FIXTURES.glob("*/sample_sources.yml"):
        doc = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
        counts[manifest.parent.name] = len(doc.get("samples") or [])
    return counts


def test_rules_exist():
    assert _rule_stems(), "no detection rules found under detections/"


def test_collected_cases_match_declared_samples():
    """Discovery must produce exactly the cases the manifests declare."""
    declared = _declared_samples()
    expected = sum(n for stem, n in declared.items() if stem in _rule_stems())
    assert expected > 0, "fixture manifests declare zero samples"
    assert len(CASES) == expected, (
        f"collected {len(CASES)} test case(s) but manifests declare {expected} — "
        "fixture discovery is dropping cases"
    )


def test_every_rule_is_tested_or_declared_exempt():
    """No rule may be silently untested."""
    tested = {stem for stem, n in _declared_samples().items() if n > 0}
    untested = _rule_stems() - tested - _conversion_only()
    assert not untested, (
        f"rule(s) with no fixture and no conversion-only declaration: {sorted(untested)}"
    )


def test_no_orphan_fixture_manifests():
    """A manifest whose rule was renamed or deleted silently stops running."""
    orphans = set(_declared_samples()) - _rule_stems()
    assert not orphans, f"fixture manifest(s) with no matching rule: {sorted(orphans)}"


def test_conversion_only_entries_reference_real_rules():
    stale = _conversion_only() - _rule_stems()
    assert not stale, f"conversion_only.txt lists non-existent rule(s): {sorted(stale)}"
