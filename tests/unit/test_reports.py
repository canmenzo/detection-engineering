"""Unit tests for the report generators' transform logic.

These cover the arithmetic behind every number the repo publishes.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from detkit.coverage import scan
from detkit.dashboard import render
from detkit.navigator import build_layer

RULE = """\
title: {title}
tags:
{tags}
detection:
  selection:
    EventID: 1
  condition: selection
"""


def _write(root: Path, name: str, tags: list[str], title: str = "Example") -> None:
    root.mkdir(parents=True, exist_ok=True)
    body = RULE.format(title=title, tags="\n".join(f"  - {t}" for t in tags))
    (root / name).write_text(body, encoding="utf-8")


def test_build_layer_scores_and_pluralises() -> None:
    layer = build_layer(Counter({"T1059.001": 2, "T1027": 1}))
    assert layer["techniques"] == [
        {"techniqueID": "T1027", "score": 1, "comment": "1 detection", "enabled": True},
        {"techniqueID": "T1059.001", "score": 2, "comment": "2 detections", "enabled": True},
    ]
    assert layer["gradient"]["maxValue"] == 2
    assert layer["domain"] == "enterprise-attack"


def test_build_layer_handles_empty_corpus() -> None:
    layer = build_layer(Counter())
    assert layer["techniques"] == []
    assert layer["gradient"]["maxValue"] == 1


def test_scan_counts_rules_pairs_and_techniques(tmp_path: Path) -> None:
    _write(tmp_path, "a.yml", ["attack.execution", "attack.t1059.001"])
    _write(tmp_path, "b.yml", ["attack.stealth", "attack.t1027", "attack.t1059.001"])
    _write(tmp_path, "untagged.yml", ["detection.threat-hunting"])

    result = scan(tmp_path)
    assert result.n_rules == 2  # the untagged rule is not counted
    assert result.counts == Counter({"T1059.001": 2, "T1027": 1})
    assert result.pairs == {
        ("execution", "T1059.001"),
        ("stealth", "T1027"),
        ("stealth", "T1059.001"),
    }


def test_scan_folds_retired_tactic_token(tmp_path: Path) -> None:
    _write(tmp_path, "a.yml", ["attack.defense-evasion", "attack.t1027"])
    assert scan(tmp_path).pairs == {("stealth", "T1027")}


def test_render_reports_counts_and_escapes_titles() -> None:
    rules = [
        {
            "stem": "one", "title": "Rule <script>", "description": "d", "level": "high",
            "tactics": ["Execution"], "techniques": ["T1059.001"], "logsource": "security",
            "status": "tested", "samples": 2, "path": "detections/one.yml",
        },
        {
            "stem": "two", "title": "Second", "description": "d", "level": "low",
            "tactics": ["Execution"], "techniques": ["T1027"], "logsource": "security",
            "status": "conversion-only", "samples": 0, "path": "detections/two.yml",
        },
    ]
    html_out = render(rules, {"total_rules": 2399, "convert": {"rate": 1.0},
                              "techniques": ["T1105"]})

    assert "<b>2</b><span>authored detections</span>" in html_out
    assert "<b>1</b><span>fixture-tested</span>" in html_out
    assert "<b>2</b><span>pinned EVTX samples</span>" in html_out
    assert "<b>2,399</b><span>vendored SigmaHQ rules</span>" in html_out
    assert "<b>100%</b><span>vendored convert rate</span>" in html_out
    # 2 authored techniques + 1 vendored-only
    assert "<b>3</b><span>ATT&amp;CK techniques</span>" in html_out
    # The tactic chip carries its rule count.
    assert 'data-tactic="Execution">Execution <span>2</span>' in html_out


def test_render_without_vendored_report() -> None:
    rules = [
        {
            "stem": "one", "title": "Rule", "description": "d", "level": "high",
            "tactics": [], "techniques": ["T1059.001"], "logsource": "security",
            "status": "untested", "samples": 0, "path": "detections/one.yml",
        },
    ]
    html_out = render(rules, {})
    assert "<b>—</b><span>vendored convert rate</span>" in html_out
    assert "<b>0</b><span>vendored SigmaHQ rules</span>" in html_out
