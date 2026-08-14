"""Unit tests for corpus loading."""
from __future__ import annotations

from pathlib import Path

import pytest

from detkit import rules as rules_mod
from detkit.rules import RuleError, conversion_only, load_rule, rule_paths, sample_count

VALID_RULE = """\
title: Example
id: 00000000-0000-0000-0000-000000000000
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
detection:
  selection:
    EventID: 4688
  condition: selection
level: high
"""


def test_load_rule_extracts_tags(tmp_path: Path) -> None:
    path = tmp_path / "example.yml"
    path.write_text(VALID_RULE, encoding="utf-8")
    rule = load_rule(path)
    assert rule.stem == "example"
    assert rule.techniques == ("T1059.001",)
    assert rule.tactics == ("execution",)
    assert rule.doc["level"] == "high"


def test_malformed_yaml_raises(tmp_path: Path) -> None:
    """Generators used to swallow this and drop the rule from every report."""
    path = tmp_path / "broken.yml"
    path.write_text("title: [unclosed\n", encoding="utf-8")
    with pytest.raises(RuleError, match="unparseable YAML"):
        load_rule(path)


def test_non_mapping_raises(tmp_path: Path) -> None:
    path = tmp_path / "list.yml"
    path.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(RuleError, match="not a YAML mapping"):
        load_rule(path)


def test_rule_paths_are_sorted_yml_then_yaml(tmp_path: Path) -> None:
    for name in ("b.yml", "a.yml", "c.yaml"):
        (tmp_path / name).write_text(VALID_RULE, encoding="utf-8")
    assert [p.name for p in rule_paths(tmp_path)] == ["a.yml", "b.yml", "c.yaml"]


def test_conversion_only_strips_comments_and_blanks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    listing = tmp_path / "conversion_only.txt"
    listing.write_text(
        "# a leading comment\n\n  rule_one  \nrule_two  # why it is exempt\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(rules_mod, "CONVERSION_ONLY", listing)
    assert conversion_only() == {"rule_one", "rule_two"}


def test_conversion_only_missing_file_is_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rules_mod, "CONVERSION_ONLY", tmp_path / "nope.txt")
    assert conversion_only() == set()


@pytest.mark.parametrize(
    "manifest,expected",
    [
        ("samples:\n  - name: a\n  - name: b\n", 2),
        ("samples: []\n", 0),
        ("{}\n", 0),
    ],
)
def test_sample_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, manifest: str, expected: int
) -> None:
    fixture_dir = tmp_path / "some_rule"
    fixture_dir.mkdir()
    (fixture_dir / "sample_sources.yml").write_text(manifest, encoding="utf-8")
    monkeypatch.setattr(rules_mod, "FIXTURES", tmp_path)
    assert sample_count("some_rule") == expected


def test_sample_count_missing_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rules_mod, "FIXTURES", tmp_path)
    assert sample_count("absent") == 0
