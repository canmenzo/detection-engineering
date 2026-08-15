"""Unit tests for the README number injection."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from detkit import readme as readme_mod
from detkit.readme import END, START, ReadmeError, build_table, run

RESULTS = {
    "rules": {
        "rule_clean": {
            "tp": 4, "fp": 0, "fn": 0, "tn": 4,
            "precision": 1.0, "recall": 1.0, "fp_rate": 0.0,
            "missed": [], "false_alarms": [],
            "thresholds": {"min_precision": 0.9, "min_recall": 1.0, "max_fp_rate": 0.1},
        },
        "rule_noisy": {
            "tp": 3, "fp": 4, "fn": 0, "tn": 0,
            "precision": 0.43, "recall": 1.0, "fp_rate": 1.0,
            "missed": [], "false_alarms": [],
            "thresholds": {"min_precision": 0.4, "min_recall": 1.0, "max_fp_rate": 1.0},
        },
    }
}


@pytest.fixture
def staged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    results = tmp_path / "results.json"
    results.write_text(json.dumps(RESULTS), encoding="utf-8")
    monkeypatch.setattr(readme_mod, "EVAL_RESULTS", results)
    monkeypatch.setattr(readme_mod, "load_corpus", lambda _root: [])
    monkeypatch.setattr(readme_mod, "REPO", tmp_path)
    return tmp_path


def test_table_is_sorted_by_fp_rate(staged: Path) -> None:
    table = build_table()
    assert table.index("rule_clean") < table.index("rule_noisy")


def test_table_reports_counts_and_flags_total_noise(staged: Path) -> None:
    table = build_table()
    assert "2 rules, 15 labelled events" in table
    # A rule that alerts on everything is emphasised, not buried.
    assert "**1.00**" in table
    assert "p≥0.40" in table


def test_run_replaces_only_the_marked_block(
    staged: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = staged / "README.md"
    target.write_text(
        f"# Title\n\nkeep me above\n\n{START}\nstale content\n{END}\n\nkeep me below\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(readme_mod, "README", target)

    assert run() == 0
    text = target.read_text(encoding="utf-8")
    assert "keep me above" in text
    assert "keep me below" in text
    assert "stale content" not in text
    assert "rule_noisy" in text


def test_run_requires_the_markers(staged: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = staged / "README.md"
    target.write_text("# Title\n\nno markers here\n", encoding="utf-8")
    monkeypatch.setattr(readme_mod, "README", target)
    with pytest.raises(ReadmeError, match="missing the"):
        run()


def test_missing_results_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(readme_mod, "EVAL_RESULTS", tmp_path / "absent.json")
    with pytest.raises(ReadmeError, match="run `detkit eval` first"):
        build_table()
