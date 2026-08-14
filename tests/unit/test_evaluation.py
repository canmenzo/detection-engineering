"""Unit tests for the evaluation harness.

Covers the three semantics ADR 0003 pinned down, the metric arithmetic, and the
case-file rules that stop the golden dataset from flattering the detections.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from detkit.evaluation.cases import CaseError, load_case_set
from detkit.evaluation.engine import matching_indices, normalise
from detkit.evaluation.metrics import score

QUERY = "SELECT * FROM <TABLE_NAME> WHERE EventID=4688 AND CommandLine LIKE '%certutil%'"


def test_matches_expected_events() -> None:
    events = [
        {"EventID": 4688, "CommandLine": "certutil -urlcache"},
        {"EventID": 4688, "CommandLine": "whoami"},
        {"EventID": 4624, "CommandLine": "certutil -decode"},
    ]
    assert matching_indices(QUERY, {"EventID", "CommandLine"}, events) == {0}


def test_absent_field_does_not_raise() -> None:
    """A field the data never carries must simply not match."""
    events = [{"EventID": 4688}]
    query = "SELECT * FROM <TABLE_NAME> WHERE ScriptBlockText LIKE '%evil%'"
    assert matching_indices(query, {"ScriptBlockText"}, events) == set()


def test_numeric_strings_are_coerced() -> None:
    """EVTX gives "0"; the rule says 0. Without coercion AS-REP stops matching."""
    events = [{"EventID": 4768, "PreAuthType": "0"}]
    query = "SELECT * FROM <TABLE_NAME> WHERE EventID=4768 AND PreAuthType=0"
    assert matching_indices(query, {"EventID", "PreAuthType"}, events) == {0}


def test_hex_strings_are_not_coerced() -> None:
    """0x17 must stay a string or the encryption-type comparisons break."""
    assert normalise("0x17") == "0x17"
    assert normalise("0") == 0
    assert normalise("-12") == -12
    assert normalise("admin ") == "admin "


def test_uint64_keyword_mask_does_not_overflow() -> None:
    events = [{"EventID": 1, "Keywords": 9223372036854775808}]
    query = "SELECT * FROM <TABLE_NAME> WHERE EventID=1"
    assert matching_indices(query, {"EventID"}, events) == {0}


def test_empty_event_list() -> None:
    assert matching_indices(QUERY, {"EventID"}, []) == set()


def test_score_counts_and_names() -> None:
    labels = [True, True, False, False]
    metrics = score(labels, {0, 2}, ["tp1", "missed1", "fp1", "tn1"])
    assert (metrics.tp, metrics.fp, metrics.fn, metrics.tn) == (1, 1, 1, 1)
    assert metrics.missed == ("missed1",)
    assert metrics.false_alarms == ("fp1",)
    assert metrics.precision == 0.5
    assert metrics.recall == 0.5
    assert metrics.fp_rate == 0.5


def test_score_precision_is_none_when_rule_never_fires() -> None:
    metrics = score([True, False], set(), ["a", "b"])
    assert metrics.precision is None
    assert metrics.recall == 0.0
    assert metrics.fp_rate == 0.0


def _write(tmp_path: Path, body: str) -> Path:
    directory = tmp_path / "some_rule"
    directory.mkdir(exist_ok=True)
    path = directory / "cases.yml"
    path.write_text(body, encoding="utf-8")
    return path


GOOD = """\
description: test
cases:
  - name: bad
    label: malicious
    why: because
    event: {EventID: 4688, CommandLine: evil}
  - name: good
    label: benign
    why: because
    event: {EventID: 4688, CommandLine: fine}
"""


def test_loads_a_valid_case_set(tmp_path: Path) -> None:
    case_set = load_case_set(_write(tmp_path, GOOD))
    assert len(case_set.malicious) == 1
    assert len(case_set.benign) == 1
    assert case_set.events[0]["CommandLine"] == "evil"


def test_rejects_case_set_without_benign_cases(tmp_path: Path) -> None:
    body = GOOD.replace("    label: benign\n", "    label: malicious\n")
    with pytest.raises(CaseError, match="no benign cases"):
        load_case_set(_write(tmp_path, body))


def test_rejects_case_set_without_malicious_cases(tmp_path: Path) -> None:
    body = GOOD.replace("    label: malicious\n", "    label: benign\n")
    with pytest.raises(CaseError, match="no malicious cases"):
        load_case_set(_write(tmp_path, body))


def test_rejects_benign_case_of_a_different_event_type(tmp_path: Path) -> None:
    """The old fixture set's only negative was a different channel entirely."""
    body = GOOD.replace("  - name: good\n    label: benign\n    why: because\n"
                        "    event: {EventID: 4688, CommandLine: fine}\n",
                        "  - name: good\n    label: benign\n    why: because\n"
                        "    event: {EventID: 4104, ScriptBlockText: fine}\n")
    with pytest.raises(CaseError, match="cannot exercise the rule's logic"):
        load_case_set(_write(tmp_path, body))


def test_rejects_unexplained_label(tmp_path: Path) -> None:
    body = GOOD.replace("    why: because\n", "", 1)
    with pytest.raises(CaseError, match="needs a 'why'"):
        load_case_set(_write(tmp_path, body))


def test_rejects_duplicate_case_names(tmp_path: Path) -> None:
    body = GOOD.replace("  - name: good\n", "  - name: bad\n")
    with pytest.raises(CaseError, match="duplicate case name"):
        load_case_set(_write(tmp_path, body))


def test_rejects_unknown_label(tmp_path: Path) -> None:
    body = GOOD.replace("label: benign", "label: suspicious")
    with pytest.raises(CaseError, match="expected one of"):
        load_case_set(_write(tmp_path, body))
