"""The Sigma |re modifier compiles to SQL REGEXP, which SQLite does not ship."""
from __future__ import annotations

from detkit.evaluation.engine import matching_indices

QUERY = "SELECT * FROM <TABLE_NAME> WHERE CommandLine REGEXP '\\s-e[a-z]*\\s+[A-Za-z0-9+/=]{15,}'"
FIELDS = {"CommandLine"}


def test_regexp_operator_is_available() -> None:
    """Without a registered REGEXP, this raises instead of matching."""
    events = [{"CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAA=="}]
    assert matching_indices(QUERY, FIELDS, events) == {0}


def test_regex_accepts_every_encodedcommand_abbreviation() -> None:
    events = [
        {"CommandLine": "powershell.exe -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAA=="},
        {"CommandLine": "powershell.exe -ec SQBFAFgAIAAoAE4AZQB3AC0ATwBiAA=="},
        {"CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAA=="},
        {"CommandLine": "powershell.exe -encodedcommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAA=="},
    ]
    assert matching_indices(QUERY, FIELDS, events) == {0, 1, 2, 3}


def test_short_argument_does_not_match() -> None:
    """The base64-length requirement is what keeps -Encoding UTF8 out."""
    events = [
        {"CommandLine": 'powershell.exe -Command "Get-Content log.txt -Encoding UTF8"'},
        {"CommandLine": "powershell.exe -ExecutionPolicy Bypass -File C:\\x.ps1"},
    ]
    assert matching_indices(QUERY, FIELDS, events) == set()


def test_regexp_on_a_missing_field_is_false_not_an_error() -> None:
    assert matching_indices(QUERY, FIELDS, [{"EventID": 1}]) == set()
