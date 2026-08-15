"""Inspect a rule against its pinned EVTX samples.

This is the loop every discriminator in this repo was written against: parse the
real sample, see which events the rule matches, and read the fields of the ones
it does not. Writing a rule against imagined telemetry is how you end up with a
rule that passes your own tests and misses the actual attack.

    detkit probe security_win_service_installed
    detkit probe security_win_service_installed --show ServiceFileName
"""
from __future__ import annotations

from typing import Any

from detkit.evaluation.engine import compile_rule, matching_indices
from detkit.paths import DETECTIONS
from detkit.rules import rule_paths
from detkit.samples import SampleError, event_id_counts, fetch, manifest, read_events

# Fields worth showing by default when a rule matches, across the log sources in
# this corpus.
INTERESTING = (
    "EventID", "Channel", "Computer",
    "Image", "OriginalFileName", "CommandLine", "ParentImage", "ParentCommandLine",
    "NewProcessName", "ParentProcessName",
    "ServiceName", "ServiceFileName", "TaskName",
    "TargetImage", "GrantedAccess", "SourceImage",
    "ScriptBlockText",
    "TargetUserName", "SubjectUserName", "TargetSid", "Properties",
    "TicketEncryptionType", "PreAuthType", "Status", "ServiceName",
)


def _summarise(event: dict[str, Any], fields: tuple[str, ...], width: int) -> list[str]:
    lines = []
    for field in fields:
        value = event.get(field)
        if value in (None, ""):
            continue
        text = str(value).replace("\r", " ").replace("\n", " ")
        if len(text) > width:
            text = text[: width - 1] + "…"
        lines.append(f"      {field}: {text}")
    return lines


def run(stem: str, show: tuple[str, ...] = (), limit: int = 3, width: int = 160) -> int:
    rules = {path.stem: path for path in rule_paths(DETECTIONS)}
    if stem not in rules:
        print(f"no rule named {stem!r}. Known rules:")
        for name in sorted(rules):
            print(f"  {name}")
        return 1

    samples = manifest(stem)
    if not samples:
        print(f"{stem}: no pinned samples (tests/fixtures/{stem}/sample_sources.yml)")
        return 1

    query, referenced = compile_rule(rules[stem])
    fields = show or INTERESTING
    print(f"rule : {rules[stem].name}")
    print(f"sql  : {query}\n")

    failures = 0
    for sample in samples:
        name = sample.get("name", "?")
        expect = sample.get("expect", "?")
        try:
            evtx = fetch(sample)
        except SampleError as exc:
            print(f"[{name}] could not fetch: {exc}")
            failures += 1
            continue

        events = read_events(evtx)
        matched = matching_indices(query, referenced, events)
        verdict = "fire" if matched else "silent"
        agrees = "ok" if verdict == expect else "MISMATCH"

        print(f"[{name}] expect={expect} got={verdict} ({agrees})")
        print(f"    {len(events)} events, EventIDs: "
              f"{dict(event_id_counts(events).most_common(8))}")

        if matched:
            for index in sorted(matched)[:limit]:
                print(f"    -- match #{index}")
                print("\n".join(_summarise(events[index], fields, width)))
        elif expect == "fire":
            # The interesting case: it should have matched and did not. Show what
            # the rule was looking at so the mismatch is diagnosable.
            failures += 1
            candidates = [e for e in events if any(e.get(f) for f in referenced)]
            print(f"    no match. {len(candidates)} event(s) carry a referenced field:")
            for event in candidates[:limit]:
                print("\n".join(_summarise(event, fields, width)))
        print()

    return 1 if failures else 0
