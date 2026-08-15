"""Fetching and reading the pinned public EVTX samples.

Samples are not vendored: each rule's tests/fixtures/<stem>/sample_sources.yml
pins them by repo + commit + sha256, and they are fetched to a gitignored cache.
See ADR 0002 for why.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from detkit.paths import FIXTURES, REPO

CACHE = REPO / "tests" / ".sample_cache"
RAW_URL = "https://raw.githubusercontent.com/{repo}/{commit}/{path}"

FETCH_ATTEMPTS = 3
FETCH_BACKOFF_SECONDS = 2


class SampleError(Exception):
    """A pinned sample could not be fetched or verified."""


def manifest(stem: str) -> list[dict[str, Any]]:
    """The pinned samples declared for a rule."""
    path = FIXTURES / stem / "sample_sources.yml"
    if not path.is_file():
        return []
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    samples = doc.get("samples") or []
    return samples if isinstance(samples, list) else []


def fetch(sample: dict[str, Any]) -> Path:
    """Download a pinned sample to the cache (keyed by sha256) and verify it."""
    sha = str(sample["sha256"]).lower()
    CACHE.mkdir(parents=True, exist_ok=True)
    dest = CACHE / f"{sha}.evtx"
    if dest.exists() and _sha256(dest) == sha:
        return dest

    url = RAW_URL.format(
        repo=sample["repo"],
        commit=sample["commit"],
        path=urllib.parse.quote(str(sample["path"])),
    )

    # A transient network blip is not a detection failure, so retry — but say
    # which of the two happened, or a flaky build gets blamed on the rule.
    last: Exception | None = None
    data = b""
    for attempt in range(FETCH_ATTEMPTS):
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                data = resp.read()
            break
        except OSError as exc:
            last = exc
            if attempt < FETCH_ATTEMPTS - 1:
                time.sleep(FETCH_BACKOFF_SECONDS * (2**attempt))
    else:
        raise SampleError(
            f"could not fetch {sample['path']} after {FETCH_ATTEMPTS} attempts: {last}\n"
            f"This is a sample-availability problem, not a rule failure. If the "
            f"upstream repo removed or rewrote the pinned commit, re-pin the sample."
        )

    got = hashlib.sha256(data).hexdigest()
    if got != sha:
        raise SampleError(
            f"sha256 mismatch for {sample['path']}: {got} != {sha}\n"
            f"The pinned sample changed upstream. Verify the new content before re-pinning."
        )
    dest.write_bytes(data)
    return dest


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_events(evtx: Path) -> list[dict[str, Any]]:
    """Parse an EVTX file into flat event dicts keyed by Sigma field names."""
    from evtx import PyEvtxParser

    parser = PyEvtxParser(str(evtx))
    events = []
    for record in parser.records_json():
        if not isinstance(record, dict):
            continue
        try:
            events.append(flatten(json.loads(record["data"])))
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    return events


def flatten(event: dict[str, Any]) -> dict[str, Any]:
    """Collapse the nested EVTX JSON into the flat names Sigma rules address.

    System metadata is hoisted (EventID, Channel, Computer), attribute blocks are
    unwrapped, and EventData/UserData members are lifted to the top level —
    which is where NewProcessName, CommandLine, ScriptBlockText and friends live.
    """
    out: dict[str, Any] = {}
    root = event.get("Event") or {}

    system = root.get("System") or {}
    for key, value in system.items():
        if key in {"Provider", "TimeCreated", "Execution", "Security"}:
            attributes = (value or {}).get("#attributes", {})
            for attr, attr_value in attributes.items():
                out[attr if key == "Provider" else f"{key}{attr}"] = attr_value
        elif isinstance(value, dict):
            if "#text" in value:
                out[key] = value["#text"]
        else:
            out[key] = value

    for section in ("EventData", "UserData"):
        block = root.get(section) or {}
        # UserData nests one level deeper, under an event-specific element name.
        blocks = [block] if section == "EventData" else list(block.values())
        for sub in blocks:
            if not isinstance(sub, dict):
                continue
            for key, value in sub.items():
                if key != "#attributes":
                    out[key] = value
    return out


def event_id_counts(events: list[dict[str, Any]]) -> Counter[Any]:
    return Counter(event.get("EventID") for event in events)
